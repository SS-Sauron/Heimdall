/*
 * opsec.c
 *
 * OPSEC cryptographic layer implementation.
 *
 * Uses mbedTLS (bundled with ESP-IDF) for:
 *   - HMAC-SHA256  (topic derivation)
 *   - HMAC-SHA1    (TOTP per RFC 6238)
 *
 * Uses SNTP (lwIP) for clock synchronisation required by TOTP.
 */

#include <string.h>
#include <stdio.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_sntp.h"
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/md.h"
#include "storage.h"
#include "opsec.h"
#include "identity.h"
#include "sdkconfig.h"

static const char *TAG = "opsec";

/* Cached key material loaded during opsec_init() */
#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
static uint8_t s_hmac_secret[STORAGE_HMAC_SECRET_LEN];
#endif
#if CONFIG_OPSEC_TOTP
static uint8_t s_totp_seed[STORAGE_TOTP_SEED_LEN];
#endif
static bool s_initialised = false;
static bool s_clock_synced = false;

/* --------------------------------------------------------------------------
 * SNTP callback
 * -------------------------------------------------------------------------- */
#if CONFIG_OPSEC_TOTP
static void sntp_sync_cb(struct timeval *tv)
{
    s_clock_synced = true;
    ESP_LOGI(TAG, "Clock synchronised via SNTP (epoch: %lld)", (long long)tv->tv_sec);
}
#endif

/* --------------------------------------------------------------------------
 * Internal: compute HMAC-SHA256(key, data) → digest[32]
 * -------------------------------------------------------------------------- */
#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
static esp_err_t hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t digest[32])
{
    int ret = mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                              key, key_len, data, data_len, digest);
    return (ret == 0) ? ESP_OK : ESP_FAIL;
}
#endif /* CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP */

/* --------------------------------------------------------------------------
 * Internal: RFC 6238 TOTP for a specific time counter T
 *
 * Algorithm:
 *   msg    = T as 8-byte big-endian
 *   digest = HMAC-SHA1(seed, msg)
 *   offset = digest[19] & 0x0F
 *   code   = ((digest[offset]   & 0x7F) << 24)
 *           | (digest[offset+1] << 16)
 *           | (digest[offset+2] << 8)
 *           | (digest[offset+3])
 *   result = code % 10^DIGITS
 * -------------------------------------------------------------------------- */
#if CONFIG_OPSEC_TOTP
static uint32_t totp_at_counter(uint64_t T)
{
    /* Encode T as 8-byte big-endian */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(T & 0xFF);
        T >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t digest[20];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                    s_totp_seed, STORAGE_TOTP_SEED_LEN,
                    msg, sizeof(msg), digest);

    /* Dynamic truncation */
    int offset = digest[19] & 0x0F;
    uint32_t code = ((uint32_t)(digest[offset] & 0x7F) << 24) | ((uint32_t)(digest[offset + 1] & 0xFF) << 16) | ((uint32_t)(digest[offset + 2] & 0xFF) << 8) | ((uint32_t)(digest[offset + 3] & 0xFF));

    /* Compute 10^DIGITS */
    uint32_t modulus = 1;
    for (int i = 0; i < CONFIG_OPSEC_TOTP_DIGITS; i++)
        modulus *= 10;

    return code % modulus;
}

/* Accept if the code matches T-1, T, or T+1 (±1 window = ±30 s drift) */
static bool totp_validate(uint32_t submitted_code)
{
    uint64_t T = (uint64_t)time(NULL) / CONFIG_OPSEC_TOTP_STEP_SEC;
    for (int delta = -1; delta <= 1; delta++)
    {
        if (totp_at_counter((uint64_t)((int64_t)T + delta)) == submitted_code)
        {
            return true;
        }
    }
    return false;
}
#endif
/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t opsec_init(void)
{
#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
    esp_err_t err;

    err = storage_load_or_generate_hmac_secret(s_hmac_secret);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to load HMAC secret: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "HMAC secret ready (%d bytes)", STORAGE_HMAC_SECRET_LEN);

#if CONFIG_OPSEC_TOTP
    err = storage_load_or_generate_totp_seed(s_totp_seed);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to load TOTP seed: %s", esp_err_to_name(err));
        return err;
    }
    ESP_LOGI(TAG, "TOTP seed ready (%d bytes)", STORAGE_TOTP_SEED_LEN);
#endif

    s_initialised = true;
#else
    ESP_LOGD(TAG, "OPSEC crypto disabled (STANDARD build)");
    s_initialised = true;
#endif
    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Topic derivation
 * -------------------------------------------------------------------------- */
esp_err_t opsec_derive_topics(char cmd_topic[OPSEC_TOPIC_MAX_LEN],
                              char rsp_topic[OPSEC_TOPIC_MAX_LEN])
{
    /* Read effective MAC (spoofed if OPSEC_IDENTITY on, else eFuse) */
    uint8_t mac[6];
    identity_get_mac(mac);

#if CONFIG_OPSEC_HMAC_TOPIC
    if (!s_initialised)
        return ESP_ERR_INVALID_STATE;

    uint8_t digest[32];
    esp_err_t err = hmac_sha256(s_hmac_secret, STORAGE_HMAC_SECRET_LEN,
                                mac, 6, digest);
    if (err != ESP_OK)
        return err;

    /* Command topic:  first 8 bytes of digest → 16 hex chars */
    snprintf(cmd_topic, OPSEC_TOPIC_MAX_LEN,
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[0], digest[1], digest[2], digest[3],
             digest[4], digest[5], digest[6], digest[7]);

    /* Response topic: next 8 bytes of digest → 16 hex chars */
    snprintf(rsp_topic, OPSEC_TOPIC_MAX_LEN,
             "%02x%02x%02x%02x%02x%02x%02x%02x",
             digest[8], digest[9], digest[10], digest[11],
             digest[12], digest[13], digest[14], digest[15]);

    ESP_LOGI(TAG, "Command  topic: %s", cmd_topic);
    ESP_LOGI(TAG, "Response topic: %s", rsp_topic);

#else
    /* STANDARD build: plain readable topics */
    snprintf(cmd_topic, OPSEC_TOPIC_MAX_LEN,
             "wol/%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    snprintf(rsp_topic, OPSEC_TOPIC_MAX_LEN,
             "wol/%02X:%02X:%02X:%02X:%02X:%02X/r",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    ESP_LOGI(TAG, "Command  topic: %s", cmd_topic);
    ESP_LOGI(TAG, "Response topic: %s", rsp_topic);
#endif

    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Payload parsing + TOTP validation
 * -------------------------------------------------------------------------- */
esp_err_t opsec_parse_payload(const char *payload, size_t payload_len,
                              uint8_t mac_out[6])
{
    if (!payload || payload_len < 17)
    { /* "AA:BB:CC:DD:EE:FF" = 17 chars min */
        ESP_LOGW(TAG, "Payload too short (%zu bytes)", payload_len);
        return ESP_ERR_INVALID_ARG;
    }

    /* Make a null-terminated working copy */
    char buf[32] = {0};
    size_t copy_len = payload_len < sizeof(buf) - 1 ? payload_len : sizeof(buf) - 1;
    memcpy(buf, payload, copy_len);

    /* Parse MAC from first 17 characters */
    unsigned int b[6] = {0};
    if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6)
    {
        ESP_LOGW(TAG, "Could not parse MAC from payload: \"%s\"", buf);
        return ESP_ERR_INVALID_ARG;
    }
    for (int i = 0; i < 6; i++)
    {
        if (b[i] > 0xFF)
            return ESP_ERR_INVALID_ARG;
        mac_out[i] = (uint8_t)b[i];
    }

#if CONFIG_OPSEC_TOTP
    /* Check clock sync */
    if (!s_clock_synced)
    {
        ESP_LOGW(TAG, "TOTP rejected — clock not yet synchronised");
        return ESP_ERR_INVALID_STATE;
    }

    /* Expect "AA:BB:CC:DD:EE:FF:DDDDDD" — colon at position 17 then digits */
    if (payload_len < 24 || buf[17] != ':')
    {
        ESP_LOGW(TAG, "TOTP missing from payload (expected ':' at pos 17)");
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t submitted = (uint32_t)strtoul(buf + 18, NULL, 10);

    if (!totp_validate(submitted))
    {
        ESP_LOGW(TAG, "TOTP validation failed for code %0*u",
                 CONFIG_OPSEC_TOTP_DIGITS, submitted);
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "TOTP validated OK (code %0*u)",
             CONFIG_OPSEC_TOTP_DIGITS, submitted);
#else
    /* STANDARD: any extra payload bytes are silently ignored */
    (void)payload_len;
#endif

    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * SNTP clock synchronisation
 * -------------------------------------------------------------------------- */
esp_err_t opsec_sync_clock(uint32_t timeout_ms)
{
#if CONFIG_OPSEC_TOTP
    if (s_clock_synced)
        return ESP_OK;

    ESP_LOGI(TAG, "Starting SNTP sync via %s", CONFIG_OPSEC_SNTP_SERVER);

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, CONFIG_OPSEC_SNTP_SERVER);
    esp_sntp_set_time_sync_notification_cb(sntp_sync_cb);
    esp_sntp_init();

    if (timeout_ms == 0)
        timeout_ms = 30000;
    uint32_t elapsed = 0;

    while (!s_clock_synced && elapsed < timeout_ms)
    {
        vTaskDelay(pdMS_TO_TICKS(200));
        elapsed += 200;
    }

    if (!s_clock_synced)
    {
        ESP_LOGW(TAG, "SNTP sync timed out after %u ms — TOTP unavailable", elapsed);
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
#else
    s_clock_synced = true; /* Not needed in STANDARD build */
    return ESP_OK;
#endif
}

bool opsec_clock_is_synced(void)
{
    return s_clock_synced;
}
