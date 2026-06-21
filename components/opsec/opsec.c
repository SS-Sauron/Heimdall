/*
 * opsec.c
 *
 * OPSEC cryptographic layer implementation.
 *
 * Uses PSA Crypto (bundled through ESP-IDF mbedTLS) for:
 *   - HMAC-SHA256  (topic derivation)
 *   - HMAC-SHA1    (TOTP per RFC 6238)
 *
 * Uses SNTP (lwIP) for clock synchronisation required by TOTP.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "esp_log.h"
#ifndef CONFIG_IDF_TARGET_LINUX
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_mac.h"
#include "esp_sntp.h"
#include "identity.h"
#endif /* CONFIG_IDF_TARGET_LINUX */
#include "psa/crypto.h"
#include "storage.h"
#include "opsec.h"
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
static volatile bool s_clock_synced = false;

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

#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP || CONFIG_OPSEC_TEST
static esp_err_t hmac_compute(psa_algorithm_t alg,
                              const uint8_t *key, size_t key_len,
                              const uint8_t *data, size_t data_len,
                              uint8_t *digest, size_t digest_len)
{
    if (!key || !data || !digest || key_len == 0 || digest_len == 0 || key_len > (SIZE_MAX / 8))
        return ESP_ERR_INVALID_ARG;

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA crypto init failed: %d", (int)status);
        return ESP_FAIL;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, alg);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, key_len * 8);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_import_key(&attributes, key, key_len, &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA HMAC key import failed: %d", (int)status);
        return ESP_FAIL;
    }

    size_t mac_len = 0;
    status = psa_mac_compute(key_id, alg, data, data_len,
                             digest, digest_len, &mac_len);

    psa_status_t destroy_status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA HMAC compute failed: %d", (int)status);
        return ESP_FAIL;
    }
    if (destroy_status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA HMAC key destroy failed: %d", (int)destroy_status);
        return ESP_FAIL;
    }
    if (mac_len != digest_len)
    {
        ESP_LOGE(TAG, "PSA HMAC length mismatch: got %u expected %u",
                 (unsigned)mac_len, (unsigned)digest_len);
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * Internal: compute HMAC-SHA256(key, data) -> digest[32]
 * -------------------------------------------------------------------------- */
#if CONFIG_OPSEC_HMAC_TOPIC
static esp_err_t hmac_sha256(const uint8_t *key, size_t key_len,
                             const uint8_t *data, size_t data_len,
                             uint8_t digest[32])
{
    return hmac_compute(PSA_ALG_HMAC(PSA_ALG_SHA_256),
                        key, key_len, data, data_len, digest, 32);
}
#endif

#if CONFIG_OPSEC_TOTP || CONFIG_OPSEC_TEST
static esp_err_t hmac_sha1(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t digest[20])
{
    return hmac_compute(PSA_ALG_HMAC(PSA_ALG_SHA_1),
                        key, key_len, data, data_len, digest, 20);
}
#endif
#endif /* CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP || CONFIG_OPSEC_TEST */

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
static esp_err_t totp_at_counter(uint64_t T, uint32_t *code_out)
{
    if (!code_out)
        return ESP_ERR_INVALID_ARG;

    /* Encode T as 8-byte big-endian */
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(T & 0xFF);
        T >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t digest[20];
    esp_err_t err = hmac_sha1(s_totp_seed, STORAGE_TOTP_SEED_LEN,
                              msg, sizeof(msg), digest);
    if (err != ESP_OK)
        return err;

    /* Dynamic truncation */
    int offset = digest[19] & 0x0F;
    uint32_t code = ((uint32_t)(digest[offset] & 0x7F) << 24) | ((uint32_t)(digest[offset + 1] & 0xFF) << 16) | ((uint32_t)(digest[offset + 2] & 0xFF) << 8) | ((uint32_t)(digest[offset + 3] & 0xFF));

    /* Compute 10^DIGITS */
    uint32_t modulus = 1;
    for (int i = 0; i < CONFIG_OPSEC_TOTP_DIGITS; i++)
        modulus *= 10;

    *code_out = code % modulus;
    return ESP_OK;
}

/* Accept if the code matches T-1, T, or T+1 (±1 window = ±30 s drift) */
static esp_err_t totp_validate(uint32_t submitted_code, bool *valid_out)
{
    if (!valid_out)
        return ESP_ERR_INVALID_ARG;

    *valid_out = false;
    uint64_t T = (uint64_t)time(NULL) / CONFIG_OPSEC_TOTP_STEP_SEC;
    for (int delta = -1; delta <= 1; delta++)
    {
        uint32_t expected_code = 0;
        esp_err_t err = totp_at_counter((uint64_t)((int64_t)T + delta), &expected_code);
        if (err != ESP_OK)
            return err;

        if (expected_code == submitted_code)
        {
            *valid_out = true;
            return ESP_OK;
        }
    }
    return ESP_OK;
}
#endif
#if CONFIG_OPSEC_TEST
uint32_t totp_at_counter_for_test(const uint8_t *seed, size_t seed_len,
                                   uint64_t counter, uint8_t digits)
{
    /* Encode counter as 8-byte big-endian */
    uint8_t msg[8];
    uint64_t T = counter;
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(T & 0xFF);
        T >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t digest[20];
    esp_err_t err = hmac_sha1(seed, seed_len, msg, sizeof(msg), digest);
    if (err != ESP_OK)
        return 0;

    /* Dynamic truncation */
    int offset = digest[19] & 0x0F;
    uint32_t code = ((uint32_t)(digest[offset]     & 0x7F) << 24)
                  | ((uint32_t)(digest[offset + 1] & 0xFF) << 16)
                  | ((uint32_t)(digest[offset + 2] & 0xFF) <<  8)
                  | ((uint32_t)(digest[offset + 3] & 0xFF));

    /* Compute 10^digits */
    uint32_t modulus = 1;
    for (uint8_t i = 0; i < digits; i++)
        modulus *= 10;

    return code % modulus;
}
#endif /* CONFIG_OPSEC_TEST */

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
#ifdef CONFIG_IDF_TARGET_LINUX
    /* opsec_derive_topics is not used by the linux unit-test build */
    (void)cmd_topic;
    (void)rsp_topic;
    return ESP_ERR_NOT_SUPPORTED;
#else
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
#endif /* CONFIG_IDF_TARGET_LINUX */
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

    bool valid = false;
    esp_err_t err = totp_validate(submitted, &valid);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "TOTP validation failed due to crypto error: %s", esp_err_to_name(err));
        return err;
    }

    if (!valid)
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
#if CONFIG_OPSEC_TOTP && !defined(CONFIG_IDF_TARGET_LINUX)
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
    /* STANDARD build or linux host: clock sync is not applicable */
    (void)timeout_ms;
    s_clock_synced = true;
    return ESP_OK;
#endif
}

bool opsec_clock_is_synced(void)
{
    return s_clock_synced;
}
