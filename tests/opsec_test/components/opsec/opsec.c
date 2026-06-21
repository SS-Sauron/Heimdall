/*
 * opsec.c  (test-local shadow of components/opsec/opsec.c)
 *
 * PURPOSE
 * -------
 * This file exists solely to make the linux IDF target build work.
 * The production opsec component depends on:
 *   storage → nvs_flash
 *   identity → esp_wifi          ← NOT available on the linux target
 *   lwip (esp_sntp)              ← NOT available on the linux target
 *
 * This shadow component requires only mbedtls + log, which ARE
 * available on the linux target.  All public API functions other than
 * totp_at_counter_for_test() are stubbed out; they are never called by
 * the unit-test executable.
 *
 * ALGORITHM FIDELITY
 * ------------------
 * totp_at_counter_for_test() mirrors the production implementation
 * in components/opsec/opsec.c. If the
 * production algorithm changes, this copy must be updated in sync.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_log.h"
#include "psa/crypto.h"
#include "opsec.h"

static const char *TAG = "opsec_test_stub";

/* --------------------------------------------------------------------------
 * Public API stubs
 * -------------------------------------------------------------------------- */

esp_err_t opsec_init(void)
{
    ESP_LOGD(TAG, "opsec_init stub");
    return ESP_OK;
}

esp_err_t opsec_derive_topics(char cmd_topic[OPSEC_TOPIC_MAX_LEN],
                               char rsp_topic[OPSEC_TOPIC_MAX_LEN])
{
    (void)cmd_topic;
    (void)rsp_topic;
    return ESP_OK;
}

esp_err_t opsec_parse_payload(const char *payload, size_t payload_len,
                               uint8_t mac_out[6])
{
    (void)payload;
    (void)payload_len;
    (void)mac_out;
    return ESP_OK;
}

esp_err_t opsec_sync_clock(uint32_t timeout_ms)
{
    (void)timeout_ms;
    return ESP_OK;
}

bool opsec_clock_is_synced(void)
{
    return true;
}

#if CONFIG_OPSEC_TEST
static esp_err_t hmac_sha1(const uint8_t *key, size_t key_len,
                           const uint8_t *data, size_t data_len,
                           uint8_t digest[20])
{
    if (!key || !data || !digest || key_len == 0 || key_len > (SIZE_MAX / 8))
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
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_1));
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
    status = psa_mac_compute(key_id, PSA_ALG_HMAC(PSA_ALG_SHA_1),
                             data, data_len, digest, 20, &mac_len);

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
    if (mac_len != 20)
    {
        ESP_LOGE(TAG, "PSA HMAC length mismatch: got %u expected 20", (unsigned)mac_len);
        return ESP_FAIL;
    }

    return ESP_OK;
}
#endif /* CONFIG_OPSEC_TEST */

/* --------------------------------------------------------------------------
 * totp_at_counter_for_test()
 *
 * Copy of the algorithm from components/opsec/opsec.c.
 * See that file for the full algorithm commentary.
 *
 * Algorithm (RFC 6238 / RFC 4226):
 *   msg    = counter as 8-byte big-endian
 *   digest = HMAC-SHA1(seed, msg)
 *   offset = digest[19] & 0x0F
 *   code   = ((digest[offset]   & 0x7F) << 24)
 *           | (digest[offset+1] << 16)
 *           | (digest[offset+2] << 8)
 *           | (digest[offset+3])
 *   result = code % 10^digits
 * -------------------------------------------------------------------------- */
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
