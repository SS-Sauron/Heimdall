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
 * This shadow component requires only mbedtls + esp_log, which ARE
 * available on the linux target.  All public API functions other than
 * totp_at_counter_for_test() are stubbed out; they are never called by
 * the unit-test executable.
 *
 * ALGORITHM FIDELITY
 * ------------------
 * totp_at_counter_for_test() is a verbatim copy of the implementation
 * in components/opsec/opsec.c — not a reimplementation.  If the
 * production algorithm changes, this copy must be updated in sync.
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "esp_err.h"
#include "esp_log.h"
#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include "mbedtls/md.h"
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

/* --------------------------------------------------------------------------
 * totp_at_counter_for_test()
 *
 * Verbatim copy of the algorithm from components/opsec/opsec.c.
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
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1),
                    seed, seed_len,
                    msg, sizeof(msg), digest);

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
