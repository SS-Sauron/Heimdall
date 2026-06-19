/*
 * opsec.h  (test-local copy)
 *
 * Kept in sync with components/opsec/opsec.h.
 * The test-local opsec component shadows the real one so that the linux
 * target is not pulled into esp_wifi / nvs_flash / lwip dependencies that
 * are not available on the linux IDF target.
 *
 * Only totp_at_counter_for_test() is implemented; all other public
 * functions are stubs that return ESP_OK / false.
 */

#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum topic string length (16 hex chars + null) */
#define OPSEC_TOPIC_MAX_LEN   32

/* -------------------------------------------------------------------------
 * Public API stubs (not exercised by unit tests)
 * ------------------------------------------------------------------------- */

esp_err_t opsec_init(void);

esp_err_t opsec_derive_topics(char cmd_topic[OPSEC_TOPIC_MAX_LEN],
                               char rsp_topic[OPSEC_TOPIC_MAX_LEN]);

esp_err_t opsec_parse_payload(const char *payload, size_t payload_len,
                               uint8_t mac_out[6]);

esp_err_t opsec_sync_clock(uint32_t timeout_ms);

bool opsec_clock_is_synced(void);

#if CONFIG_OPSEC_TEST
/* -------------------------------------------------------------------------
 * Test-only exports (CONFIG_OPSEC_TEST=y)
 * Never enable in production builds.
 * ------------------------------------------------------------------------- */

/**
 * @brief Run the TOTP algorithm with explicit parameters (test use only).
 *
 * Identical to the internal totp_at_counter() algorithm but accepts
 * an arbitrary seed and digit count instead of using the NVS globals.
 *
 * @param seed      TOTP seed bytes.
 * @param seed_len  Length of seed in bytes.
 * @param counter   TOTP counter value T (Unix time / step).
 * @param digits    Number of output digits (e.g. 6).
 * @return          TOTP code as an unsigned integer.
 */
uint32_t totp_at_counter_for_test(const uint8_t *seed, size_t seed_len,
                                   uint64_t counter, uint8_t digits);
#endif /* CONFIG_OPSEC_TEST */

#ifdef __cplusplus
}
#endif
