/*
 * opsec.h
 *
 * OPSEC cryptographic layer.
 *
 * Provides two services:
 *
 *   1. HMAC-SHA256 topic derivation
 *      Derives opaque MQTT topic strings from the chip MAC and a
 *      secret held in NVS. Enabled by CONFIG_OPSEC_HMAC_TOPIC.
 *      Falls back to plain "wol/<MAC>" strings in STANDARD builds.
 *
 *   2. TOTP payload validation (RFC 6238)
 *      Validates the 6-digit TOTP suffix appended to incoming MQTT
 *      payloads. Enabled by CONFIG_OPSEC_TOTP (requires HMAC topic).
 *      In STANDARD builds the payload is the bare MAC string.
 *
 * All functions are safe to call from any task after opsec_init().
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
 * Initialisation
 * ------------------------------------------------------------------------- */

/**
 * @brief Initialise the OPSEC layer.
 *
 * Loads or generates the HMAC secret and TOTP seed from NVS.
 * In STANDARD builds (no OPSEC flags) this is a no-op.
 *
 * Must be called once before any other opsec_* function.
 * Call after storage component is ready (after nvs_flash_init).
 */
esp_err_t opsec_init(void);

/* -------------------------------------------------------------------------
 * Topic derivation
 * ------------------------------------------------------------------------- */

/**
 * @brief Derive the MQTT command, status, and log topic strings.
 *
 * In HARDENED builds (CONFIG_OPSEC_HMAC_TOPIC):
 *   digest         = HMAC-SHA256(secret, chip_mac_bytes)
 *   command_topic  = hex(digest[0..7])    e.g. "d4f3a891c02e57b3"
 *   status_topic   = hex(digest[8..15])/s e.g. "f10c34a29b7e81d4/s"
 *   log_topic      = hex(digest[8..15])/l e.g. "f10c34a29b7e81d4/l"
 *
 * In STANDARD builds:
 *   command_topic  = "wol/AA:BB:CC:DD:EE:FF"
 *   status_topic   = "wol/AA:BB:CC:DD:EE:FF/s"
 *   log_topic      = "wol/AA:BB:CC:DD:EE:FF/l"
 *
 * @param[out] cmd_topic    Buffer for command topic (min OPSEC_TOPIC_MAX_LEN bytes).
 * @param[out] status_topic Buffer for status topic  (min OPSEC_TOPIC_MAX_LEN bytes).
 * @param[out] log_topic    Buffer for log topic     (min OPSEC_TOPIC_MAX_LEN bytes).
 * @return ESP_OK on success.
 */
esp_err_t opsec_derive_topics(char cmd_topic[OPSEC_TOPIC_MAX_LEN],
                               char status_topic[OPSEC_TOPIC_MAX_LEN],
                               char log_topic[OPSEC_TOPIC_MAX_LEN]);

/* -------------------------------------------------------------------------
 * Payload parsing and TOTP validation
 * ------------------------------------------------------------------------- */

/**
 * @brief Parse an incoming MQTT payload and extract the target MAC.
 *
 * In STANDARD builds:
 *   Expected payload: "AA:BB:CC:DD:EE:FF"
 *   Returns the 6-byte MAC in mac_out.
 *
 * In HARDENED builds (CONFIG_OPSEC_TOTP):
 *   Expected payload: "AA:BB:CC:DD:EE:FF:123456"
 *   Validates the TOTP token before returning.
 *   Returns ESP_ERR_INVALID_STATE if clock is not yet synchronised.
 *   Returns ESP_ERR_INVALID_ARG if the token is invalid or expired.
 *
 * @param[in]  payload      Raw MQTT payload bytes.
 * @param[in]  payload_len  Length of payload in bytes.
 * @param[out] mac_out      6-byte buffer for the parsed MAC address.
 * @return ESP_OK on success, error code if validation fails.
 */
esp_err_t opsec_parse_payload(const char *payload, size_t payload_len,
                               uint8_t mac_out[6]);

#if CONFIG_WOL_PING_FEEDBACK
/**
 * @brief Extract optional IP address from a command payload.
 *
 * Called AFTER opsec_parse_payload() has already succeeded and
 * validated the payload. This function looks for an IP address
 * appended to the payload beyond what opsec_parse_payload() consumed.
 *
 * For STANDARD (JSON) payloads: looks for "ip" key in JSON object.
 * For HARDENED (plain string) payloads: looks for a fourth colon-
 * separated segment after the TOTP code.
 *
 * @param payload     Original raw payload bytes.
 * @param payload_len Length of payload.
 * @param ip_out      Output buffer, at least 16 bytes.
 * @return ESP_OK if a valid IP was found and written to ip_out.
 *         ESP_ERR_NOT_FOUND if no IP field is present (not an error).
 *         ESP_ERR_INVALID_ARG if an IP field is present but malformed.
 */
esp_err_t opsec_extract_ip(const char *payload, size_t payload_len,
                            char ip_out[16]);
#endif /* CONFIG_WOL_PING_FEEDBACK */

#if CONFIG_OPSEC_TOTP
/**
 * @brief Validate a submitted TOTP code against the current time window.
 *
 * Used by non-WoL command handlers (e.g. GPIO) in HARDENED builds to
 * apply the same authentication requirement as opsec_parse_payload().
 *
 * Accepts codes within a ±1 window (T-1, T, T+1) identical to the
 * main TOTP validation path.
 *
 * @param submitted_code  The TOTP code as a plain uint32_t integer.
 * @return ESP_OK if the code is valid.
 *         ESP_ERR_INVALID_ARG if the code is invalid or expired.
 *         ESP_ERR_INVALID_STATE if clock is not yet synchronised.
 */
esp_err_t opsec_validate_totp_code(uint32_t submitted_code);
#endif /* CONFIG_OPSEC_TOTP */

/* -------------------------------------------------------------------------
 * SNTP clock synchronisation (required for TOTP)
 * ------------------------------------------------------------------------- */

/**
 * @brief Start SNTP and wait for clock synchronisation.
 *
 * No-op in STANDARD builds. In HARDENED builds starts the SNTP client
 * against CONFIG_OPSEC_SNTP_SERVER and blocks until the system clock
 * is synchronised (or timeout_ms elapses).
 *
 * @param timeout_ms  Max time to wait for sync, or 0 for 30 000 ms default.
 * @return ESP_OK when clock is synchronised, ESP_ERR_TIMEOUT otherwise.
 *         TOTP validation will refuse to act until this returns ESP_OK.
 */
esp_err_t opsec_sync_clock(uint32_t timeout_ms);

/**
 * @brief Returns true if the system clock has been synchronised via SNTP.
 *
 * Thread-safe. If false, TOTP validation rejects all payloads.
 */
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
