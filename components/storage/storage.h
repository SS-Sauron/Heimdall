/*
 * storage.h
 *
 * Typed NVS credential store.
 *
 * All values are stored in a single NVS namespace under short, opaque
 * key names (single or two-character strings) so that a raw flash dump
 * gives no structural hint about what the device does.
 *
 * Key map (internal — not part of the public API):
 *   "pv"  →  provisioned flag (u8)
 *   "wk"  →  WiFi SSID        (str, max 32 chars)
 *   "wp"  →  WiFi password    (str, max 64 chars)
 *   "mu"  →  MQTT broker URL  (str, max 128 chars)
 *   "mp"  →  MQTT port        (u16)
 *   "ma"  →  MQTT username    (str, max 64 chars)
 *   "mb"  →  MQTT password    (str, max 64 chars)
 *   "hs"  →  HMAC secret      (blob, 32 bytes)
 *   "ts"  →  TOTP seed        (blob, 20 bytes, HMAC-SHA1 for RFC 6238)
 */

#pragma once

#include "esp_err.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum field lengths (not including null terminator) */
#define STORAGE_SSID_MAX        32
#define STORAGE_WIFI_PASS_MAX   64
#define STORAGE_MQTT_URL_MAX    128
#define STORAGE_MQTT_USER_MAX   64
#define STORAGE_MQTT_PASS_MAX   64
#define STORAGE_HMAC_SECRET_LEN 32
#define STORAGE_TOTP_SEED_LEN   20

/* -------------------------------------------------------------------------
 * Credential bundle — passed in from the portal after the user submits the
 * configuration form. All fields are validated by the portal before storage
 * writes them.
 * ------------------------------------------------------------------------- */
typedef struct {
    char     wifi_ssid[STORAGE_SSID_MAX + 1];
    char     wifi_pass[STORAGE_WIFI_PASS_MAX + 1];
    char     mqtt_url[STORAGE_MQTT_URL_MAX + 1];
    uint16_t mqtt_port;
    char     mqtt_user[STORAGE_MQTT_USER_MAX + 1];
    char     mqtt_pass[STORAGE_MQTT_PASS_MAX + 1];
} storage_credentials_t;

/* -------------------------------------------------------------------------
 * Provisioning state
 * ------------------------------------------------------------------------- */

/**
 * @brief Returns true if a complete set of credentials has been saved.
 *
 * Checks for the presence of the provisioned flag ("pv" key) in NVS.
 * Called by main.c to decide whether to start the portal or the relay.
 */
bool storage_is_provisioned(void);

/* -------------------------------------------------------------------------
 * Read / Write credentials
 * ------------------------------------------------------------------------- */

/**
 * @brief Save a complete credential bundle to NVS and set the provisioned flag.
 *
 * Atomically writes all fields and marks the device as provisioned.
 * Called by the portal after successful form submission.
 *
 * @param creds  Pointer to a fully populated credential bundle.
 * @return ESP_OK on success.
 */
esp_err_t storage_save_credentials(const storage_credentials_t *creds);

/**
 * @brief Load credentials from NVS into a caller-allocated bundle.
 *
 * @param[out] creds  Bundle to populate.
 * @return ESP_OK on success, ESP_ERR_NVS_NOT_FOUND if not provisioned.
 */
esp_err_t storage_load_credentials(storage_credentials_t *creds);

/* -------------------------------------------------------------------------
 * OPSEC key material (HARDENED build only)
 * These functions are no-ops / return ESP_ERR_NOT_SUPPORTED in STANDARD.
 * ------------------------------------------------------------------------- */

/**
 * @brief Save the HMAC secret used for topic derivation.
 *
 * @param secret  32-byte secret.
 */
esp_err_t storage_save_hmac_secret(const uint8_t secret[STORAGE_HMAC_SECRET_LEN]);

/**
 * @brief Load the HMAC secret. Generates and saves a random one if not present.
 *
 * @param[out] secret  32-byte buffer to receive the secret.
 */
esp_err_t storage_load_or_generate_hmac_secret(uint8_t secret[STORAGE_HMAC_SECRET_LEN]);

/**
 * @brief Save the TOTP seed (20 bytes, RFC 6238 HMAC-SHA1 base).
 */
esp_err_t storage_save_totp_seed(const uint8_t seed[STORAGE_TOTP_SEED_LEN]);

/**
 * @brief Load the TOTP seed. Generates and saves a random one if not present.
 */
esp_err_t storage_load_or_generate_totp_seed(uint8_t seed[STORAGE_TOTP_SEED_LEN]);

/* -------------------------------------------------------------------------
 * Erase
 * ------------------------------------------------------------------------- */

/**
 * @brief Erase all keys in the WoL namespace.
 *
 * Called by the factory reset handler in main.c. After this call,
 * storage_is_provisioned() returns false and the next boot will start
 * the captive portal.
 */
esp_err_t storage_erase_all(void);

/**
 * @brief Initialize the factory reset button.
 *
 * Configures GPIO0 with the espressif/button component.
 * A long press (configured via Kconfig) will trigger an NVS erase and reboot.
 */
void storage_button_init(void);

#ifdef __cplusplus
}
#endif
