/*
 * portal.h
 *
 * First-boot captive portal.
 *
 * Starts a WiFi SoftAP, a DNS redirect server, and an HTTP server that
 * serves a password login page followed by a configuration form. Blocks
 * until the user submits valid credentials, saves them to NVS, and reboots
 * the device.
 *
 * portal_start() never returns — it ends with esp_restart().
 */

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the captive portal and block until provisioned.
 *
 * Call this when storage_is_provisioned() returns false.
 *
 * Sequence:
 *   1. Derive AP SSID and eFuse-tied portal password.
 *   2. Start WiFi in AP mode with WPA2 enabled.
 *   3. Start DNS redirect server (all queries → 192.168.4.1).
 *   4. Register HTTP endpoints (/, /login, /api/scan, /api/provision,
 *      captive-portal detection URIs).
 *   5. Require the eFuse-derived portal password before showing the form.
 *   6. Wait for the user to submit valid credentials.
 *   7. Save credentials to NVS.
 *   8. Call esp_restart().
 *
 * This function never returns.
 */
void portal_start(void);

/**
 * @brief Derive the permanent portal password from the factory eFuse MAC.
 *
 * The output is an 8-character uppercase hex string plus null terminator.
 * This does not read or write NVS and is stable across factory resets.
 *
 * @param[out] out  Caller-provided buffer of at least 9 bytes.
 * @return ESP_OK on success.
 */
esp_err_t portal_derive_password(char out[9]);

#ifdef __cplusplus
}
#endif
