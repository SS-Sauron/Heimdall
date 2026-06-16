/*
 * portal.h
 *
 * First-boot captive portal.
 *
 * Starts a WiFi SoftAP, a DNS redirect server, and an HTTP server that
 * serves a configuration form. Blocks until the user submits valid
 * credentials, saves them to NVS, and reboots the device.
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
 *   1. Derive AP SSID and password from chip MAC.
 *   2. Start WiFi in AP mode.
 *   3. Start DNS redirect server (all queries → 192.168.4.1).
 *   4. Register HTTP endpoints (/, /api/scan, /api/provision,
 *      captive-portal detection URIs).
 *   5. Wait for the user to submit valid credentials.
 *   6. Save credentials to NVS.
 *   7. Call esp_restart().
 *
 * This function never returns.
 */
void portal_start(void);

#ifdef __cplusplus
}
#endif
