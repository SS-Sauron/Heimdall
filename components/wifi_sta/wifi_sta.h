/*
 * wifi_sta.h
 *
 * WiFi station management.
 *
 * Reads credentials from the storage component, connects to the home
 * network, and handles reconnection transparently in the background.
 * Callers block on wifi_sta_connect() until an IP address is obtained.
 */

#pragma once

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Connect to the WiFi network stored in NVS and block until done.
 *
 * Initialises the WiFi driver (if not already done by identity.c),
 * creates the default STA netif, registers event handlers, and starts
 * the connection process.
 *
 * Blocks indefinitely — it does NOT return on failure. On failure, the
 * function calls esp_restart() internally via one of two paths and never
 * returns to its caller. The only return value this function ever yields
 * to its caller is ESP_OK.
 *
 *   Fast path  — CONFIG_WIFI_STA_MAX_RETRY consecutive disconnects whose
 *                reason code identifies a credential mismatch:
 *                  WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT
 *                  WIFI_REASON_HANDSHAKE_TIMEOUT
 *                  WIFI_REASON_802_1X_AUTH_FAILED
 *                  WIFI_REASON_IE_IN_4WAY_DIFFERS
 *                On triggering: NVS credentials are erased, then
 *                esp_restart() is called. The device reboots into the
 *                provisioning portal. The fast-path counter does NOT
 *                accumulate across reboots — it resets on any transient
 *                (non-credential) disconnect.
 *
 *   Slow path  — If the device remains continuously disconnected for the
 *                entire per-boot ceiling
 *                (CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES, default 30 min)
 *                without ever obtaining an IP address in this boot session,
 *                a persistent reboot-strike counter stored in NVS under key
 *                "rc" is incremented and esp_restart() is called.
 *                After CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS
 *                consecutive such cycles (default: 7 × 30 min = 210 min
 *                total), NVS credentials are erased and the device reboots
 *                into the provisioning portal. A successful IP assignment at
 *                any point resets the "rc" counter to zero, so only truly
 *                consecutive failure cycles accumulate toward the threshold.
 *
 * @return ESP_OK  An IP address was obtained; the caller may proceed.
 *                 This is the only value ever returned to the caller.
 *                 On any failure the function does not return — it calls
 *                 esp_restart() and the stack unwinds at the hardware level.
 */
esp_err_t wifi_sta_connect(void);

/**
 * @brief Returns true if the station currently has an IP address.
 *
 * Thread-safe. Can be polled from any task to check connectivity
 * before attempting MQTT operations.
 */
bool wifi_sta_is_connected(void);

/**
 * @brief Block until the station has an IP address.
 *
 * Useful for tasks that start shortly after wifi_sta_connect() returns
 * and want to wait out any brief re-association event.
 *
 * @param timeout_ms  Maximum time to wait, or 0 for indefinite.
 * @return ESP_OK if connected, ESP_ERR_TIMEOUT if time expired.
 */
esp_err_t wifi_sta_wait_connected(uint32_t timeout_ms);

#ifdef __cplusplus
}
#endif
