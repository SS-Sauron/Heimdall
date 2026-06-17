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
 * @brief Connect to the WiFi network stored in NVS.
 *
 * Initialises the WiFi driver (if not already done by identity.c),
 * creates the default STA netif, registers event handlers, and starts
 * the connection process.
 *
 * Blocks indefinitely (portMAX_DELAY) — it will never return on failure.
 * Two internal mechanisms ensure the device cannot hang permanently:
 *
 *   Fast path  — if CONFIG_WIFI_STA_MAX_RETRY consecutive wrong-credential
 *                disconnect reasons are observed, credentials are erased from
 *                NVS and esp_restart() is called to force re-provisioning.
 *
 *   Slow path  — if the device remains continuously disconnected for longer
 *                than CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES (default 20 min),
 *                credentials are erased and esp_restart() is called regardless
 *                of the disconnect reason code. This catches permanent
 *                NO_AP_FOUND loops caused by an SSID typo.
 *
 * @return ESP_OK when the network is up and an IP address is assigned.
 *         Never returns on failure — esp_restart() is called internally.
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
