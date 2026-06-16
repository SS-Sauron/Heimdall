/*
 * mqtt_relay.h
 *
 * MQTT relay — the core runtime loop.
 *
 * Connects to the broker stored in NVS, subscribes to the command
 * topic (HMAC-derived in HARDENED builds, plain in STANDARD), and
 * dispatches incoming Magic Packets via the wol component.
 *
 * Optionally publishes a confirmation to the response topic after
 * each successful dispatch (CONFIG_WOL_RESPONSE_CHANNEL).
 *
 * mqtt_relay_start() does not return under normal operation.
 */

#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialise and start the MQTT relay.
 *
 * Call after wifi_sta_connect() returns ESP_OK.
 *
 * Sequence:
 *   1. Initialise OPSEC layer (load key material, optional SNTP sync).
 *   2. Derive MQTT topics.
 *   3. Build broker URI from NVS credentials.
 *   4. Start esp_mqtt_client.
 *   5. Enter health-monitor loop (never returns under normal operation).
 *
 * If the MQTT client encounters an unrecoverable error, the device
 * is rebooted rather than hanging.
 */
void mqtt_relay_start(void);

#ifdef __cplusplus
}
#endif
