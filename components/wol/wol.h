/*
 * wol.h
 *
 * Wake-on-LAN Magic Packet builder and broadcaster.
 *
 * Accepts a target MAC address as a colon-separated string
 * (e.g. "AA:BB:CC:DD:EE:FF") or as a 6-byte array, constructs
 * the standard 102-byte Magic Packet, and broadcasts it over UDP
 * to the configured LAN broadcast address on port 9.
 */

#pragma once

#include "esp_err.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Send a Magic Packet to wake the machine with the given MAC address.
 *
 * Parses @p mac_str (format "AA:BB:CC:DD:EE:FF"), constructs the 102-byte
 * Magic Packet, and sends it as a UDP broadcast to
 * the broadcast address derived at send time from the STA interface IP and netmask.
 *
 * The broadcast is sent three times with a 10 ms gap to improve
 * delivery reliability on lossy local networks.
 *
 * @param mac_str  Colon-separated MAC string, e.g. "AA:BB:CC:DD:EE:FF".
 *                 Case-insensitive. NULL or malformed strings return
 *                 ESP_ERR_INVALID_ARG.
 * @return ESP_OK on success, or an error code.
 */
esp_err_t wol_send(const char *mac_str);

/**
 * @brief Raw variant — accepts a pre-parsed 6-byte MAC array.
 *
 * @param mac  6-byte MAC address in network byte order.
 * @return ESP_OK on success.
 */
esp_err_t wol_send_raw(const uint8_t mac[6]);

/**
 * @brief Parse a colon-separated MAC string into a 6-byte array.
 *
 * @param mac_str  Input string, e.g. "AA:BB:CC:DD:EE:FF".
 * @param mac_out  6-byte output buffer.
 * @return ESP_OK on success, ESP_ERR_INVALID_ARG on parse failure.
 */
esp_err_t wol_parse_mac(const char *mac_str, uint8_t mac_out[6]);

#ifdef __cplusplus
}
#endif
