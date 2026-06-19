/*
 * identity.h
 *
 * Network identity obfuscation.
 *
 * Applies a locally-administered MAC address and an obfuscated DHCP
 * hostname to the WiFi station interface before the WiFi driver starts.
 * Both operations are no-ops when the corresponding Kconfig options are
 * disabled (STANDARD build profile).
 *
 * Call identity_apply() once, after esp_netif_init() and before
 * esp_wifi_init() / esp_wifi_start().
 */

#pragma once

#include "esp_err.h"
#include "sdkconfig.h"
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Apply all enabled identity obfuscation steps.
 *
 * In STANDARD builds (no OPSEC flags set) this is a lightweight no-op
 * that returns immediately. In HARDENED builds it:
 *   1. Derives a locally-administered MAC from the eFuse base MAC and
 *      programs it into the WiFi station interface.
 *   2. Sets the DHCP hostname to an obfuscated consumer-device string.
 *
 * Must be called AFTER esp_netif_init() but BEFORE esp_wifi_start().
 */
void identity_apply(void);

/**
 * @brief Retrieve the effective MAC address currently in use.
 *
 * If MAC spoofing is enabled this returns the spoofed address.
 * If not, it returns the burned-in eFuse base MAC.
 *
 * @param[out] mac  6-byte buffer to receive the MAC address.
 * @return ESP_OK on success.
 */
esp_err_t identity_get_mac(uint8_t mac[6]);

/**
 * @brief Retrieve the effective DHCP hostname currently in use.
 *
 * Returns the obfuscated hostname if OPSEC_IDENTITY_FAKE_HOSTNAME is
 * enabled, or the default ESP-IDF hostname otherwise.
 *
 * @param[out] buf   Caller-allocated buffer to receive the hostname.
 * @param[in]  len   Size of buf in bytes (32 bytes is sufficient).
 */
void identity_get_hostname(char *buf, size_t len);

/**
 * @brief Spoof the softAP MAC address to hide the Espressif OUI.
 *
 * Must be called AFTER esp_wifi_set_mode() includes WIFI_MODE_AP (or
 * WIFI_MODE_APSTA) and BEFORE esp_wifi_start(). The AP MAC is derived
 * from the already-spoofed STA MAC by incrementing the last byte by 1,
 * mirroring the natural STA→AP offset the hardware uses by default.
 *
 * This is a no-op when CONFIG_OPSEC_IDENTITY_SPOOF_MAC is disabled
 * (STANDARD build).
 *
 * @return ESP_OK on success, or an esp_err_t on failure.
 */
#if CONFIG_OPSEC_IDENTITY_SPOOF_MAC
esp_err_t identity_spoof_ap_mac(void);
#else
static inline esp_err_t identity_spoof_ap_mac(void) { return ESP_OK; }
#endif

#ifdef __cplusplus
}
#endif
