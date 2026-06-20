/*
 * identity.c
 *
 * Applies network identity obfuscation before WiFi starts.
 *
 * MAC spoofing uses esp_derive_local_mac() which sets the locally-
 * administered bit (bit 1 of octet 0) so the result is a valid LAA
 * address that does not resolve to Espressif in OUI databases.
 *
 * Hostname obfuscation builds a fake consumer-device string by taking
 * the last 3 bytes of the derived MAC, hex-encoding them, and appending
 * them to the configured prefix (e.g. "NETGEAR-A3F19C").
 */

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "identity.h"
#include "storage.h"
#include "nvs.h"
#include "sdkconfig.h"

static const char *TAG = "identity";

/* Cached values set once during identity_apply() */
static uint8_t s_effective_mac[6] = {0};
static char s_effective_hostname[33] = {0}; /* max 32 chars + null */
static bool s_identity_applied = false;

/* --------------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------------- */

/**
 * Derive and apply a locally-administered MAC to the STA interface.
 *
 * esp_derive_local_mac() XORs the base eFuse MAC with a hash of the
 * base MAC to produce a deterministic but non-Espressif address. The
 * locally-administered bit is set automatically.
 *
 * IMPORTANT: esp_wifi_set_mac() must be called AFTER esp_wifi_init()
 * but BEFORE esp_wifi_start(). The WiFi driver must be in INIT state.
 */
#if CONFIG_OPSEC_IDENTITY_SPOOF_MAC
static esp_err_t apply_mac_spoof(const uint8_t base_mac[6])
{
    uint8_t local_mac[6];
    esp_err_t err = esp_derive_local_mac(local_mac, base_mac);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_derive_local_mac failed: %s", esp_err_to_name(err));
        return err;
    }

    /* WiFi driver must already be initialised (esp_wifi_init called) but
     * not yet started. Caller (identity_apply) ensures this ordering. */
    err = esp_wifi_set_mac(WIFI_IF_STA, local_mac);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_wifi_set_mac failed: %s", esp_err_to_name(err));
        return err;
    }

    memcpy(s_effective_mac, local_mac, 6);
    ESP_LOGI(TAG, "MAC spoofed → %02X:%02X:%02X:%02X:%02X:%02X",
             local_mac[0], local_mac[1], local_mac[2],
             local_mac[3], local_mac[4], local_mac[5]);
    return ESP_OK;
}
#endif

/**
 * Build and apply the obfuscated DHCP hostname.
 *
 * Format: CONFIG_OPSEC_IDENTITY_HOSTNAME_PREFIX + hex(mac[3..5])
 * Example with prefix "NETGEAR-" and mac bytes A3 F1 9C → "NETGEAR-A3F19C"
 */
#if CONFIG_OPSEC_IDENTITY_FAKE_HOSTNAME
static void apply_fake_hostname(const uint8_t mac[6])
{
    snprintf(s_effective_hostname, sizeof(s_effective_hostname),
             "%s%02X%02X%02X",
             CONFIG_OPSEC_IDENTITY_HOSTNAME_PREFIX,
             mac[3], mac[4], mac[5]);

    /* Apply via the default STA netif. The netif must have been created
     * (esp_netif_create_default_wifi_sta) before this point. */
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif == NULL)
    {
        ESP_LOGW(TAG, "STA netif not found — hostname not applied yet");
        /* Will be set again when wifi_sta_connect() creates the netif */
        return;
    }

    esp_netif_set_hostname(sta_netif, s_effective_hostname);
    ESP_LOGI(TAG, "Hostname set to: %s", s_effective_hostname);
}
#endif

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

void identity_apply(void)
{
    /* Read the burned-in eFuse base MAC */
    uint8_t base_mac[6];
    ESP_ERROR_CHECK(esp_read_mac(base_mac, ESP_MAC_EFUSE_FACTORY));
    memcpy(s_effective_mac, base_mac, 6); /* default: use base MAC */

    /* Build default hostname from base MAC before any OPSEC logic.
     * This may be overwritten by NVS or fake-hostname logic below. */
    snprintf(s_effective_hostname, sizeof(s_effective_hostname),
             "esp32-%02X%02X%02X", base_mac[3], base_mac[4], base_mac[5]);

    /* ------------------------------------------------------------------
     * Precedence 1: User-set hostname from NVS (highest priority).
     * If present and still valid, use it and skip all further hostname
     * generation — the user's explicit choice overrides both the MAC-
     * derived default and the HARDENED fake-hostname.
     * ------------------------------------------------------------------ */
    {
        char nvs_hostname[STORAGE_HOSTNAME_MAX + 1] = {0};
        esp_err_t hn_err = storage_load_hostname(nvs_hostname, sizeof(nvs_hostname));
        if (hn_err == ESP_OK) {
            /* Defence-in-depth: re-validate in case rules changed between
             * firmware versions.  Reject if empty, too long, bad chars, or
             * leading/trailing hyphen. */
            size_t hn_len = strlen(nvs_hostname);
            bool valid = (hn_len >= 1 && hn_len <= STORAGE_HOSTNAME_MAX);
            if (valid && (nvs_hostname[0] == '-' || nvs_hostname[hn_len - 1] == '-'))
                valid = false;
            if (valid) {
                for (size_t i = 0; i < hn_len && valid; i++) {
                    char c = nvs_hostname[i];
                    if (!isalnum((unsigned char)c) && c != '-')
                        valid = false;
                }
            }
            if (valid) {
                strncpy(s_effective_hostname, nvs_hostname,
                        sizeof(s_effective_hostname) - 1);
                s_effective_hostname[sizeof(s_effective_hostname) - 1] = '\0';
                ESP_LOGI(TAG, "Hostname loaded from NVS: %s", s_effective_hostname);
                /* Skip fake-hostname generation — NVS value takes precedence */
                goto apply_mac_spoof;
            } else {
                ESP_LOGW(TAG, "NVS hostname '%s' failed re-validation — using default",
                         nvs_hostname);
            }
        } else if (hn_err != ESP_ERR_NVS_NOT_FOUND) {
            ESP_LOGW(TAG, "storage_load_hostname error: %s — using default",
                     esp_err_to_name(hn_err));
        }
        /* ESP_ERR_NVS_NOT_FOUND: fall through to default/fake-hostname logic */
    }

apply_mac_spoof:
#if CONFIG_OPSEC_IDENTITY_SPOOF_MAC
    /*
     * MAC spoofing requires the WiFi driver to be initialised first.
     * We initialise it here with a minimal config, apply the MAC, then
     * leave the driver in INIT state for wifi_sta_connect() to start it.
     *
     * Note: If your build calls esp_wifi_init() elsewhere before this
     * point, move apply_mac_spoof() there instead and remove the init
     * call below.
     */
    {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_err_t init_err = esp_wifi_init(&cfg);
    /* ESP-IDF v5 returns ESP_ERR_WIFI_INIT_STATE on double-init;
     * v6 returns the generic ESP_ERR_INVALID_STATE — both are safe to ignore. */
    if (init_err != ESP_OK &&
        init_err != ESP_ERR_WIFI_INIT_STATE &&
        init_err != ESP_ERR_INVALID_STATE)
    {
        ESP_ERROR_CHECK(init_err);
    }

    /* Espressif requirement: esp_wifi_set_mode() MUST be called before
     * esp_wifi_set_mac() so the driver knows which interface owns the MAC.
     * Without this, esp_wifi_set_mac(WIFI_IF_STA, ...) returns
     * ESP_ERR_WIFI_MODE and the spoof silently fails.
     *
     * We set STA here; downstream callers (portal → APSTA, wifi_sta → STA)
     * will set the final mode before esp_wifi_start(), so this is safe. */
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

    apply_mac_spoof(base_mac);
    }
#endif

#if CONFIG_OPSEC_IDENTITY_FAKE_HOSTNAME
    /* Precedence 2: HARDENED fake hostname — only applies if no NVS hostname
     * was loaded (the goto above skips this block when NVS value is used).
     * Use the spoofed MAC (if active) as the hostname source, so the
     * hostname suffix matches the MAC the network actually sees. */
    apply_fake_hostname(s_effective_mac);
#endif

#if !CONFIG_OPSEC_IDENTITY_SPOOF_MAC && !CONFIG_OPSEC_IDENTITY_FAKE_HOSTNAME
    ESP_LOGD(TAG, "Identity obfuscation disabled (STANDARD build)");
#endif
    s_identity_applied = true;
}

esp_err_t identity_get_mac(uint8_t mac[6])
{
    if (!s_identity_applied) {
        ESP_LOGE(TAG, "identity_get_mac() called before identity_apply()!");
        return ESP_ERR_INVALID_STATE;
    }
    memcpy(mac, s_effective_mac, 6);
    return ESP_OK;
}

void identity_get_hostname(char *buf, size_t len)
{
    strncpy(buf, s_effective_hostname, len - 1);
    buf[len - 1] = '\0';
}

/* --------------------------------------------------------------------------
 * AP MAC spoofing — call AFTER esp_wifi_set_mode(APSTA) and BEFORE start()
 * -------------------------------------------------------------------------- */
#if CONFIG_OPSEC_IDENTITY_SPOOF_MAC
esp_err_t identity_spoof_ap_mac(void)
{
    /* Derive AP MAC from the already-spoofed STA MAC.
     * Increment the last byte by 1 — the same natural STA→AP offset the
     * hardware uses — so the pair looks coherent on the network without
     * revealing the Espressif OUI (78:1C:3C…) in beacon frames. */
    uint8_t ap_mac[6];
    memcpy(ap_mac, s_effective_mac, 6);
    ap_mac[5] += 1;

    esp_err_t err = esp_wifi_set_mac(WIFI_IF_AP, ap_mac);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "AP MAC spoof failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "AP  MAC spoofed → %02X:%02X:%02X:%02X:%02X:%02X",
             ap_mac[0], ap_mac[1], ap_mac[2],
             ap_mac[3], ap_mac[4], ap_mac[5]);
    return ESP_OK;
}
#endif
