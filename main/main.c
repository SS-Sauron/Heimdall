/*
 * wol_relay — main.c
 *
 * Boot dispatcher. This file owns the startup sequence only.
 * All business logic lives in the component layer.
 *
 * Boot sequence:
 *   1. NVS flash init
 *   2. Core networking primitives (netif + event loop)
 *   3. Identity obfuscation (MAC spoof, hostname) — before WiFi starts
 *   4. Factory-reset button check
 *   5. Provisioning check → portal (first boot) or station (normal boot)
 *   6. WiFi station connect
 *   7. MQTT relay start (runs indefinitely)
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nvs_flash.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "driver/gpio.h"

#include "identity.h"
#include "storage.h"
#include "portal.h"
#include "wifi_sta.h"
#include "mqtt_relay.h"

static const char *TAG = "main";


/* --------------------------------------------------------------------------
 * app_main — entry point called by ESP-IDF after system init
 * -------------------------------------------------------------------------- */
void app_main(void)
{
    ESP_LOGI(TAG, "=== WoL Relay starting ===");

    /* ------------------------------------------------------------------
     * Step 1: NVS flash initialisation
     * Erase and reinitialise if the partition has been erased or the
     * stored format version changed (common after a full reflash).
     * ------------------------------------------------------------------ */
    esp_err_t nvs_err = nvs_flash_init();
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES ||
        nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_LOGW(TAG, "NVS needs erase (err=0x%x) — erasing", nvs_err);
        ESP_ERROR_CHECK(nvs_flash_erase());
        nvs_err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(nvs_err);
    ESP_LOGI(TAG, "NVS ready");

    /* ------------------------------------------------------------------
     * Step 2: Core networking primitives
     * Must be done before any WiFi or TCP/IP operation.
     * ------------------------------------------------------------------ */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_LOGI(TAG, "netif + event loop ready");

    /* ------------------------------------------------------------------
     * Step 3: Identity obfuscation
     * Applies MAC spoof and DHCP hostname BEFORE WiFi driver starts,
     * so the spoofed values are the ones the driver registers with the
     * network stack. No-op in STANDARD build (CONFIG_OPSEC_IDENTITY off).
     * ------------------------------------------------------------------ */
    identity_apply();

    /* Step 4: Factory reset button initialization
     * Setup the BOOT button to trigger a factory reset on long-press.
     * ------------------------------------------------------------------ */
    storage_button_init();

    /* ------------------------------------------------------------------
     * Step 5: Provisioning branch
     * storage_is_provisioned() returns true if NVS contains a complete
     * set of WiFi + MQTT credentials written by the portal.
     *
     * First boot / after factory reset → portal_start()
     *   Starts SoftAP + HTTP server + DNS redirect. Blocks until the
     *   user submits valid credentials, saves them to NVS, and reboots.
     *   This function never returns.
     *
     * Normal boot → fall through to WiFi + MQTT startup.
     * ------------------------------------------------------------------ */
    if (!storage_is_provisioned()) {
        ESP_LOGI(TAG, "Not provisioned — starting captive portal");
        portal_start();   /* blocks until credentials saved, then reboots */
        /* unreachable */
    }

    ESP_LOGI(TAG, "Credentials found — starting relay");

    /* ------------------------------------------------------------------
     * Step 6: WiFi station connect
     * Reads SSID + password from NVS, connects, and blocks until the
     * network is up (or fails fatally after the configured retry limit).
     * ------------------------------------------------------------------ */
    ESP_ERROR_CHECK(wifi_sta_connect());
    ESP_LOGI(TAG, "WiFi connected");

    /* ------------------------------------------------------------------
     * Step 7: MQTT relay
     * Connects to the broker, subscribes to the command topic, and
     * enters the relay loop. This function does not return under normal
     * operation — it runs as a long-lived FreeRTOS task.
     * ------------------------------------------------------------------ */
    ESP_LOGI(TAG, "Starting MQTT relay");
    mqtt_relay_start();

    /* Should never reach here. If mqtt_relay_start() returns
     * unexpectedly, log and reboot rather than hanging. */
    ESP_LOGE(TAG, "mqtt_relay_start() returned unexpectedly — rebooting");
    esp_restart();
}
