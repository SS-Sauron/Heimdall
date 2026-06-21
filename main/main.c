/*
 * wol_relay — main.c
 *
 * Boot dispatcher. This file owns the startup sequence only.
 * All business logic lives in the component layer.
 *
 * Boot sequence:
 *   1. NVS flash init
 *   2. Core networking primitives + one-time WiFi driver init
 *   3. Factory-reset button check (blocking — GPIO 0, active-low)
 *   4. Identity obfuscation (MAC spoof, hostname) — before WiFi starts
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
#include "esp_wifi.h"
#include "driver/gpio.h"
#include "esp_system.h"
#include "esp_attr.h"

#include "identity.h"
#include "storage.h"
#include "portal.h"
#include "wifi_sta.h"
#include "mqtt_relay.h"
#include "mdns.h"
#include "lwip/apps/netbiosns.h"

static const char *TAG = "main";

RTC_NOINIT_ATTR volatile uint32_t boot_crash_counter;

/* --------------------------------------------------------------------------
 * app_main — entry point called by ESP-IDF after system init
 * -------------------------------------------------------------------------- */

/* ------------------------------------------------------------------
 * Background Task: Factory Reset Monitor
 * Watches GPIO 0 (BOOT button) continuously.
 * ------------------------------------------------------------------ */
static void factory_reset_task(void *pvParameters) {
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << 0),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_ENABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    gpio_config(&io_conf);

    while (1) {
        if (gpio_get_level(0) == 0) {
            vTaskDelay(pdMS_TO_TICKS(20)); /* debounce */
            if (gpio_get_level(0) == 0) {
                ESP_LOGW(TAG, "BOOT button held — factory reset armed. Hold for %d ms to confirm.", CONFIG_WOL_FACTORY_RESET_HOLD_MS);
                int elapsed_ms = 20;
                bool confirmed = false;
                while (elapsed_ms < CONFIG_WOL_FACTORY_RESET_HOLD_MS) {
                    vTaskDelay(pdMS_TO_TICKS(50));
                    elapsed_ms += 50;
                    if (gpio_get_level(0) != 0) {
                        ESP_LOGI(TAG, "BOOT button released — factory reset cancelled");
                        break;
                    }
                    if (elapsed_ms >= CONFIG_WOL_FACTORY_RESET_HOLD_MS) {
                        confirmed = true;
                        break;
                    }
                }
                
                if (confirmed) {
                    ESP_LOGW(TAG, "Factory reset confirmed — wiping all NVS credentials");
                    vTaskDelay(pdMS_TO_TICKS(200));
                    storage_erase_all();
                    ESP_LOGI(TAG, "NVS erased — rebooting into captive portal");
                    vTaskDelay(pdMS_TO_TICKS(200));
                    esp_log_level_set("*", ESP_LOG_NONE); /* Suppress ugly disconnect errors during reboot */
                    esp_restart();
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(100)); /* Polling interval */
    }
}

void app_main(void)
{
    esp_reset_reason_t reason = esp_reset_reason();
    if (reason == ESP_RST_PANIC || 
        reason == ESP_RST_INT_WDT || reason == ESP_RST_TASK_WDT ||
        reason == ESP_RST_WDT) {
        boot_crash_counter++;
    } else {
        /* Clean boot (e.g., power-on, external reset). Clear counter
         * because RTC_NOINIT_ATTR memory contains garbage on cold boot. */
        boot_crash_counter = 0;
    }

    ESP_LOGI(TAG, "=== WoL Relay starting ===");
    if (boot_crash_counter > 0) {
        ESP_LOGW(TAG, "Continuous crash loop count: %lu", (unsigned long)boot_crash_counter);
    }

    if (boot_crash_counter >= 3) {
        ESP_LOGE(TAG, "Crash loop detected! Engaging escape hatch — wiping NVS");
        boot_crash_counter = 0;
        
        esp_err_t err = nvs_flash_erase();
        if (err == ESP_OK) {
            ESP_LOGW(TAG, "NVS wiped successfully. Rebooting into factory state.");
        } else if (err == ESP_ERR_NOT_FOUND) {
            ESP_LOGE(TAG, "NVS partition not found during wipe attempt.");
        } else {
            ESP_LOGE(TAG, "Failed to erase NVS: %s", esp_err_to_name(err));
        }
        
        esp_restart();
    }

    /* ------------------------------------------------------------------
     * Step 1: NVS flash initialisation
     * Erase and reinitialise if the partition has been erased or the
     * stored format version changed (common after a full reflash).
     *
     * Note: The "nvs_keys" partition is allocated in partitions.csv but
     * NVS encryption (nvs_flash_secure_init) is not yet enabled here.
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
     * Step 2: Core networking primitives + one-time WiFi driver init
     * Must be done before any WiFi or TCP/IP operation.
     * ------------------------------------------------------------------ */
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(mdns_init());
    netbiosns_init();
    ESP_LOGI(TAG, "netif + event loop ready");

    /* Create the default STA netif before identity_apply() so hostname
     * assignment can happen before DHCP, then initialize the WiFi driver once.
     * Station/portal code owns mode/config/start after identity is applied. */
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif == NULL) {
        sta_netif = esp_netif_create_default_wifi_sta();
    }
    configASSERT(sta_netif != NULL);

    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wifi_cfg));
    ESP_LOGI(TAG, "WiFi base initialized");

    /* ------------------------------------------------------------------
     * Step 3: Factory-reset button monitor
     * Spawns a background task to constantly monitor the BOOT button.
     * ------------------------------------------------------------------ */
    xTaskCreate(factory_reset_task, "reset_task", 2048, NULL, 1, NULL);


    /* ------------------------------------------------------------------
     * Step 4: Identity obfuscation
     * Applies MAC spoof and DHCP hostname BEFORE WiFi driver starts,
     * so the spoofed values are the ones the driver registers with the
     * network stack. No-op in STANDARD build (CONFIG_OPSEC_IDENTITY off).
     * ------------------------------------------------------------------ */
    identity_apply();

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
#if CONFIG_WOL_SERIAL_PROVISION_INFO
        char portal_password[9] = {0};
        esp_err_t portal_pass_err = portal_derive_password(portal_password);
        if (portal_pass_err != ESP_OK || portal_password[0] == '\0') {
            ESP_LOGE(TAG, "Portal password derivation failed (%s) — rebooting",
                     esp_err_to_name(portal_pass_err));
            esp_restart();
        }
        ESP_LOGI(TAG, "Portal password: %s  (permanent — same after every reset)",
                 portal_password);
#endif
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
