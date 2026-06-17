/*
 * wifi_sta.c
 *
 * WiFi station implementation. Uses an EventGroup so wifi_sta_connect()
 * can block until either GOT_IP or a fatal failure occurs without polling.
 */

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "storage.h"
#include "identity.h"
#include "wifi_sta.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "mdns.h"
#include "lwip/apps/netbiosns.h"

static const char *TAG = "wifi_sta";

#define STA_CONNECTED_BIT BIT0
#define STA_FAIL_BIT BIT1

static EventGroupHandle_t s_wifi_events = NULL;
static int s_retry_count = 0;
static bool s_connected = false;
static esp_netif_t *s_sta_netif = NULL;

/* Timestamp (esp_timer_get_time() in µs) of the first disconnect since
 * the last successful IP assignment. Zero means we are not in a
 * disconnected state (or have never connected). */
static int64_t s_disconnect_start_time = 0;
static bool s_has_connected_once = false;
static bool s_is_tracking_disconnect = false;

/* --------------------------------------------------------------------------
 * Event handlers
 * -------------------------------------------------------------------------- */
static void on_wifi_disconnect(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    s_connected = false;

    /* Start the absolute-timeout clock on the first disconnect */
    if (!s_is_tracking_disconnect) {
        s_disconnect_start_time = esp_timer_get_time();
        s_is_tracking_disconnect = true;
        ESP_LOGW(TAG, "Absolute timeout clock started");
    }

    /* Slow path: if we have been continuously disconnected for longer than
     * CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES, the SSID is probably wrong.
     * Erase credentials and reboot into the provisioning portal. */
    if (!s_has_connected_once) {
        const uint64_t ceiling_us = (uint64_t)CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES * 60ULL * 1000000ULL;
        if ((uint64_t)(esp_timer_get_time() - s_disconnect_start_time) >= ceiling_us) {
            ESP_LOGE(TAG,
                     "Absolute timeout (%d min) exceeded — erasing credentials "
                     "and rebooting into portal",
                     CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES);
            xEventGroupSetBits(s_wifi_events, STA_FAIL_BIT);
            storage_erase_all();
            esp_restart();
            /* unreachable */
        }
    }

    /* FIX 3 + NEW PROBLEM 3: read the disconnect reason from event data */
    wifi_event_sta_disconnected_t *disc = (wifi_event_sta_disconnected_t *)data;
    uint8_t reason = disc->reason;

    /* Definitive wrong-credential reasons — count toward portal fallback.
     * Everything else (router reboot, signal loss, v6 NO_AP_FOUND variants,
     * AUTH_EXPIRE, BEACON_TIMEOUT etc.) retries indefinitely. */
    bool wrong_creds = (reason == WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT ||
                        reason == WIFI_REASON_HANDSHAKE_TIMEOUT ||
                        reason == WIFI_REASON_802_1X_AUTH_FAILED ||
                        reason == WIFI_REASON_IE_IN_4WAY_DIFFERS);

    if (wrong_creds)
    {
        s_retry_count++;
        ESP_LOGW(TAG, "Wrong credentials suspected (reason %d) — attempt %d/%d",
                 reason, s_retry_count, CONFIG_WIFI_STA_MAX_RETRY);
        if (s_retry_count >= CONFIG_WIFI_STA_MAX_RETRY)
        {
            ESP_LOGE(TAG, "Max credential failures — triggering portal fallback");
            xEventGroupSetBits(s_wifi_events, STA_FAIL_BIT);
            return; /* do NOT call esp_wifi_connect() after setting FAIL_BIT */
        }
    }
    else
    {
        /* Transient disconnect — reset counter so transient events never
         * accumulate toward the portal-fallback threshold */
        s_retry_count = 0;
        ESP_LOGW(TAG, "Transient disconnect (reason %d) — retrying indefinitely",
                 reason);
    }

    /* ADDITIONAL PROBLEM 1 FIX: removed vTaskDelay here — never block
     * the WiFi event task. Call esp_wifi_connect() directly. */
    esp_wifi_connect();
}

static void on_got_ip(void *arg, esp_event_base_t base,
                      int32_t id, void *data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
    ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
    s_retry_count = 0;
    s_connected = true;
    s_has_connected_once = true; // Permanently disable the absolute timeout for this boot session
    s_is_tracking_disconnect = false; // Reset the disconnect tracker
    xEventGroupSetBits(s_wifi_events, STA_CONNECTED_BIT);
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */
esp_err_t wifi_sta_connect(void)
{
    /* Read credentials from NVS */
    storage_credentials_t creds = {0};
    esp_err_t err = storage_load_credentials(&creds);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to load credentials from NVS: %s",
                 esp_err_to_name(err));
        return err;
    }

    s_wifi_events = xEventGroupCreate();
    configASSERT(s_wifi_events);

    /* ADDITIONAL PROBLEM 3 FIX: check ifkey before creating a new netif.
     * The portal runs in APSTA mode and may have already created the STA
     * netif. Creating it again produces a duplicate. */
    if (s_sta_netif == NULL)
    {
        s_sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        if (s_sta_netif == NULL)
        {
            s_sta_netif = esp_netif_create_default_wifi_sta();
        }
    }

    /* Apply obfuscated hostname now that the netif exists */
    char hostname[33];
    identity_get_hostname(hostname, sizeof(hostname));
    esp_netif_set_hostname(s_sta_netif, hostname);
    mdns_hostname_set(hostname);
    netbiosns_set_name(hostname);

    /* Initialise WiFi driver if identity.c hasn't already done so */
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    err = esp_wifi_init(&cfg);
    if (err != ESP_OK && err != ESP_ERR_WIFI_INIT_STATE)
    {
        return err;
    }

    /* Register event handlers */
    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, on_wifi_disconnect, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, on_got_ip, NULL));

    /* Configure and start */
    wifi_config_t wifi_cfg = {0};
    strncpy((char *)wifi_cfg.sta.ssid, creds.wifi_ssid, sizeof(wifi_cfg.sta.ssid) - 1);
    strncpy((char *)wifi_cfg.sta.password, creds.wifi_pass, sizeof(wifi_cfg.sta.password) - 1);
    wifi_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "Connecting to SSID: %s", creds.wifi_ssid);
    esp_wifi_connect();

    /* Block indefinitely — the slow-path absolute timeout in
     * on_wifi_disconnect() guarantees we never hang here forever.
     * The only exit is STA_CONNECTED_BIT (returns ESP_OK) or
     * STA_FAIL_BIT (fast-path erase+restart, never returns). */
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events,
        STA_CONNECTED_BIT | STA_FAIL_BIT,
        pdFALSE, pdFALSE,
        portMAX_DELAY);

    if (bits & STA_CONNECTED_BIT)
    {
        return ESP_OK;
    }

    /* STA_FAIL_BIT: wrong credentials confirmed — erase and reboot.
     * (The slow-path erases+restarts directly from the event handler;
     * this branch handles the fast-path MAX_RETRY case.) */
    ESP_LOGE(TAG, "Wrong credentials confirmed — clearing NVS and rebooting");
    storage_erase_all();
    esp_restart();
    /* unreachable — suppress compiler warning */
    return ESP_FAIL;
}

bool wifi_sta_is_connected(void)
{
    return s_connected;
}

esp_err_t wifi_sta_wait_connected(uint32_t timeout_ms)
{
    if (s_connected)
        return ESP_OK;
    if (s_wifi_events == NULL)
        return ESP_ERR_INVALID_STATE;

    TickType_t ticks = (timeout_ms == 0) ? portMAX_DELAY
                                         : pdMS_TO_TICKS(timeout_ms);
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events, STA_CONNECTED_BIT, pdFALSE, pdFALSE, ticks);

    return (bits & STA_CONNECTED_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}