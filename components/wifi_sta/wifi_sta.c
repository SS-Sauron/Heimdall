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

#define STA_CONNECTED_BIT           BIT0
#define STA_FAIL_BIT                BIT1
#define STA_ABSOLUTE_TIMEOUT_BIT    BIT2  /* slow-path: 30-min ceiling elapsed */

static EventGroupHandle_t s_wifi_events = NULL;
static int s_retry_count = 0;
static bool s_connected = false;
static esp_netif_t *s_sta_netif = NULL;

/* Timestamp (esp_timer_get_time() in µs) of the first disconnect since
 * the last successful IP assignment. Zero means we are not in a
 * disconnected state (or have never connected). */
static int64_t s_disconnect_start_time = 0;
static volatile bool s_has_connected_once = false;
static bool s_is_tracking_disconnect = false;

/* --------------------------------------------------------------------------
 * Event handlers
 * -------------------------------------------------------------------------- */
static void on_wifi_disconnect(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    s_connected = false;

    /* Start the absolute-timeout clock on the first disconnect this boot */
    if (!s_is_tracking_disconnect) {
        s_disconnect_start_time = esp_timer_get_time();
        s_is_tracking_disconnect = true;
        ESP_LOGW(TAG, "Absolute timeout clock started (ceiling: %d min)",
                 CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES);
    }

    /* Slow path: if the device has been continuously disconnected for the
     * entire per-boot ceiling AND has never obtained an IP this boot,
     * signal the main task to apply the reboot-strike logic. */
    if (!s_has_connected_once) {
        const uint64_t ceiling_us =
            (uint64_t)CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES * 60ULL * 1000000ULL;
        if ((uint64_t)(esp_timer_get_time() - s_disconnect_start_time) >= ceiling_us) {
            ESP_LOGE(TAG,
                     "Absolute timeout (%d min) exceeded — signalling slow-path reboot",
                     CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MINUTES);
            xEventGroupSetBits(s_wifi_events, STA_ABSOLUTE_TIMEOUT_BIT);
            return; /* do NOT retry — let wifi_sta_connect() handle the restart */
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

    /* Reset fast-path counter */
    s_retry_count = 0;
    s_connected = true;

    /* Permanently disable the absolute timeout for this boot session */
    s_has_connected_once = true;
    s_is_tracking_disconnect = false;
    s_disconnect_start_time = 0;

    /* Reset the persistent reboot-strike counter — any successful connection
     * proves the network is reachable, so consecutive-failure counting resets.
     * Ignore errors: if NVS is temporarily unavailable we simply don't clear
     * the counter this cycle; it will be cleared on the next successful boot. */
    storage_set_reboot_count(0);

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

    /* main.c creates the default STA netif before identity_apply(). Keep this
     * fallback so the component remains robust if called from a test harness. */
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

    /* Block indefinitely — two internal escape hatches prevent a permanent hang:
     *   STA_CONNECTED_BIT        → success, return ESP_OK.
     *   STA_FAIL_BIT             → fast path: wrong credentials confirmed after
     *                              CONFIG_WIFI_STA_MAX_RETRY attempts; erase+restart.
     *   STA_ABSOLUTE_TIMEOUT_BIT → slow path: per-boot 30-min ceiling elapsed
     *                              without ever getting an IP; increment reboot-
     *                              strike counter and restart (erase only after
     *                              CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS
     *                              consecutive cycles). */
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_events,
        STA_CONNECTED_BIT | STA_FAIL_BIT | STA_ABSOLUTE_TIMEOUT_BIT,
        pdFALSE, pdFALSE,
        portMAX_DELAY);

    if (bits & STA_CONNECTED_BIT)
    {
        return ESP_OK;
    }

    if (bits & STA_ABSOLUTE_TIMEOUT_BIT)
    {
        /* Slow path: read, increment, and persist the reboot-strike counter */
        uint8_t strikes = 0;
        storage_get_reboot_count(&strikes);
        strikes++;
        storage_set_reboot_count(strikes);

        if (strikes >= CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS)
        {
            ESP_LOGE(TAG,
                     "Reboot-strike threshold reached (%d/%d) — "
                     "erasing credentials and rebooting into portal",
                     strikes, CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS);
            storage_erase_all();
        }
        else
        {
            ESP_LOGW(TAG,
                     "Slow-path reboot strike %d/%d — retrying after restart",
                     strikes, CONFIG_WIFI_STA_ABSOLUTE_TIMEOUT_MAX_REBOOTS);
        }
        esp_restart();
        /* unreachable */
    }

    /* STA_FAIL_BIT: wrong credentials confirmed — erase and reboot.
     * (on_wifi_disconnect() sets this bit after MAX_RETRY wrong-cred events;
     * it never touches the reboot-strike counter.) */
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
