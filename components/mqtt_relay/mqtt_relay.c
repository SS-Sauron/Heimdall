/*
 * mqtt_relay.c
 *
 * Core relay runtime. Uses the native esp_mqtt_client (ESP-IDF component
 * "mqtt"). The client manages its own FreeRTOS task; our event handler
 * is called from that task context for every MQTT event.
 *
 * Event flow:
 *   CONNECTED   → subscribe to command topic, publish "online" to LWT topic
 *   SUBSCRIBED  → log confirmation
 *   DATA        → opsec_parse_payload() → wol_send() → publish response
 *   DISCONNECTED→ log (client auto-reconnects)
 *   ERROR       → log TLS / TCP details
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_err.h"
#include "mqtt_client.h" /* esp-mqtt native component */
#include "storage.h"
#include "wol.h"
#include "opsec.h"
#include "mqtt_relay.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"

static const char *TAG = "mqtt_relay";

/* Context shared between mqtt_relay_start() and the event handler */
static char s_cmd_topic[OPSEC_TOPIC_MAX_LEN];
static char s_rsp_topic[OPSEC_TOPIC_MAX_LEN];
static esp_mqtt_client_handle_t s_client = NULL;

/* Event group: set FATAL bit if the client should not be restarted */
#define RELAY_FATAL_BIT BIT0
static EventGroupHandle_t s_relay_events = NULL;

/* --------------------------------------------------------------------------
 * Response channel
 *
 * Publishes a brief JSON message to the response topic so the trigger
 * script (and the user) can confirm the packet was dispatched.
 * -------------------------------------------------------------------------- */
static void publish_response(const uint8_t mac[6], esp_err_t wol_result)
{
#if CONFIG_WOL_RESPONSE_CHANNEL
    if (s_client == NULL)
        return;

    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
             "\"status\":\"%s\","
             "\"rssi\":%d}",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             wol_result == ESP_OK ? "sent" : "error",
             0 /* TODO: esp_wifi_sta_get_rssi() once available */
    );

    int msg_id = esp_mqtt_client_publish(
        s_client,
        s_rsp_topic,
        payload,
        0, /* len=0 → use strlen */
        1, /* QoS 1 */
        0  /* retain = false */
    );

    if (msg_id < 0)
    {
        ESP_LOGW(TAG, "Response publish failed (client may be disconnected)");
    }
    else
    {
        ESP_LOGD(TAG, "Response published (msg_id=%d): %s", msg_id, payload);
    }
#else
    (void)mac;
    (void)wol_result;
#endif
}

/* --------------------------------------------------------------------------
 * MQTT event handler
 * Called from the esp_mqtt_client internal task.
 * -------------------------------------------------------------------------- */
static void mqtt_event_handler(void *arg, esp_event_base_t base,
                               int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;
    esp_mqtt_client_handle_t client = event->client;

    switch ((esp_mqtt_event_id_t)event_id)
    {

    case MQTT_EVENT_CONNECTED:
        ESP_LOGI(TAG, "MQTT connected — subscribing to: %s", s_cmd_topic);
        esp_mqtt_client_subscribe(client, s_cmd_topic, 1);
        /* Publish "online" status to mirror the LWT offline message */
        esp_mqtt_client_publish(client, s_rsp_topic,
                                "{\"status\":\"online\"}", 0, 1, true);
        break;

    case MQTT_EVENT_DISCONNECTED:
        ESP_LOGW(TAG, "MQTT disconnected — client will reconnect automatically");
        break;

    case MQTT_EVENT_SUBSCRIBED:
        ESP_LOGI(TAG, "Subscription confirmed (msg_id=%d)", event->msg_id);
        /* Firmware has proven it can do its job — cancel OTA rollback */
        esp_ota_mark_app_valid_cancel_rollback();
        break;

    case MQTT_EVENT_DATA:
    {
        /* Guard: only process messages on our command topic */
        if (event->topic_len == 0 ||
            (size_t)event->topic_len != strlen(s_cmd_topic) ||
            strncmp(event->topic, s_cmd_topic, event->topic_len) != 0)
        {
            break;
        }

        ESP_LOGI(TAG, "Command received (%d bytes)", event->data_len);

        /* Parse payload and validate TOTP if enabled */
        uint8_t target_mac[6];
        esp_err_t parse_err = opsec_parse_payload(
            event->data, (size_t)event->data_len, target_mac);

        if (parse_err != ESP_OK)
        {
            ESP_LOGW(TAG, "Payload rejected (err=%s) — ignoring",
                     esp_err_to_name(parse_err));
            break;
        }

        /* Dispatch the Magic Packet */
        esp_err_t wol_err = wol_send_raw(target_mac);

        /* Publish response (no-op if CONFIG_WOL_RESPONSE_CHANNEL=n) */
        publish_response(target_mac, wol_err);
        break;
    }

    case MQTT_EVENT_ERROR:
        if (event->error_handle)
        {
            ESP_LOGE(TAG, "MQTT error type: %d", event->error_handle->error_type);
            if (event->error_handle->connect_return_code)
            {
                ESP_LOGE(TAG, "MQTT connect return code: %d",
                         event->error_handle->connect_return_code);
            }
            if (event->error_handle->esp_tls_last_esp_err)
            {
                ESP_LOGE(TAG, "TLS error: 0x%x",
                         event->error_handle->esp_tls_last_esp_err);
            }
        }
        break;

    default:
        ESP_LOGD(TAG, "Unhandled MQTT event id: %ld", event_id);
        break;
    }
}

/* --------------------------------------------------------------------------
 * Build MQTT broker URI from stored credentials
 *
 * Uses "mqtts://" prefix for port 8883 (TLS) and "mqtt://" for 1883.
 * -------------------------------------------------------------------------- */
static void build_broker_uri(const storage_credentials_t *creds,
                             char *uri_out, size_t uri_len)
{
    const char *scheme = (creds->mqtt_port == 1883) ? "mqtt" : "mqtts";
    snprintf(uri_out, uri_len, "%s://%s:%u",
             scheme, creds->mqtt_url, creds->mqtt_port);
}

/* --------------------------------------------------------------------------
 * mqtt_relay_start — public entry point (never returns)
 * -------------------------------------------------------------------------- */
void mqtt_relay_start(void)
{
    /* ------------------------------------------------------------------
     * Step 1: Initialise OPSEC layer (load key material)
     * ------------------------------------------------------------------ */
    ESP_ERROR_CHECK(opsec_init());

    /* ------------------------------------------------------------------
     * Step 2: SNTP clock sync (required for TOTP — no-op in STANDARD)
     * ------------------------------------------------------------------ */
    esp_err_t sntp_err = opsec_sync_clock(30000);
    if (sntp_err != ESP_OK)
    {
        ESP_LOGW(TAG, "SNTP sync failed — TOTP validation will be unavailable");
    }

    /* ------------------------------------------------------------------
     * Step 3: Derive MQTT topics
     * ------------------------------------------------------------------ */
    ESP_ERROR_CHECK(opsec_derive_topics(s_cmd_topic, s_rsp_topic));

    /* ------------------------------------------------------------------
     * Step 4: Load credentials and build the broker URI
     * ------------------------------------------------------------------ */
    storage_credentials_t creds = {0};
    ESP_ERROR_CHECK(storage_load_credentials(&creds));

    char broker_uri[STORAGE_MQTT_URL_MAX + 16];
    build_broker_uri(&creds, broker_uri, sizeof(broker_uri));
    ESP_LOGI(TAG, "Connecting to MQTT broker: %s", broker_uri);

    /* ------------------------------------------------------------------
     * Step 5: Configure esp_mqtt_client
     * ------------------------------------------------------------------ */
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address = {
                .uri = broker_uri,
            },
            .verification = {
                .skip_cert_common_name_check = CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK,
            },
        },
        .credentials = {
            .username = creds.mqtt_user,
            .authentication = {
                .password = creds.mqtt_pass,
            },
        },
        .session = {
            .keepalive = CONFIG_MQTT_RELAY_KEEPALIVE_SEC,
            .disable_clean_session = false,
            /* Last-will message: broker marks device "offline" on dropout */
            .last_will = {
                .topic = s_rsp_topic,
                .msg = "{\"status\":\"offline\"}",
                .msg_len = 0, /* 0 = use strlen */
                .qos = 1,
                .retain = true,
            },
        },
        .network = {
            .reconnect_timeout_ms = CONFIG_MQTT_RELAY_RECONNECT_TIMEOUT_MS,
        },
        .task = {
            .stack_size = CONFIG_MQTT_RELAY_TASK_STACK_KB * 1024,
        },
    };

    s_client = esp_mqtt_client_init(&mqtt_cfg);
    if (s_client == NULL)
    {
        ESP_LOGE(TAG, "esp_mqtt_client_init() returned NULL — rebooting");
        esp_restart();
    }

    /* Register event handler for all MQTT events */
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(
        s_client, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));

    ESP_ERROR_CHECK(esp_mqtt_client_start(s_client));
    ESP_LOGI(TAG, "MQTT client started — relay is active");

    /* ------------------------------------------------------------------
     * Step 6: Health monitor loop
     *
     * The esp_mqtt_client handles reconnection internally. This loop
     * keeps the calling task alive (preventing main from returning)
     * and provides a place to add future health checks (e.g. watchdog
     * kicks, periodic RSSI logging, uptime heartbeat publishing).
     * ------------------------------------------------------------------ */
    s_relay_events = xEventGroupCreate();

    while (true)
    {
        /* Log uptime every 5 minutes at DEBUG level */
        vTaskDelay(pdMS_TO_TICKS(300000));
        ESP_LOGD(TAG, "Relay alive — uptime: %llu s",
                 (unsigned long long)esp_timer_get_time() / 1000000ULL);

        /* Check if a fatal event was signalled by the event handler */
        EventBits_t bits = xEventGroupGetBits(s_relay_events);
        if (bits & RELAY_FATAL_BIT)
        {
            ESP_LOGE(TAG, "Fatal relay error — rebooting");
            esp_restart();
        }
    }
}
