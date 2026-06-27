/*
 * mqtt_relay.c
 *
 * Core relay runtime. Uses the native esp_mqtt_client (ESP-IDF component
 * "mqtt"). The client manages its own FreeRTOS task; our event handler
 * is called from that task context for every MQTT event.
 *
 * Event flow:
 *   CONNECTED   → subscribe to command topic, publish "online" to status topic
 *   SUBSCRIBED  → log confirmation, cancel OTA rollback
 *   DATA        → detect_command_type()
 *                 ├─ GPIO: gpio_handle_command() [if CONFIG_WOL_GPIO_COMMANDS]
 *                 └─ WoL:  opsec_parse_payload() → wol_send() → publish_status()
 *                          → [optional] opsec_extract_ip() → wol_ping_start()
 *   DISCONNECTED→ log (client auto-reconnects)
 *   ERROR       → log TLS / TCP details
 */

#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "mqtt_client.h" /* esp-mqtt native component */
#include "storage.h"
#include "wol.h"
#include "opsec.h"
#include "mqtt_relay.h"
#include "sdkconfig.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#if CONFIG_WOL_GPIO_COMMANDS
#include "driver/gpio.h"
#endif

static const char *TAG = "mqtt_relay";

/* Context shared between mqtt_relay_start() and the event handler */
static char s_cmd_topic[OPSEC_TOPIC_MAX_LEN];
static char s_status_topic[OPSEC_TOPIC_MAX_LEN]; /* /s — machine JSON, retained */
static char s_log_topic[OPSEC_TOPIC_MAX_LEN];    /* /l — human diagnostics, not retained */
static esp_mqtt_client_handle_t s_client = NULL;

/* --------------------------------------------------------------------------
 * Response channel
 *
 * publish_status() → /s  — machine-readable JSON, retain=false (WoL events)
 * publish_log()    → /l  — human-readable diagnostics, retain=false
 * Both also publish to the legacy /r topic when WOL_LEGACY_RSP_TOPIC=y.
 * -------------------------------------------------------------------------- */
static void publish_status(const char *payload)
{
#if CONFIG_WOL_RESPONSE_CHANNEL
    if (s_client == NULL || payload == NULL)
        return;

    int msg_id = esp_mqtt_client_publish(
        s_client, s_status_topic, payload, 0, 1, 0);
    if (msg_id < 0)
        ESP_LOGW(TAG, "Status publish failed");
    else
        ESP_LOGD(TAG, "Status published: %s", payload);

#if CONFIG_WOL_LEGACY_RSP_TOPIC
    /* Duplicate to legacy topic for backward compatibility */
    esp_mqtt_client_publish(s_client, s_log_topic, payload, 0, 1, 0);
#endif
#else
    (void)payload;
#endif
}

static void publish_log(const char *payload)
{
#if CONFIG_WOL_RESPONSE_CHANNEL
    if (s_client == NULL || payload == NULL)
        return;

    int msg_id = esp_mqtt_client_publish(
        s_client, s_log_topic, payload, 0, 1, 0);
    if (msg_id < 0)
        ESP_LOGW(TAG, "Log publish failed");
    else
        ESP_LOGD(TAG, "Log published: %s", payload);
#else
    (void)payload;
#endif
}

static void publish_wol_status(const uint8_t mac[6], esp_err_t wol_result)
{
#if CONFIG_WOL_RESPONSE_CHANNEL
    if (s_client == NULL)
        return;

    char payload[160];
    snprintf(payload, sizeof(payload),
             "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
             "\"status\":\"%s\"}",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             wol_result == ESP_OK ? "sent" : "error");
    publish_status(payload);

    /* Health diagnostics go to the log topic, not status */
    uint32_t heap_free = esp_get_free_heap_size();
    int64_t  uptime_s  = esp_timer_get_time() / 1000000LL;
    char log_payload[96];
    snprintf(log_payload, sizeof(log_payload),
             "{\"free_heap\":%" PRIu32 ",\"uptime_s\":%" PRId64 "}",
             heap_free, uptime_s);
    publish_log(log_payload);
#else
    (void)mac;
    (void)wol_result;
#endif
}

/* --------------------------------------------------------------------------
 * GPIO command handler
 * -------------------------------------------------------------------------- */
#if CONFIG_WOL_GPIO_COMMANDS

/* Parse the allowed-pins string from Kconfig into a bitmask once at startup */
static uint64_t s_gpio_allowed_mask = 0;

static void gpio_init_allowed_pins(void)
{
    /* CONFIG_WOL_GPIO_ALLOWED_PINS is a comma-separated string e.g. "4,5" */
    char pins_str[] = CONFIG_WOL_GPIO_ALLOWED_PINS;
    char *tok = pins_str;
    char *end = pins_str + sizeof(pins_str);
    while (tok < end && *tok != '\0')
    {
        int pin = (int)strtol(tok, &tok, 10);
        if (pin >= 0 && pin < GPIO_NUM_MAX)
        {
            /* Configure pin as output now so we don't do it on the first command */
            gpio_reset_pin((gpio_num_t)pin);
            gpio_config_t io_conf = {
                .pin_bit_mask  = (1ULL << pin),
                .mode          = GPIO_MODE_OUTPUT,
                .pull_up_en    = GPIO_PULLUP_DISABLE,
                .pull_down_en  = GPIO_PULLDOWN_DISABLE,
                .intr_type     = GPIO_INTR_DISABLE,
            };
            gpio_config(&io_conf);
            /* Safe default: all outputs start LOW */
            gpio_set_level((gpio_num_t)pin, 0);
            s_gpio_allowed_mask |= (1ULL << pin);
            ESP_LOGI(TAG, "GPIO %d configured as output (allowed)", pin);
        }
        /* Skip comma or any non-digit */
        while (tok < end && *tok != '\0' && (*tok < '0' || *tok > '9'))
            tok++;
    }
}

static bool gpio_pin_is_allowed(int pin)
{
    if (pin < 0 || pin >= GPIO_NUM_MAX)
        return false;
    return (s_gpio_allowed_mask & (1ULL << pin)) != 0;
}

static void gpio_handle_command(const char *data, int data_len)
{
    cJSON *root = cJSON_ParseWithLength(data, (size_t)data_len);
    if (!root)
    {
        ESP_LOGW(TAG, "GPIO: failed to parse JSON payload");
        return;
    }

#if CONFIG_OPSEC_TOTP
    /* HARDENED: require a TOTP code in the "totp" field */
    cJSON *totp_item = cJSON_GetObjectItemCaseSensitive(root, "totp");
    if (!cJSON_IsNumber(totp_item))
    {
        ESP_LOGW(TAG, "GPIO: missing or non-numeric 'totp' field — rejected");
        cJSON_Delete(root);
        return;
    }
    uint32_t totp_code = (uint32_t)totp_item->valuedouble;
    if (opsec_validate_totp_code(totp_code) != ESP_OK)
    {
        ESP_LOGW(TAG, "GPIO: TOTP validation failed — command rejected");
        cJSON_Delete(root);
        return;
    }
#endif /* CONFIG_OPSEC_TOTP */

    cJSON *pin_item   = cJSON_GetObjectItemCaseSensitive(root, "pin");
    cJSON *level_item = cJSON_GetObjectItemCaseSensitive(root, "level");

    if (!cJSON_IsNumber(pin_item) || !cJSON_IsNumber(level_item))
    {
        ESP_LOGW(TAG, "GPIO: 'pin' or 'level' missing or not a number");
        cJSON_Delete(root);
        return;
    }

    int pin   = (int)pin_item->valuedouble;
    int level = (int)level_item->valuedouble;

    char rsp[96];
    if (!gpio_pin_is_allowed(pin))
    {
        ESP_LOGW(TAG, "GPIO: pin %d is not in the allowed list", pin);
        snprintf(rsp, sizeof(rsp),
                 "{\"action\":\"gpio\",\"pin\":%d,"
                 "\"status\":\"error\",\"reason\":\"invalid_pin\"}", pin);
        publish_status(rsp);
        cJSON_Delete(root);
        return;
    }

    if (level != 0 && level != 1)
    {
        ESP_LOGW(TAG, "GPIO: level %d invalid (must be 0 or 1)", level);
        snprintf(rsp, sizeof(rsp),
                 "{\"action\":\"gpio\",\"pin\":%d,"
                 "\"status\":\"error\",\"reason\":\"invalid_level\"}", pin);
        publish_status(rsp);
        cJSON_Delete(root);
        return;
    }

    esp_err_t err = gpio_set_level((gpio_num_t)pin, (uint32_t)level);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "GPIO: gpio_set_level(%d, %d) failed: %s",
                 pin, level, esp_err_to_name(err));
        snprintf(rsp, sizeof(rsp),
                 "{\"action\":\"gpio\",\"pin\":%d,\"level\":%d,"
                 "\"status\":\"error\",\"reason\":\"gpio_fail\"}", pin, level);
    }
    else
    {
        ESP_LOGI(TAG, "GPIO: pin %d set to %d", pin, level);
        snprintf(rsp, sizeof(rsp),
                 "{\"action\":\"gpio\",\"pin\":%d,\"level\":%d,"
                 "\"status\":\"ok\"}", pin, level);
    }
    publish_status(rsp);
    cJSON_Delete(root);
}
#endif /* CONFIG_WOL_GPIO_COMMANDS */

/* --------------------------------------------------------------------------
 * Command type detection
 *
 * Returns 1 for a GPIO JSON command, 0 for a WoL payload (plain or JSON).
 * Called before any security-critical parsing.
 * -------------------------------------------------------------------------- */
static int is_gpio_command(const char *data, int data_len)
{
#if CONFIG_WOL_GPIO_COMMANDS
    if (data_len < 2 || data[0] != '{')
        return 0;
    /* Quick scan: look for "action":"gpio" before full JSON parse */
    /* cJSON is only called if the quick scan succeeds */
    const char *needle = "\"gpio\"";
    for (int i = 0; i < data_len - 6; i++)
    {
        if (memcmp(data + i, needle, 6) == 0)
            return 1;
    }
#else
    (void)data;
    (void)data_len;
#endif
    return 0;
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
        /* Publish "online" to status topic with retain so home automation
         * systems that reconnect immediately see the current device state */
        esp_mqtt_client_publish(client, s_status_topic,
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

        /* --- Command type dispatch --- */
        if (is_gpio_command(event->data, event->data_len))
        {
#if CONFIG_WOL_GPIO_COMMANDS
            gpio_handle_command(event->data, event->data_len);
#endif
            break;
        }

        /* --- WoL path (existing) --- */
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

        /* Record timestamp before send — used for boot_time_s calculation */
        int64_t wol_send_time = esp_timer_get_time();

        /* Dispatch the Magic Packet */
        esp_err_t wol_err = wol_send_raw(target_mac);

        /* Publish immediate WoL status response */
        publish_wol_status(target_mac, wol_err);

#if CONFIG_WOL_PING_FEEDBACK
        {
            /* Extract optional IP — does not touch security-critical parsing */
            char ip_str[16] = {0};
            esp_err_t ip_err = opsec_extract_ip(
                event->data, (size_t)event->data_len, ip_str);

            if (ip_err == ESP_OK)
            {
                esp_err_t ping_err = wol_ping_start(
                    ip_str,
                    target_mac,
                    s_client,
                    s_status_topic,
                    wol_send_time);

                if (ping_err == ESP_ERR_INVALID_STATE)
                {
                    ESP_LOGW(TAG, "Ping session already active — skipped");
                }
                else if (ping_err != ESP_OK)
                {
                    ESP_LOGW(TAG, "Failed to start ping: %s",
                             esp_err_to_name(ping_err));
                }
                else
                {
                    ESP_LOGI(TAG, "Ping session started for %s", ip_str);
                }
            }
            else if (ip_err == ESP_ERR_NOT_FOUND)
            {
                ESP_LOGD(TAG, "No IP in payload — ping skipped");
            }
            else
            {
                ESP_LOGW(TAG, "Malformed IP in payload — ping skipped");
            }
        }
#endif /* CONFIG_WOL_PING_FEEDBACK */
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

            if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED &&
                (event->error_handle->connect_return_code == MQTT_CONNECTION_REFUSE_NOT_AUTHORIZED ||
                 event->error_handle->connect_return_code == MQTT_CONNECTION_REFUSE_BAD_USERNAME))
            {
                ESP_LOGE(TAG, "Invalid MQTT credentials — wiping device and rebooting to portal");
                storage_erase_all();
                esp_restart();
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
    ESP_ERROR_CHECK(opsec_derive_topics(s_cmd_topic, s_status_topic, s_log_topic));

#if CONFIG_WOL_GPIO_COMMANDS
    gpio_init_allowed_pins();
#endif

    /* ------------------------------------------------------------------
     * Step 4: Load credentials and build the broker URI
     * ------------------------------------------------------------------ */
    storage_credentials_t creds = {0};
    ESP_ERROR_CHECK(storage_load_credentials(&creds));

    char broker_uri[STORAGE_MQTT_URL_MAX + 16];
    build_broker_uri(&creds, broker_uri, sizeof(broker_uri));
    ESP_LOGI(TAG, "Connecting to MQTT broker: %s", broker_uri);
    ESP_LOGI(TAG, "MQTT credential lengths: username=%u password=%u",
             (unsigned)strlen(creds.mqtt_user),
             (unsigned)strlen(creds.mqtt_pass));
#if CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK
    ESP_LOGW(TAG, "TLS hostname verification/SNI: disabled by config");
#else
    ESP_LOGI(TAG, "TLS hostname verification/SNI: enabled via broker URI hostname");
#endif

    /* ------------------------------------------------------------------
     * Step 5: Configure esp_mqtt_client
     * ------------------------------------------------------------------ */
    esp_mqtt_client_config_t mqtt_cfg = {
        .broker = {
            .address = {
                .uri = broker_uri,
            },
            .verification = {
                .crt_bundle_attach = esp_crt_bundle_attach,
#if CONFIG_MQTT_RELAY_SKIP_CERT_CN_CHECK
                .skip_cert_common_name_check = true,
#endif
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
                .topic = s_status_topic,
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
    while (true)
    {
        /* Publish uptime heartbeat to the /l log topic every 5 minutes */
        vTaskDelay(pdMS_TO_TICKS(300000));
        uint32_t heap_free = esp_get_free_heap_size();
        int64_t  uptime_s  = esp_timer_get_time() / 1000000LL;
        char heartbeat[96];
        snprintf(heartbeat, sizeof(heartbeat),
                 "{\"free_heap\":%" PRIu32 ",\"uptime_s\":%" PRId64 "}",
                 heap_free, uptime_s);
        publish_log(heartbeat);
        ESP_LOGD(TAG, "Relay alive — uptime: %llu s",
                 (unsigned long long)uptime_s);
#if CONFIG_WOL_PING_FEEDBACK
        /* Release resources from any completed ping session */
        wol_ping_cleanup();
#endif
    }
}
