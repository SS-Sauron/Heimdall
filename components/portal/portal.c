/*
 * portal.c
 *
 * Captive portal implementation.
 *
 * HTTP endpoints served:
 *   GET  /                       → index.html (the configuration form)
 *   GET  /api/scan               → JSON array of visible SSIDs
 *   POST /api/provision          → validate + save credentials, reboot
 *
 * Captive-portal OS detection stubs (all redirect to /):
 *   GET  /generate_204           → Android
 *   GET  /hotspot-detect.html    → Apple (iOS / macOS)
 *   GET  /ncsi.txt               → Windows
 *   GET  /connecttest.txt        → Windows 10+
 *   GET  /redirect               → Android fallback
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_http_server.h"
#include "esp_random.h"
#include "cJSON.h"
#include "mbedtls/md.h"
#include "dns_server.h"
#include "storage.h"
#include "identity.h"
#include "portal.h"
#include "sdkconfig.h"
#include "lwip/ip4_addr.h"
#include "esp_timer.h"

static const char *TAG = "portal";

static esp_timer_handle_t s_portal_timeout_timer = NULL;

static void portal_timeout_callback(void* arg) {
    ESP_LOGE(TAG, "Portal abandoned by user (5 minute inactivity timeout) — rebooting");
    esp_restart();
}

/* Embedded HTML (placed in firmware flash via EMBED_FILES in CMakeLists) */
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");

/* Event bit set when the user successfully submits credentials */
#define PORTAL_CRED_SAVED_BIT BIT0
static EventGroupHandle_t s_portal_events = NULL;

/* SoftAP default IP assigned by ESP-IDF */
#define SOFTAP_IP "192.168.4.1"

/* --------------------------------------------------------------------------
 * AP identity derivation
 *
 * SSID  : CONFIG_PORTAL_AP_SSID_PREFIX + upper-hex(SHA256(MAC)[0..2])
 * Pass  : lower-hex(SHA256(MAC)[3..8])   (12 chars, alphanumeric-ish)
 * -------------------------------------------------------------------------- */
static void derive_ap_credentials(char ssid_out[33], char pass_out[13])
{
    uint8_t mac[6];
    identity_get_mac(mac); /* spoofed MAC if OPSEC_IDENTITY on */

    uint8_t digest[32];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (mbedtls_md_setup(&ctx, info, 0) != 0 ||
        mbedtls_md_starts(&ctx) != 0 ||
        mbedtls_md_update(&ctx, mac, 6) != 0 ||
        mbedtls_md_finish(&ctx, digest) != 0)
    {
        ESP_LOGE(TAG, "SHA-256 failed in derive_ap_credentials");
        mbedtls_md_free(&ctx);
        memcpy(digest, mac, 6);
    }
    else
    {
        mbedtls_md_free(&ctx);
    }

    /* SSID: prefix + first 3 digest bytes as uppercase hex */
    snprintf(ssid_out, 33, "%s%02X%02X%02X",
             CONFIG_PORTAL_AP_SSID_PREFIX,
             digest[0], digest[1], digest[2]);

#if CONFIG_PORTAL_AP_PASSWORD_FROM_MAC
    /* Password: bytes 3..8 of digest as lowercase hex (12 chars) */
    snprintf(pass_out, 13, "%02x%02x%02x%02x%02x%02x",
             digest[3], digest[4], digest[5],
             digest[6], digest[7], digest[8]);
#else
    pass_out[0] = '\0'; /* open AP */
#endif
}

/* --------------------------------------------------------------------------
 * SoftAP initialisation
 * -------------------------------------------------------------------------- */
static esp_netif_t *s_ap_netif = NULL;

static void start_softap(const char *ssid, const char *password)
{
    s_ap_netif = esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_cfg = WIFI_INIT_CONFIG_DEFAULT();
    /* esp_wifi_init may already have been called by identity.c — ignore
     * ESP_ERR_WIFI_INIT_STATE in that case */
    esp_err_t init_err = esp_wifi_init(&wifi_cfg);
    if (init_err != ESP_OK && init_err != ESP_ERR_WIFI_INIT_STATE)
    {
        ESP_ERROR_CHECK(init_err);
    }

    wifi_config_t ap_config = {
        .ap = {
            .channel = CONFIG_PORTAL_AP_CHANNEL,
            .max_connection = CONFIG_PORTAL_AP_MAX_CONN,
            .authmode = (password[0] != '\0')
                            ? WIFI_AUTH_WPA2_PSK
                            : WIFI_AUTH_OPEN,
            .pmf_cfg = {.required = false},
        }};
    strncpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid) - 1);
    strncpy((char *)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
    ap_config.ap.ssid_len = (uint8_t)strlen(ssid);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "SoftAP started  SSID: %s  Auth: %s",
             ssid, password[0] ? "WPA2" : "OPEN");
}

/* --------------------------------------------------------------------------
 * JSON helpers
 * -------------------------------------------------------------------------- */
static esp_err_t send_json(httpd_req_t *req, cJSON *root, int http_status)
{
    char *body = cJSON_PrintUnformatted(root);
    httpd_resp_set_status(req, http_status == 200 ? "200 OK" : "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t ret = httpd_resp_sendstr(req, body ? body : "{}");
    free(body);
    return ret;
}

/* --------------------------------------------------------------------------
 * HTTP handlers
 * -------------------------------------------------------------------------- */

/* GET / — serve the embedded HTML form */
static esp_err_t handle_root(httpd_req_t *req)
{
    if (s_portal_timeout_timer != NULL) {
        esp_timer_restart(s_portal_timeout_timer, 300ULL * 1000000ULL);
    }
    size_t html_len = (size_t)(index_html_end - index_html_start);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, index_html_start, (ssize_t)html_len);
}

/* GET /api/scan — return JSON array of visible SSIDs */
static esp_err_t handle_scan(httpd_req_t *req)
{
    /* Perform a blocking WiFi scan */
    wifi_scan_config_t scan_cfg = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = false,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
    };

    /* FIX 2: check the return value of esp_wifi_scan_start */
    esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Scan failed: %s", esp_err_to_name(err));
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    uint16_t count = 0;
    esp_wifi_scan_get_ap_num(&count);

    /* FIX 1: reduced cap from 20 to 10 to avoid contiguous heap exhaustion */
    uint16_t max_aps = (count > 10) ? 10 : count;
    wifi_ap_record_t *records = calloc(max_aps, sizeof(wifi_ap_record_t));
    if (!records)
    {
        ESP_LOGE(TAG, "OOM in scan handler");
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }
    esp_wifi_scan_get_ap_records(&max_aps, records);

    /* FIX 3: NULL check on cJSON array creation */
    cJSON *arr = cJSON_CreateArray();
    if (!arr)
    {
        ESP_LOGE(TAG, "OOM building scan JSON");
        free(records);
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    for (int i = 0; i < max_aps; i++)
    {
        /* FIX 3: NULL check on each cJSON object creation */
        cJSON *entry = cJSON_CreateObject();
        if (!entry)
        {
            ESP_LOGW(TAG, "OOM creating JSON entry at index %d, stopping early", i);
            break;
        }
        cJSON_AddStringToObject(entry, "ssid", (char *)records[i].ssid);
        cJSON_AddNumberToObject(entry, "rssi", records[i].rssi);
        cJSON_AddBoolToObject(entry, "auth", records[i].authmode != WIFI_AUTH_OPEN);
        cJSON_AddItemToArray(arr, entry);
    }

    /* records no longer needed — free before sending to relieve heap pressure */
    free(records);

    esp_err_t ret = send_json(req, arr, 200);
    cJSON_Delete(arr);
    return ret;
}

/* --------------------------------------------------------------------------
 * Broker URL sanitisation
 *
 * Strips any scheme prefix that esp-mqtt adds itself at connect time.
 * The NVS field holds only the bare hostname (or IP); the scheme is
 * determined separately by the mqtt_relay component based on the port.
 * -------------------------------------------------------------------------- */
static const char *sanitize_broker_url(const char *url)
{
    static const char *const prefixes[] = {
        "mqtt://", "mqtts://", "tcp://", "ssl://", "http://", "https://", NULL
    };
    for (int i = 0; prefixes[i] != NULL; i++) {
        size_t len = strlen(prefixes[i]);
        if (strncasecmp(url, prefixes[i], len) == 0) {
            return url + len; /* pointer into caller's buffer — no allocation */
        }
    }
    return url; /* no recognised prefix — return as-is */
}

/* POST /api/provision — parse, validate, save credentials, trigger reboot */
static esp_err_t handle_provision(httpd_req_t *req)
{
    /* Read the POST body */
    int content_len = req->content_len;
    if (content_len <= 0 || content_len > 768)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Body too large");
        return ESP_FAIL;
    }

    char *body = malloc(content_len + 1);
    if (!body)
    {
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    int received = httpd_req_recv(req, body, content_len);
    if (received != content_len)
    {
        free(body);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete body");
        return ESP_FAIL;
    }
    body[content_len] = '\0';

    /* Parse JSON */
    cJSON *json = cJSON_Parse(body);
    free(body);

    if (!json)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    /* Extract fields */
    storage_credentials_t creds = {0};
    cJSON *j;

    j = cJSON_GetObjectItem(json, "wifi_ssid");
    if (!cJSON_IsString(j) || strlen(j->valuestring) == 0 || strlen(j->valuestring) > STORAGE_SSID_MAX)
    {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid WiFi SSID");
        esp_err_t r = send_json(req, err, 400);
        cJSON_Delete(err);
        return r;
    }
    strncpy(creds.wifi_ssid, j->valuestring, STORAGE_SSID_MAX);

    j = cJSON_GetObjectItem(json, "wifi_pass");
    if (cJSON_IsString(j))
    {
        strncpy(creds.wifi_pass, j->valuestring, STORAGE_WIFI_PASS_MAX);
    }

    j = cJSON_GetObjectItem(json, "mqtt_url");
    if (!cJSON_IsString(j) || strlen(j->valuestring) == 0 || strlen(j->valuestring) > STORAGE_MQTT_URL_MAX)
    {
        cJSON_Delete(json);
        cJSON *err = cJSON_CreateObject();
        cJSON_AddStringToObject(err, "error", "Invalid MQTT broker URL");
        esp_err_t r = send_json(req, err, 400);
        cJSON_Delete(err);
        return r;
    }
    const char *clean_url = sanitize_broker_url(j->valuestring);
    if (clean_url != j->valuestring) {
        ESP_LOGI(TAG, "Stripped scheme prefix from broker URL: '%s' → '%s'",
                 j->valuestring, clean_url);
    }
    strncpy(creds.mqtt_url, clean_url, STORAGE_MQTT_URL_MAX);

    j = cJSON_GetObjectItem(json, "mqtt_port");
    creds.mqtt_port = cJSON_IsNumber(j) ? (uint16_t)j->valuedouble : 8883;

    j = cJSON_GetObjectItem(json, "mqtt_user");
    if (cJSON_IsString(j))
        strncpy(creds.mqtt_user, j->valuestring, STORAGE_MQTT_USER_MAX);

    j = cJSON_GetObjectItem(json, "mqtt_pass");
    if (cJSON_IsString(j))
        strncpy(creds.mqtt_pass, j->valuestring, STORAGE_MQTT_PASS_MAX);

    /* Optional hostname field — validate if present, reject with 400 if invalid */
    char validated_hostname[STORAGE_HOSTNAME_MAX + 1] = {0};
    bool hostname_provided = false;
    j = cJSON_GetObjectItem(json, "hostname");
    if (cJSON_IsString(j) && strlen(j->valuestring) > 0) {
        const char *hn = j->valuestring;
        size_t hn_len = strlen(hn);
        bool valid = (hn_len >= 1 && hn_len <= STORAGE_HOSTNAME_MAX);
        if (valid && (hn[0] == '-' || hn[hn_len - 1] == '-'))
            valid = false;
        if (valid) {
            for (size_t i = 0; i < hn_len && valid; i++) {
                char c = hn[i];
                if (!isalnum((unsigned char)c) && c != '-')
                    valid = false;
            }
        }
        if (!valid) {
            cJSON_Delete(json);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "error",
                "Invalid hostname: 1–32 chars, a-z/A-Z/0-9/hyphen, "
                "must not start or end with a hyphen");
            esp_err_t r = send_json(req, err, 400);
            cJSON_Delete(err);
            return r;
        }
        strncpy(validated_hostname, hn, STORAGE_HOSTNAME_MAX);
        hostname_provided = true;
    }

    cJSON_Delete(json);

    if (s_portal_timeout_timer != NULL) {
        esp_timer_stop(s_portal_timeout_timer);
        esp_timer_delete(s_portal_timeout_timer);
        s_portal_timeout_timer = NULL;
    }

    /* Save and signal the main portal task */
    esp_err_t save_err = storage_save_credentials(&creds);
    if (save_err != ESP_OK)
    {
        cJSON *err_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(err_obj, "error", "NVS write failed");
        esp_err_t r = send_json(req, err_obj, 400);
        cJSON_Delete(err_obj);
        return r;
    }

    /* Save hostname if the user provided one (optional) */
    if (hostname_provided) {
        esp_err_t hn_err = storage_save_hostname(validated_hostname);
        if (hn_err != ESP_OK) {
            ESP_LOGW(TAG, "Hostname save failed (%s) — device will use default",
                     esp_err_to_name(hn_err));
        }
    }

#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
    uint8_t hmac_secret[STORAGE_HMAC_SECRET_LEN];
    storage_load_or_generate_hmac_secret(hmac_secret);
    char hmac_hex[STORAGE_HMAC_SECRET_LEN * 2 + 1];
    for (int i = 0; i < STORAGE_HMAC_SECRET_LEN; i++)
        snprintf(hmac_hex + i * 2, 3, "%02x", hmac_secret[i]);
#endif
#if CONFIG_OPSEC_TOTP
    uint8_t totp_seed[STORAGE_TOTP_SEED_LEN];
    storage_load_or_generate_totp_seed(totp_seed);
    char totp_hex[STORAGE_TOTP_SEED_LEN * 2 + 1];
    for (int i = 0; i < STORAGE_TOTP_SEED_LEN; i++)
        snprintf(totp_hex + i * 2, 3, "%02x", totp_seed[i]);
#endif

    /* Send success response before triggering the reboot */
    cJSON *ok = cJSON_CreateObject();
    cJSON_AddStringToObject(ok, "status", "ok");

#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
    cJSON_AddStringToObject(ok, "hmac_secret", hmac_hex);
#endif
#if CONFIG_OPSEC_TOTP
    cJSON_AddStringToObject(ok, "totp_seed", totp_hex);
#endif

    cJSON_AddStringToObject(ok, "message", "Credentials saved. Rebooting...");
    esp_err_t ret = send_json(req, ok, 200);
    cJSON_Delete(ok);

    /* Signal portal_start() to finish and reboot */
    xEventGroupSetBits(s_portal_events, PORTAL_CRED_SAVED_BIT);
    return ret;
}

/* OS captive-portal detection: redirect everything else to / */
static esp_err_t handle_captive_redirect(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://" SOFTAP_IP "/");
    return httpd_resp_send(req, NULL, 0);
}

/* --------------------------------------------------------------------------
 * HTTP server registration
 * -------------------------------------------------------------------------- */
static httpd_handle_t start_http_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = CONFIG_PORTAL_HTTP_PORT;
    config.max_open_sockets = 5;
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 12;

    httpd_handle_t server = NULL;
    if (httpd_start(&server, &config) != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to start HTTP server");
        return NULL;
    }

    static const httpd_uri_t uris[] = {
        {.uri = "/", .method = HTTP_GET, .handler = handle_root},
        {.uri = "/api/scan", .method = HTTP_GET, .handler = handle_scan},
        {.uri = "/api/provision", .method = HTTP_POST, .handler = handle_provision},
        /* OS detection stubs */
        {.uri = "/generate_204", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/ncsi.txt", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/connecttest.txt", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/redirect", .method = HTTP_GET, .handler = handle_captive_redirect},
        /* Wildcard catch-all — must be last */
        {.uri = "/*", .method = HTTP_ANY, .handler = handle_captive_redirect},
    };

    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++)
    {
        httpd_register_uri_handler(server, &uris[i]);
    }

    ESP_LOGI(TAG, "HTTP server ready on port %d", CONFIG_PORTAL_HTTP_PORT);
    return server;
}

/* --------------------------------------------------------------------------
 * portal_start — public entry point (never returns)
 * -------------------------------------------------------------------------- */
void portal_start(void)
{
    char ssid[33] = {0};
    char pass[13] = {0};
    derive_ap_credentials(ssid, pass);

    ESP_LOGI(TAG, "Portal AP  SSID: %s", ssid);
#if CONFIG_WOL_SERIAL_PROVISION_INFO
    if (pass[0])
    {
        ESP_LOGI(TAG, "Portal AP  PASS: %s  (write this on a label)", pass);
    }
#endif

    /* Create event group before starting HTTP server so the handler
     * can set the bit from within an HTTP callback */
    s_portal_events = xEventGroupCreate();
    configASSERT(s_portal_events);

    const esp_timer_create_args_t timer_args = {
        .callback = &portal_timeout_callback,
        .name = "portal_watchdog"
    };

    if (esp_timer_create(&timer_args, &s_portal_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_portal_timeout_timer, 300ULL * 1000000ULL);
    }

    start_softap(ssid, pass);

    /* Start DNS redirect so all DNS queries go to the ESP32 */
    esp_ip4_addr_t ap_ip;
    IP4_ADDR(&ap_ip, 192, 168, 4, 1);
    ESP_ERROR_CHECK(dns_server_start(ap_ip));

    httpd_handle_t server = start_http_server();
    configASSERT(server != NULL);

    ESP_LOGI(TAG, "Portal ready — waiting for credentials");

    /* -----------------------------------------------------------------
     * Block indefinitely. The portal_watchdog timer handles inactivity timeouts,
     * while PORTAL_CRED_SAVED_BIT signals a successful submission.
     * ----------------------------------------------------------------- */
    xEventGroupWaitBits(
        s_portal_events,
        PORTAL_CRED_SAVED_BIT,
        pdFALSE, /* don't clear on exit */
        pdFALSE, /* any bit */
        portMAX_DELAY);

    ESP_LOGI(TAG, "Credentials saved — rebooting into relay mode");

    /* Give the HTTP response a moment to flush before restarting */
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_restart();
    /* unreachable */
}
