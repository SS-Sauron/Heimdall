/*
 * portal.c
 *
 * Captive portal implementation.
 *
 * HTTP endpoints served:
 *   GET  /                       → login page, then index.html after login
 *   POST /login                  → unlock RAM-only portal session
 *   GET  /api/scan               → JSON array of visible SSIDs
 *   POST /api/provision          → validate + save credentials, reboot
 *
 * Captive-portal OS detection stubs (all redirect to /):
 *   GET  /generate_204           → Android
 *   GET  /hotspot-detect.html    → Apple (iOS / macOS)
 *   GET  /ncsi.txt               → Windows
 *   GET  /connecttest.txt        → Windows 10+
 *   GET  /redirect               → Android fallback
 *
 * HTTPS interception limitation
 * ─────────────────────────────
 * DNS redirection alone cannot intercept HTTPS requests. When a user types
 * a URL (e.g. "www.google.com") that the browser knows uses HTTPS, or that
 * is on the browser's HSTS preload list, the browser connects directly to
 * port 443. The ESP32 HTTP server on port 80 never sees the request, and
 * DNS redirection is bypassed entirely by the TLS certificate check.
 *
 * DHCP Option 114 (RFC 8910) is the correct primary fix. It sends the
 * captive portal URL to the OS during IP address assignment, before the
 * user opens any browser. The OS performs a controlled HTTP check to a
 * known non-HTTPS URL and automatically shows the portal notification.
 * This is implemented in start_softap() via esp_netif_dhcps_option() with
 * ESP_NETIF_CAPTIVEPORTAL_URI. Users should not need to type anything.
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
#include "esp_system.h"
#include "cJSON.h"
#include "mbedtls/md.h"
#include "psa/crypto.h"
#include "dns_server.h"
#include "identity.h"
#include "storage.h"
#include "portal.h"
#include "sdkconfig.h"
#include "opsec.h"
#include "lwip/ip4_addr.h"
#include "esp_timer.h"

static const char *TAG = "portal";

static esp_timer_handle_t s_portal_timeout_timer = NULL;

static void portal_timeout_callback(void* arg) {
    ESP_LOGE(TAG, "Portal abandoned by user (5 minute inactivity timeout) — rebooting");
    esp_restart();
}

/* Embedded HTML. index.html keeps the existing EMBED_FILES symbol names.
 * The smaller pages use EMBED_TXTFILES and include an appended null byte. */
extern const char index_html_start[] asm("_binary_index_html_start");
extern const char index_html_end[] asm("_binary_index_html_end");
extern const uint8_t login_html_start[] asm("_binary_login_html_start");
extern const uint8_t login_html_end[] asm("_binary_login_html_end");
extern const uint8_t secrets_html_start[] asm("_binary_secrets_html_start");
extern const uint8_t secrets_html_end[] asm("_binary_secrets_html_end");
extern const uint8_t rebooting_html_start[] asm("_binary_rebooting_html_start");
extern const uint8_t rebooting_html_end[] asm("_binary_rebooting_html_end");

/* Event bit set when the user successfully submits credentials */
#define PORTAL_CRED_SAVED_BIT BIT0
static EventGroupHandle_t s_portal_events = NULL;
static bool s_portal_authenticated = false;
static char s_portal_password[9] = {0};

/* SoftAP default IP assigned by ESP-IDF */
#define SOFTAP_IP "192.168.4.1"
#define PORTAL_PASSWORD_LEN 8
#define PORTAL_LOGIN_BODY_MAX 64
#define PORTAL_PASSWORD_KEY "heimdall-portal"
#define PORTAL_PASSWORD_KEY_LEN 15
#define SECRETS_PAGE_BUF_SIZE 4096

static char s_secrets_page_buf[SECRETS_PAGE_BUF_SIZE];

/* --------------------------------------------------------------------------
 * Permanent portal password derivation
 *
 * key  = "heimdall-portal" (15 bytes, no null terminator)
 * data = factory eFuse MAC (6 bytes)
 * pass = first 4 bytes of HMAC-SHA256, uppercase hex
 * -------------------------------------------------------------------------- */
esp_err_t portal_derive_password(char out[9])
{
    if (out == NULL)
        return ESP_ERR_INVALID_ARG;

    out[0] = '\0';

    uint8_t efuse_mac[6] = {0};
    esp_err_t err = esp_read_mac(efuse_mac, ESP_MAC_EFUSE_FACTORY);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to read eFuse factory MAC: %s", esp_err_to_name(err));
        return err;
    }

    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA crypto init failed: %d", (int)status);
        return ESP_FAIL;
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t key_id = 0;

    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attributes, PORTAL_PASSWORD_KEY_LEN * 8);
    psa_set_key_lifetime(&attributes, PSA_KEY_LIFETIME_VOLATILE);

    status = psa_import_key(&attributes,
                            (const uint8_t *)PORTAL_PASSWORD_KEY,
                            PORTAL_PASSWORD_KEY_LEN,
                            &key_id);
    psa_reset_key_attributes(&attributes);
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA portal key import failed: %d", (int)status);
        return ESP_FAIL;
    }

    uint8_t digest[32] = {0};
    size_t mac_len = 0;
    status = psa_mac_compute(key_id,
                             PSA_ALG_HMAC(PSA_ALG_SHA_256),
                             efuse_mac,
                             sizeof(efuse_mac),
                             digest,
                             sizeof(digest),
                             &mac_len);

    psa_status_t destroy_status = psa_destroy_key(key_id);
    if (status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA portal HMAC compute failed: %d", (int)status);
        if (destroy_status != PSA_SUCCESS)
        {
            ESP_LOGE(TAG, "PSA portal key destroy failed after compute error: %d",
                     (int)destroy_status);
        }
        return ESP_FAIL;
    }
    if (destroy_status != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "PSA portal key destroy failed: %d", (int)destroy_status);
        return ESP_FAIL;
    }
    if (mac_len != sizeof(digest))
    {
        ESP_LOGE(TAG, "PSA portal HMAC length mismatch: got %u expected %u",
                 (unsigned)mac_len, (unsigned)sizeof(digest));
        return ESP_FAIL;
    }

    int written = snprintf(out, PORTAL_PASSWORD_LEN + 1,
                           "%02X%02X%02X%02X",
                           digest[0], digest[1], digest[2], digest[3]);
    if (written != PORTAL_PASSWORD_LEN)
    {
        out[0] = '\0';
        ESP_LOGE(TAG, "Portal password formatting failed");
        return ESP_FAIL;
    }

    return ESP_OK;
}

/* --------------------------------------------------------------------------
 * AP identity derivation
 *
 * SSID  : CONFIG_PORTAL_AP_SSID_PREFIX + upper-hex(SHA256(MAC)[0..2])
 * Pass  : derived separately from the eFuse MAC by portal_derive_password()
 * -------------------------------------------------------------------------- */
static void derive_ap_ssid(char ssid_out[33])
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
        ESP_LOGE(TAG, "SHA-256 failed in derive_ap_ssid");
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
}

/* --------------------------------------------------------------------------
 * SoftAP initialisation
 * -------------------------------------------------------------------------- */
static esp_netif_t *s_ap_netif = NULL;

static void start_softap(const char *ssid, const char *password)
{
    if (password == NULL || strlen(password) != PORTAL_PASSWORD_LEN)
    {
        ESP_LOGE(TAG, "Refusing to start portal without a valid derived password");
        esp_restart();
    }

    if (s_ap_netif == NULL)
    {
        s_ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (s_ap_netif == NULL)
        {
            s_ap_netif = esp_netif_create_default_wifi_ap();
        }
    }
    configASSERT(s_ap_netif != NULL);

    if (esp_netif_get_handle_from_ifkey("WIFI_STA_DEF") == NULL)
    {
        esp_netif_create_default_wifi_sta();
    }

    wifi_config_t ap_config = {
        .ap = {
            .channel = CONFIG_PORTAL_AP_CHANNEL,
            .max_connection = CONFIG_PORTAL_AP_MAX_CONN,
            .authmode = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg = {.required = false},
        }};
    strncpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid) - 1);
    strncpy((char *)ap_config.ap.password, password, sizeof(ap_config.ap.password) - 1);
    ap_config.ap.ssid_len = (uint8_t)strlen(ssid);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    /* Spoof the AP MAC to avoid leaking the Espressif OUI in beacon frames.
     * identity_spoof_ap_mac() is a no-op in STANDARD builds. */
    ESP_ERROR_CHECK(identity_spoof_ap_mac());
    ESP_ERROR_CHECK(esp_wifi_start());

    /* DHCP Option 114 (RFC 8910): captive portal URI — Fix 1.
     *
     * Advertised to connecting clients during IP address assignment, before
     * the user opens any browser. The OS performs a controlled HTTP check
     * to this URL and automatically shows the portal notification. This is
     * the primary detection mechanism for Chrome and Android, which do not
     * rely on DNS interception alone.
     *
     * The stop/set/start sequence is required: DHCP server options must be
     * configured while the server is not running. esp_netif_create_default_
     * wifi_ap() starts the server automatically, so we stop it, set the
     * option, then restart.
     *
     * API: esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET,
     *                             ESP_NETIF_CAPTIVEPORTAL_URI, url, len)
     * Confirmed against ESP-IDF v6.0.1 docs. */
    const char *captive_url = "http://" SOFTAP_IP "/";
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(s_ap_netif));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET,
                                           ESP_NETIF_CAPTIVEPORTAL_URI,
                                           (void *)captive_url,
                                           (uint32_t)strlen(captive_url)));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_start(s_ap_netif));

    ESP_LOGI(TAG, "SoftAP started  SSID: %s  Auth: WPA2  DHCP opt-114: %s",
             ssid, captive_url);
}

/* --------------------------------------------------------------------------
 * JSON helpers
 * -------------------------------------------------------------------------- */
static esp_err_t send_json(httpd_req_t *req, cJSON *root, int http_status)
{
    char *body = cJSON_PrintUnformatted(root);
    httpd_resp_set_status(req, http_status == 200 ? "200 OK" : "400 Bad Request");
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, body ? body : "{}");
    free(body);
    return ret;
}

/* --------------------------------------------------------------------------
 * HTTP handlers
 * -------------------------------------------------------------------------- */

static void portal_touch_timeout(void)
{
    if (s_portal_timeout_timer != NULL)
    {
        esp_timer_restart(s_portal_timeout_timer, 300ULL * 1000000ULL);
    }
}

static size_t embedded_txt_len(const uint8_t *start, const uint8_t *end)
{
    size_t total_len = (size_t)(end - start);
    return total_len > 0 ? total_len - 1 : 0;
}

static esp_err_t send_embedded_txt_page(httpd_req_t *req,
                                        const char *status,
                                        const uint8_t *start,
                                        const uint8_t *end)
{
    size_t html_len = embedded_txt_len(start, end);
    if (html_len == 0)
    {
        ESP_LOGE(TAG, "Embedded HTML template is empty");
        httpd_resp_send_500(req);
        return ESP_FAIL;
    }

    if (status != NULL)
    {
        httpd_resp_set_status(req, status);
    }
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, (const char *)start, (ssize_t)html_len);
}

static esp_err_t send_login_page(httpd_req_t *req,
                                 const char *status,
                                 const char *message)
{
    (void)message;
    return send_embedded_txt_page(req, status,
                                  login_html_start, login_html_end);
}

static esp_err_t replace_placeholder_once(char *buf,
                                          size_t *len,
                                          const char *placeholder,
                                          const char *replacement)
{
    char *pos = strstr(buf, placeholder);
    if (pos == NULL)
    {
        ESP_LOGE(TAG, "Missing secrets page placeholder: %s", placeholder);
        return ESP_FAIL;
    }

    size_t placeholder_len = strlen(placeholder);
    size_t replacement_len = replacement ? strlen(replacement) : 0;
    size_t prefix_len = (size_t)(pos - buf);
    size_t suffix_len = *len - prefix_len - placeholder_len;
    size_t new_len = *len - placeholder_len + replacement_len;

    if (new_len >= SECRETS_PAGE_BUF_SIZE)
    {
        ESP_LOGE(TAG, "Secrets page exceeds %u bytes after replacing %s",
                 (unsigned)SECRETS_PAGE_BUF_SIZE, placeholder);
        return ESP_ERR_NO_MEM;
    }

    memmove(pos + replacement_len, pos + placeholder_len, suffix_len);
    if (replacement_len > 0)
    {
        memcpy(pos, replacement, replacement_len);
    }
    *len = new_len;
    buf[*len] = '\0';
    return ESP_OK;
}

static esp_err_t send_secrets_page(httpd_req_t *req,
                                   const char *hmac_secret,
                                   const char *totp_b32,
                                   const char *otp_uri)
{
    char *buf = s_secrets_page_buf;
    memset(buf, 0, SECRETS_PAGE_BUF_SIZE);

    size_t template_len = embedded_txt_len(secrets_html_start, secrets_html_end);
    if (template_len == 0 || template_len >= SECRETS_PAGE_BUF_SIZE)
    {
        ESP_LOGE(TAG, "Secrets page template does not fit in %u bytes",
                 (unsigned)SECRETS_PAGE_BUF_SIZE);
        return ESP_ERR_NO_MEM;
    }

    memcpy(buf, secrets_html_start, template_len);
    size_t filled_len = template_len;
    buf[filled_len] = '\0';

    esp_err_t err = replace_placeholder_once(buf, &filled_len,
                                             "{{HMAC_SECRET}}",
                                             hmac_secret ? hmac_secret : "");
    if (err != ESP_OK)
        goto cleanup;

    err = replace_placeholder_once(buf, &filled_len,
                                   "{{TOTP_B32}}",
                                   totp_b32 ? totp_b32 : "");
    if (err != ESP_OK)
        goto cleanup;

    err = replace_placeholder_once(buf, &filled_len,
                                   "{{OTP_URI}}",
                                   otp_uri ? otp_uri : "");
    if (err != ESP_OK)
        goto cleanup;

    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    err = httpd_resp_send(req, buf, (ssize_t)filled_len);

cleanup:
    memset(buf, 0, SECRETS_PAGE_BUF_SIZE);
    return err;
}

static esp_err_t require_authenticated(httpd_req_t *req)
{
    if (s_portal_authenticated)
        return ESP_OK;

    return send_login_page(req, "401 Unauthorized", "Portal password required.");
}

static bool extract_login_password(const char *body, char out[9])
{
    if (body == NULL || out == NULL)
        return false;

    const char *p = strstr(body, "password=");
    if (p == NULL)
        return false;

    p += strlen("password=");
    size_t len = 0;
    while (p[len] != '\0' && p[len] != '&' && len < PORTAL_PASSWORD_LEN)
    {
        out[len] = p[len];
        len++;
    }
    out[len] = '\0';

    return len == PORTAL_PASSWORD_LEN &&
           (p[len] == '\0' || p[len] == '&');
}

/* GET / — serve the embedded HTML form */
static esp_err_t handle_root(httpd_req_t *req)
{
    portal_touch_timeout();

    if (!s_portal_authenticated)
    {
        return send_login_page(req, NULL, NULL);
    }

    size_t html_len = (size_t)(index_html_end - index_html_start);
    httpd_resp_set_type(req, "text/html");
    return httpd_resp_send(req, index_html_start, (ssize_t)html_len);
}

/* POST /login — unlock the RAM-only portal session */
static esp_err_t handle_login(httpd_req_t *req)
{
    portal_touch_timeout();

    size_t content_len = req->content_len;
    if (content_len == 0)
    {
        return send_login_page(req, "401 Unauthorized", "Portal password required.");
    }
    if (content_len > PORTAL_LOGIN_BODY_MAX)
    {
        httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, "Login body too large");
        return ESP_FAIL;
    }

    char body[PORTAL_LOGIN_BODY_MAX + 1] = {0};
    int received = httpd_req_recv(req, body, content_len);
    if (received < 0 || (size_t)received != content_len)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Incomplete body");
        return ESP_FAIL;
    }
    body[received] = '\0';

    char submitted[PORTAL_PASSWORD_LEN + 1] = {0};
    if (!extract_login_password(body, submitted) ||
        strcmp(submitted, s_portal_password) != 0)
    {
        return send_login_page(req, "401 Unauthorized", "Incorrect portal password.");
    }

    s_portal_authenticated = true;
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "http://" SOFTAP_IP "/");
    return httpd_resp_sendstr(req, "Portal unlocked");
}

/* GET /api/scan — return JSON array of visible SSIDs */
static esp_err_t handle_scan(httpd_req_t *req)
{
    esp_err_t auth_err = require_authenticated(req);
    if (auth_err != ESP_OK)
        return auth_err;

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
#if CONFIG_OPSEC_TOTP
/* --------------------------------------------------------------------------
 * Base32 encoder (RFC 4648, uppercase alphabet, no padding)
 *
 * Converts an arbitrary byte array to a null-terminated Base32 string.
 * For a 20-byte TOTP seed the output is exactly 32 characters.
 *
 * Parameters:
 *   in      — pointer to input byte array
 *   in_len  — number of bytes to encode
 *   out     — caller-provided output buffer
 *   out_len — size of output buffer (must be >= ceil(in_len*8/5)+1)
 *
 * The output is always null-terminated. If the buffer is too small the
 * result is silently truncated (the null terminator is always written).
 * -------------------------------------------------------------------------- */
static void bytes_to_base32(const uint8_t *in, size_t in_len,
                            char *out, size_t out_len)
{
    static const char B32_ALPHA[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    if (out_len == 0) return;
    if (in_len == 0) { out[0] = '\0'; return; }

    size_t out_pos = 0;
    uint32_t bits  = 0;   /* accumulator */
    int      n     = 0;   /* bits currently loaded */

    for (size_t i = 0; i < in_len; i++) {
        bits = (bits << 8) | in[i];
        n   += 8;
        while (n >= 5) {
            n -= 5;
            if (out_pos < out_len - 1) {
                out[out_pos++] = B32_ALPHA[(bits >> n) & 0x1F];
            }
        }
    }

    /* Flush any remaining bits (pad with trailing zero-bits, no '=' chars) */
    if (n > 0 && out_pos < out_len - 1) {
        out[out_pos++] = B32_ALPHA[(bits << (5 - n)) & 0x1F];
    }

    out[out_pos] = '\0';
}
#endif

/* POST /api/provision — parse, validate, save credentials, trigger reboot */
static esp_err_t handle_provision(httpd_req_t *req)
{
    esp_err_t auth_err = require_authenticated(req);
    if (auth_err != ESP_OK)
        return auth_err;

    portal_touch_timeout();

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
    bool valid_url = false;
    if (cJSON_IsString(j) && strlen(j->valuestring) > 0 && strlen(j->valuestring) <= STORAGE_MQTT_URL_MAX) {
        valid_url = true;
        for (int i = 0; j->valuestring[i] != '\0'; i++) {
            if (isspace((unsigned char)j->valuestring[i]) || iscntrl((unsigned char)j->valuestring[i])) {
                valid_url = false;
                break;
            }
        }
    }
    if (!valid_url)
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
    if (cJSON_IsString(j)) {
        if (strlen(j->valuestring) > STORAGE_MQTT_USER_MAX) {
            cJSON_Delete(json);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "error", "MQTT username too long");
            esp_err_t r = send_json(req, err, 400);
            cJSON_Delete(err);
            return r;
        }
        strncpy(creds.mqtt_user, j->valuestring, STORAGE_MQTT_USER_MAX);
    }

    j = cJSON_GetObjectItem(json, "mqtt_pass");
    if (cJSON_IsString(j)) {
        if (strlen(j->valuestring) > STORAGE_MQTT_PASS_MAX) {
            cJSON_Delete(json);
            cJSON *err = cJSON_CreateObject();
            cJSON_AddStringToObject(err, "error", "MQTT password too long");
            esp_err_t r = send_json(req, err, 400);
            cJSON_Delete(err);
            return r;
        }
        strncpy(creds.mqtt_pass, j->valuestring, STORAGE_MQTT_PASS_MAX);
    }

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

    const char *hmac_secret_value = "";
    const char *totp_b32_value = "";
    const char *otp_uri_value = "";

#if CONFIG_OPSEC_HMAC_TOPIC || CONFIG_OPSEC_TOTP
    uint8_t hmac_secret[STORAGE_HMAC_SECRET_LEN];
    esp_err_t secret_err = storage_load_or_generate_hmac_secret(hmac_secret);
    if (secret_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load HMAC secret: %s", esp_err_to_name(secret_err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Failed to load security credentials");
        return ESP_FAIL;
    }
    char hmac_hex[STORAGE_HMAC_SECRET_LEN * 2 + 1];
    for (int i = 0; i < STORAGE_HMAC_SECRET_LEN; i++)
        snprintf(hmac_hex + i * 2, 3, "%02X", hmac_secret[i]);
    hmac_secret_value = hmac_hex;
#endif

#if CONFIG_OPSEC_TOTP
    uint8_t totp_seed[STORAGE_TOTP_SEED_LEN];
    esp_err_t totp_err = storage_load_or_generate_totp_seed(totp_seed);
    if (totp_err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load TOTP seed: %s", esp_err_to_name(totp_err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Failed to load security credentials");
        return ESP_FAIL;
    }
    /* Base32 for authenticator apps: 20 bytes → 32 chars + null */
    char totp_b32[33];
    bytes_to_base32(totp_seed, STORAGE_TOTP_SEED_LEN, totp_b32, sizeof(totp_b32));
    /* otpauth URI for QR / direct import */
    char otp_uri[128];
    snprintf(otp_uri, sizeof(otp_uri),
             "otpauth://totp/WoL-Relay?secret=%s&issuer=WoL-Relay", totp_b32);
    totp_b32_value = totp_b32;
    otp_uri_value = otp_uri;
#endif

    return send_secrets_page(req, hmac_secret_value, totp_b32_value, otp_uri_value);
}

/* --------------------------------------------------------------------------
 * GET /provisioned — acknowledgment page shown after secrets are read.
 * Contains the single "Start Relay" button that POSTs to /reboot.
 * -------------------------------------------------------------------------- */
static esp_err_t provisioned_get_handler(httpd_req_t *req)
{
    esp_err_t auth_err = require_authenticated(req);
    if (auth_err != ESP_OK)
        return auth_err;

    portal_touch_timeout();

    httpd_resp_set_type(req, "text/html");
    return httpd_resp_sendstr(req,
        "<!DOCTYPE html><html><head>"
        "<meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>WoL Relay — Ready</title>"
        "<style>"
        "body{font-family:ui-sans-serif,system-ui,sans-serif;background:#050505;color:#e5e2e1;"
              "margin:0;padding:32px 16px;text-align:center;max-width:480px;margin-left:auto;margin-right:auto;}"
        "h1{font-family:ui-serif,Georgia,serif;font-size:2rem;font-weight:600;margin-bottom:8px;}"
        "p{color:#d0c5af;line-height:1.6;margin-bottom:24px;}"
        ".btn{display:inline-block;width:100%;padding:16px;margin-top:16px;box-sizing:border-box;"
              "background:transparent;border:1px solid #d4af37;border-radius:9999px;"
              "color:#d4af37;font-size:1rem;cursor:pointer;text-transform:uppercase;"
              "letter-spacing:.1em;font-weight:500;transition:all 0.2s;}"
        ".btn:hover{background:#d4af37;color:#050505;}"
        "</style></head><body>"
        "<h1>&#x2728; Provisioning Complete</h1>"
        "<p>Your WiFi, MQTT, and security credentials have been saved to flash.<br><br>"
        "Press the button below when you have recorded all secrets from the previous page.</p>"
        "<form method=\"POST\" action=\"/reboot\">"
        "<button class=\"btn\" type=\"submit\">"
        "I have saved my credentials &mdash; Start Relay</button>"
        "</form>"
        "</body></html>");
}

/* --------------------------------------------------------------------------
 * POST /reboot — explicit user confirmation triggers the actual reboot.
 * Sets the event bit that unblocks portal_start(), then responds before
 * the chip resets so the browser gets a final confirmation message.
 * -------------------------------------------------------------------------- */
static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    esp_err_t auth_err = require_authenticated(req);
    if (auth_err != ESP_OK)
        return auth_err;

    esp_err_t ret = send_embedded_txt_page(req, NULL,
                                           rebooting_html_start,
                                           rebooting_html_end);
    /* Signal portal_start() — the event group unblocks and triggers restart */
    xEventGroupSetBits(s_portal_events, PORTAL_CRED_SAVED_BIT);
    return ret;
}

/* OS captive-portal detection: redirect everything else to the portal root.
 *
 * 303 See Other (not 302): ensures POST requests are also redirected to GET.
 *
 * Body is required — iOS ignores a body-less redirect when performing
 * captive portal detection; it expects actual content in the response to
 * confirm that a portal is present. "Redirect to captive portal" satisfies
 * this requirement without triggering any additional OS-side logic. */
static esp_err_t handle_captive_redirect(httpd_req_t *req)
{
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "http://" SOFTAP_IP "/");
    return httpd_resp_sendstr(req, "Redirect to captive portal");
}

/* 404 error handler — registered via httpd_register_err_handler().
 *
 * Distinct from the wildcard URI catch-all above. The httpd framework
 * raises a 404 error before URI matching in some edge cases (malformed
 * request line, method not allowed on an unregistered path, etc.). This
 * handler catches those and redirects them identically to handle_captive_
 * redirect, ensuring no request ever returns a bare 404 page.
 *
 * iOS requires a non-empty body on a captive portal redirect response;
 * a bare 303 without body content is silently ignored by the OS. */
static esp_err_t http_404_error_handler(httpd_req_t *req,
                                        httpd_err_code_t error)
{
    (void)error;
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "http://" SOFTAP_IP "/");
    return httpd_resp_sendstr(req, "Redirect to captive portal");
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
        {.uri = "/login", .method = HTTP_POST, .handler = handle_login},
        {.uri = "/api/scan", .method = HTTP_GET, .handler = handle_scan},
        {.uri = "/api/provision", .method = HTTP_POST, .handler = handle_provision},
        /* OS detection stubs */
        {.uri = "/generate_204", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/hotspot-detect.html", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/ncsi.txt", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/connecttest.txt", .method = HTTP_GET, .handler = handle_captive_redirect},
        {.uri = "/redirect", .method = HTTP_GET, .handler = handle_captive_redirect},
        /* Acknowledgment and explicit reboot trigger */
        {.uri = "/provisioned", .method = HTTP_GET,  .handler = provisioned_get_handler},
        {.uri = "/reboot",      .method = HTTP_POST, .handler = reboot_post_handler},
        /* Wildcard catch-all — must be last */
        {.uri = "/*", .method = HTTP_ANY, .handler = handle_captive_redirect},
    };

    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++)
    {
        httpd_register_uri_handler(server, &uris[i]);
    }

    /* Secondary catch-all: handles 404s raised by the framework before
     * URI matching (e.g. unrecognized method on unregistered path).
     * The wildcard URI above handles the common case; this covers the rest. */
    httpd_register_err_handler(server, HTTPD_404_NOT_FOUND,
                               http_404_error_handler);

    ESP_LOGI(TAG, "HTTP server ready on port %d", CONFIG_PORTAL_HTTP_PORT);
    return server;
}

/* --------------------------------------------------------------------------
 * portal_start — public entry point (never returns)
 * -------------------------------------------------------------------------- */
void portal_start(void)
{
    char ssid[33] = {0};
    derive_ap_ssid(ssid);

    s_portal_authenticated = false;
    memset(s_portal_password, 0, sizeof(s_portal_password));
    esp_err_t pass_err = portal_derive_password(s_portal_password);
    if (pass_err != ESP_OK || s_portal_password[0] == '\0')
    {
        ESP_LOGE(TAG, "Portal password derivation failed (%s) — rebooting",
                 esp_err_to_name(pass_err));
        esp_restart();
    }

    ESP_LOGI(TAG, "Portal AP  SSID: %s", ssid);
    ESP_LOGI(TAG, "Portal AP  Auth: WPA2");

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

    start_softap(ssid, s_portal_password);

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
