/*
 * wol.c
 *
 * Builds and broadcasts the Wake-on-LAN Magic Packet.
 *
 * Standard packet structure (102 bytes):
 *   Bytes  0– 5:  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF   (sync stream)
 *   Bytes  6–101: target MAC repeated 16 times     (16 × 6 = 96 bytes)
 *
 * SecureOn extension (optional, +6 bytes = 108 bytes total):
 *   If a SecureOn password is stored in NVS (key "so"), it is parsed
 *   from "AA:BB:CC:DD:EE:FF" format and appended directly after the
 *   102-byte payload before transmission. The target NIC will only
 *   honour the packet if this 6-byte password matches its stored value.
 *   If no password is configured, the standard 102-byte packet is sent.
 */

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "wol.h"
#include "sdkconfig.h"
#include "esp_netif.h"
#if CONFIG_WOL_PING_FEEDBACK
#include "ping/ping_sock.h"
#include "esp_timer.h"
#include "mqtt_client.h"
#include "opsec.h"
#endif /* CONFIG_WOL_PING_FEEDBACK */
#include "storage.h"

static const char *TAG = "wol";

#define MAGIC_PACKET_LEN 102
#define SEND_REPETITIONS 3 /* send the packet N times for reliability */
#define SEND_GAP_MS 10     /* ms between repetitions */

/* --------------------------------------------------------------------------
 * Internal: build the 102-byte packet into caller-supplied buffer
 * -------------------------------------------------------------------------- */
static void build_magic_packet(uint8_t pkt[MAGIC_PACKET_LEN], const uint8_t mac[6])
{
    /* Sync stream: 6 bytes of 0xFF */
    memset(pkt, 0xFF, 6);

    /* MAC address repeated 16 times */
    for (int i = 0; i < 16; i++)
    {
        memcpy(pkt + 6 + i * 6, mac, 6);
    }
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */
esp_err_t wol_parse_mac(const char *mac_str, uint8_t mac_out[6])
{
    if (!mac_str || !mac_out)
        return ESP_ERR_INVALID_ARG;

    unsigned int bytes[6] = {0};
    int parsed = sscanf(mac_str, "%x:%x:%x:%x:%x:%x",
                        &bytes[0], &bytes[1], &bytes[2],
                        &bytes[3], &bytes[4], &bytes[5]);

    if (parsed != 6)
    {
        ESP_LOGE(TAG, "Invalid MAC string: \"%s\"", mac_str);
        return ESP_ERR_INVALID_ARG;
    }

    for (int i = 0; i < 6; i++)
    {
        if (bytes[i] > 0xFF)
            return ESP_ERR_INVALID_ARG;
        mac_out[i] = (uint8_t)bytes[i];
    }
    return ESP_OK;
}

esp_err_t wol_send_raw(const uint8_t mac[6])
{
    if (!mac)
        return ESP_ERR_INVALID_ARG;

    /* Build the packet */
    uint8_t pkt[MAGIC_PACKET_LEN + 6];
    build_magic_packet(pkt, mac);
    int pkt_len = MAGIC_PACKET_LEN;

    storage_credentials_t creds = {0};
    if (storage_load_credentials(&creds) == ESP_OK && strlen(creds.secureon_pwd) > 0) {
        uint8_t sec_mac[6];
        if (wol_parse_mac(creds.secureon_pwd, sec_mac) == ESP_OK) {
            memcpy(pkt + MAGIC_PACKET_LEN, sec_mac, 6);
            pkt_len += 6;
            ESP_LOGI(TAG, "Appending 6-byte SecureOn password to Magic Packet");
        } else {
            ESP_LOGW(TAG, "Invalid SecureOn password format in NVS; sending standard 102-byte packet");
        }
    }

    /* Resolve broadcast address from STA netif IP and netmask */
    esp_netif_t *sta_netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (sta_netif == NULL)
    {
        ESP_LOGE(TAG, "STA netif not found — is WiFi connected?");
        return ESP_FAIL;
    }

    esp_netif_ip_info_t ip_info;
    if (esp_netif_get_ip_info(sta_netif, &ip_info) != ESP_OK || ip_info.ip.addr == 0)
    {
        ESP_LOGE(TAG, "No valid IP on STA interface — WiFi not connected");
        return ESP_FAIL;
    }

    /* broadcast = ip | ~netmask  (values are in network byte order, no swap needed) */
    uint32_t bcast = ip_info.ip.addr | ~ip_info.netmask.addr;

    struct sockaddr_in dest = {
        .sin_family = AF_INET,
        .sin_port = htons(CONFIG_WOL_BROADCAST_PORT),
        .sin_addr.s_addr = bcast,
    };

    /* Open UDP socket */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "socket() failed: errno %d", errno);
        return ESP_FAIL;
    }

    /* Enable broadcast permission on the socket */
    int bcast_opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast_opt, sizeof(bcast_opt)) < 0)
    {
        ESP_LOGE(TAG, "setsockopt SO_BROADCAST failed: errno %d", errno);
        close(sock);
        return ESP_FAIL;
    }

    /* Send SEND_REPETITIONS times for robustness */
    esp_err_t ret = ESP_OK;
    for (int i = 0; i < SEND_REPETITIONS; i++)
    {
        ssize_t sent = sendto(sock, pkt, pkt_len, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent != pkt_len)
        {
            ESP_LOGW(TAG, "sendto incomplete: sent=%d errno=%d", (int)sent, errno);
            ret = ESP_FAIL;
        }
        if (i < SEND_REPETITIONS - 1)
        {
            vTaskDelay(pdMS_TO_TICKS(SEND_GAP_MS));
        }
    }

    close(sock);

    if (ret == ESP_OK)
    {
        ESP_LOGI(TAG, "Magic Packet sent → %02X:%02X:%02X:%02X:%02X:%02X  bcast=" IPSTR " port=%d (%dx)",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 IP2STR((esp_ip4_addr_t *)&bcast), CONFIG_WOL_BROADCAST_PORT,
                 SEND_REPETITIONS);
    }
    return ret;
}

esp_err_t wol_send(const char *mac_str)
{
    uint8_t mac[6];
    esp_err_t err = wol_parse_mac(mac_str, mac);
    if (err != ESP_OK)
        return err;
    return wol_send_raw(mac);
}

/* ==========================================================================
 * Optional ping feedback
 * ==========================================================================
 * Compiles only when CONFIG_WOL_PING_FEEDBACK=y.
 *
 * Lifetime rules:
 *   - esp_ping_new_session / esp_ping_start are called from the MQTT task
 *     via wol_ping_start().
 *   - on_ping_success / on_ping_end run on the ping's own internal task.
 *     They may call esp_ping_stop() but MUST NOT call
 *     esp_ping_delete_session() (that would delete the running task itself).
 *   - wol_ping_cleanup() is called from the health monitor loop in
 *     mqtt_relay.c and is the only place that calls esp_ping_delete_session.
 * ========================================================================== */
#if CONFIG_WOL_PING_FEEDBACK

/* --------------------------------------------------------------------------
 * Private session context
 * -------------------------------------------------------------------------- */
typedef struct {
    esp_mqtt_client_handle_t mqtt_client;
    char                     rsp_topic[OPSEC_TOPIC_MAX_LEN];
    uint8_t                  mac[6];
    int64_t                  start_us; /* esp_timer_get_time() when WoL sent */
} ping_ctx_t;

static esp_ping_handle_t  s_ping_session      = NULL;
static volatile bool      s_ping_active        = false;
static volatile bool      s_ping_needs_cleanup = false;
static ping_ctx_t         s_ping_ctx           = {0};
static bool               s_machine_woke       = false;

/* --------------------------------------------------------------------------
 * Callbacks — run on the ping's internal FreeRTOS task
 * -------------------------------------------------------------------------- */

static void on_ping_success(esp_ping_handle_t hdl, void *args)
{
    ping_ctx_t *ctx = (ping_ctx_t *)args;

    s_machine_woke = true;

    /* boot_time_s = wall-clock time elapsed since the WoL packet was sent */
    uint32_t boot_time_s = (uint32_t)(
        (esp_timer_get_time() - ctx->start_us) / 1000000LL);

    char payload[96];
    snprintf(payload, sizeof(payload),
             "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
             "\"status\":\"awake\","
             "\"boot_time_s\":%" PRIu32 "}",
             ctx->mac[0], ctx->mac[1], ctx->mac[2],
             ctx->mac[3], ctx->mac[4], ctx->mac[5],
             boot_time_s);

    if (ctx->mqtt_client)
    {
        int msg_id = esp_mqtt_client_publish(
            ctx->mqtt_client,
            ctx->rsp_topic,
            payload,
            0,  /* len=0 → strlen */
            1,  /* QoS 1 */
            0   /* retain=false */
        );
        if (msg_id < 0)
        {
            ESP_LOGW(TAG, "ping: awake publish failed");
        }
        else
        {
            ESP_LOGI(TAG, "ping: awake → %s", payload);
        }
    }

    /* Stop the session early — safe to call from callback */
    esp_ping_stop(hdl);
    s_ping_active        = false;
    s_ping_needs_cleanup = true;
}

static void on_ping_timeout(esp_ping_handle_t hdl, void *args)
{
    /* Individual packet timeouts are normal while the machine is booting.
     * The session continues until count is exhausted — no action needed. */
    (void)hdl;
    (void)args;
}

static void on_ping_end(esp_ping_handle_t hdl, void *args)
{
    ping_ctx_t *ctx = (ping_ctx_t *)args;

    if (!s_machine_woke)
    {
        /* Session exhausted without a reply — publish timeout */
        char payload[72];
        snprintf(payload, sizeof(payload),
                 "{\"mac\":\"%02X:%02X:%02X:%02X:%02X:%02X\","
                 "\"status\":\"timeout\"}",
                 ctx->mac[0], ctx->mac[1], ctx->mac[2],
                 ctx->mac[3], ctx->mac[4], ctx->mac[5]);

        if (ctx->mqtt_client)
        {
            int msg_id = esp_mqtt_client_publish(
                ctx->mqtt_client,
                ctx->rsp_topic,
                payload,
                0, 1, 0);
            if (msg_id < 0)
            {
                ESP_LOGW(TAG, "ping: timeout publish failed");
            }
            else
            {
                ESP_LOGI(TAG, "ping: timeout → %s", payload);
            }
        }
    }

    /* Do NOT call esp_ping_delete_session() here — we are running on the
     * ping's own internal task; deleting it from within would delete the
     * current task. Defer to wol_ping_cleanup(). */
    s_ping_active        = false;
    s_ping_needs_cleanup = true;
    (void)hdl;
}

/* --------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------- */

esp_err_t wol_ping_start(const char *target_ip,
                          const uint8_t mac[6],
                          esp_mqtt_client_handle_t mqtt_client,
                          const char *rsp_topic,
                          int64_t wol_send_time)
{
    if (!target_ip || !mac || !mqtt_client || !rsp_topic)
        return ESP_ERR_INVALID_ARG;

    if (s_ping_active)
    {
        ESP_LOGW(TAG, "wol_ping_start: session already active — ignoring");
        return ESP_ERR_INVALID_STATE;
    }

    /* ------------------------------------------------------------------
     * Convert dotted-decimal IP string → ip_addr_t
     * Official ESP-IDF pattern (icmp_echo example + esp-csi):
     * ------------------------------------------------------------------ */
    ip_addr_t target_addr;
    memset(&target_addr, 0, sizeof(target_addr));

    struct addrinfo hint;
    struct addrinfo *res = NULL;
    memset(&hint, 0, sizeof(hint));

    if (getaddrinfo(target_ip, NULL, &hint, &res) != 0 || res == NULL)
    {
        ESP_LOGE(TAG, "wol_ping_start: could not resolve IP: %s", target_ip);
        if (res) freeaddrinfo(res);
        return ESP_FAIL;
    }

    struct in_addr addr4 = ((struct sockaddr_in *)(res->ai_addr))->sin_addr;
    inet_addr_to_ip4addr(ip_2_ip4(&target_addr), &addr4);
    target_addr.type = IPADDR_TYPE_V4;
    freeaddrinfo(res);

    /* ------------------------------------------------------------------
     * Store session context
     * ------------------------------------------------------------------ */
    s_ping_ctx.mqtt_client = mqtt_client;
    strncpy(s_ping_ctx.rsp_topic, rsp_topic, OPSEC_TOPIC_MAX_LEN - 1);
    s_ping_ctx.rsp_topic[OPSEC_TOPIC_MAX_LEN - 1] = '\0';
    memcpy(s_ping_ctx.mac, mac, 6);
    s_ping_ctx.start_us = wol_send_time;
    s_machine_woke      = false;

    /* ------------------------------------------------------------------
     * Build ping config
     *
     * Total session duration ≈ count × interval_ms
     * (timeout_ms is per-packet, not a session total)
     * ------------------------------------------------------------------ */
    esp_ping_config_t cfg = ESP_PING_DEFAULT_CONFIG();
    cfg.target_addr     = target_addr;
    cfg.count           = (uint32_t)((CONFIG_WOL_PING_TIMEOUT_SEC * 1000)
                                     / CONFIG_WOL_PING_INTERVAL_MS);
    cfg.interval_ms     = (uint32_t)CONFIG_WOL_PING_INTERVAL_MS;
    cfg.timeout_ms      = 1000; /* 1 s per-packet timeout */
    cfg.task_stack_size = 4096;

    esp_ping_callbacks_t cbs = {
        .cb_args         = &s_ping_ctx,
        .on_ping_success = on_ping_success,
        .on_ping_timeout = on_ping_timeout,
        .on_ping_end     = on_ping_end,
    };

    esp_err_t err = esp_ping_new_session(&cfg, &cbs, &s_ping_session);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ping_new_session failed: %s", esp_err_to_name(err));
        return err;
    }

    s_ping_active        = true;
    s_ping_needs_cleanup = false;

    err = esp_ping_start(s_ping_session);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ping_start failed: %s", esp_err_to_name(err));
        /* Clean up immediately — we're not in a callback so it's safe */
        esp_ping_delete_session(s_ping_session);
        s_ping_session = NULL;
        s_ping_active  = false;
        return err;
    }

    ESP_LOGI(TAG, "Ping session started → %s (count=%" PRIu32 " interval=%" PRIu32 "ms)",
             target_ip, cfg.count, cfg.interval_ms);
    return ESP_OK;
}

void wol_ping_cleanup(void)
{
    if (!s_ping_needs_cleanup || s_ping_session == NULL)
        return;

    ESP_LOGD(TAG, "wol_ping_cleanup: deleting completed session");
    esp_ping_delete_session(s_ping_session);
    s_ping_session       = NULL;
    s_ping_needs_cleanup = false;
}

#endif /* CONFIG_WOL_PING_FEEDBACK */
