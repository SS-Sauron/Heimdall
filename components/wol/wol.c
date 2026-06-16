/*
 * wol.c
 *
 * Builds and broadcasts the 102-byte Wake-on-LAN Magic Packet.
 *
 * Packet structure (RFC-like):
 *   Bytes  0– 5:  0xFF 0xFF 0xFF 0xFF 0xFF 0xFF   (sync stream)
 *   Bytes  6–101: target MAC repeated 16 times     (16 × 6 = 96 bytes)
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
    uint8_t pkt[MAGIC_PACKET_LEN];
    build_magic_packet(pkt, mac);

    /* Resolve broadcast address */
    // REPLACE WITH:
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
        ssize_t sent = sendto(sock, pkt, MAGIC_PACKET_LEN, 0,
                              (struct sockaddr *)&dest, sizeof(dest));
        if (sent != MAGIC_PACKET_LEN)
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
        ESP_LOGI(TAG, "Magic Packet sent → %02X:%02X:%02X:%02X:%02X:%02X  via %s:%d (%dx)",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                 CONFIG_WOL_BROADCAST_ADDR, CONFIG_WOL_BROADCAST_PORT,
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
