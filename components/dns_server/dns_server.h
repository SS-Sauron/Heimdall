/*
 * dns_server.h
 *
 * Minimal UDP DNS server that responds to ALL A-record queries with a
 * single configurable IP address. Used by the captive portal component
 * to redirect every DNS lookup to the ESP32's SoftAP IP (192.168.4.1),
 * triggering the OS captive portal detector on iOS, Android, and Windows.
 *
 * Ported from the ESP-IDF captive portal example:
 *   $IDF_PATH/examples/protocols/http_server/captive_portal/
 *
 * If that example is available on your machine, copy dns_server.c from
 * there instead of using this stub. The API is identical.
 */

#pragma once

#include "esp_err.h"
#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Start the DNS redirect server on UDP port 53.
 *
 * Spawns a FreeRTOS task that listens for DNS queries and responds to
 * all A-record requests with @p redirect_addr. AAAA (IPv6) queries are
 * answered with NXDOMAIN.
 *
 * @param redirect_addr  IPv4 address to return for every A-record query.
 *                       Typically the SoftAP interface IP (192.168.4.1).
 * @return ESP_OK on success, or an error code.
 */
esp_err_t dns_server_start(esp_ip4_addr_t redirect_addr);

/**
 * @brief Stop the DNS redirect server and free its resources.
 */
void dns_server_stop(void);

#ifdef __cplusplus
}
#endif
