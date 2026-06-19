/*
 * dns_server.c
 *
 * Minimal UDP DNS redirect server for captive portal use.
 *
 * Responds to every DNS A-record query with a single IPv4 address
 * (the SoftAP interface IP, 192.168.4.1 by default) so that Android,
 * Windows, and iOS captive-portal detectors receive a response and
 * automatically open the configuration page.
 *
 * Implementation closely follows the official ESP-IDF captive portal
 * example at:
 *   $IDF_PATH/examples/protocols/http_server/captive_portal/
 *                     components/dns_server/dns_server.c
 *
 * Key design points confirmed from the MCP / official sources:
 *   - OPCODE_MASK and QR_FLAG are applied to the flags field WITHOUT
 *     htons() — the official example intentionally treats the field
 *     in wire (memory) byte order, and this is what makes it work.
 *   - SO_RCVTIMEO (1 s) lets the task notice s_running == false and
 *     exit cleanly rather than blocking forever on recvfrom().
 *   - The socket is recreated on bind/recv errors so a transient
 *     failure does not permanently kill the server.
 *   - AAAA and other non-A queries receive a header-only response
 *     with an_count = 0 (NOERROR, no answers) — sufficient for
 *     captive portal detection to succeed on all tested OS versions.
 *
 * HTTPS interception limitation
 * ─────────────────────────────
 * This DNS server CANNOT intercept HTTPS requests. When a user types a
 * URL that the browser already knows uses HTTPS (e.g. "www.google.com",
 * any domain on the HSTS preload list, or any URL typed with "https://")
 * the browser connects directly to port 443. The ESP32 HTTP server on
 * port 80 never sees the request and DNS redirection has no effect because
 * the TLS certificate check fails before any HTTP exchange occurs.
 *
 * DHCP Option 114 (RFC 8910) is the correct primary solution: it sends
 * the captive portal URL to the connecting device during IP address
 * assignment, before the user opens any browser. The OS then performs
 * a controlled HTTP check to a known non-HTTPS URL and automatically
 * shows the portal notification pop-up. DNS redirection (this file)
 * and DHCP Option 114 (portal.c:start_softap) are complementary —
 * both should be active for maximum OS compatibility.
 */

#include <string.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "dns_server.h"

static const char *TAG = "dns_server";

/* ── Protocol constants ──────────────────────────────────────────────────── */
#define DNS_PORT        53
#define DNS_MAX_LEN     256      /* max UDP payload we handle */
#define ANS_TTL_SEC     300      /* 5-minute TTL — short enough not to cache
                                    the redirect after provisioning is done  */

/*
 * Flags-field bitmasks — applied WITHOUT htons() intentionally.
 * The packet is kept in wire byte order in the buffer; these masks
 * address the correct bits in memory on a little-endian (ESP32) host.
 * This matches the official ESP-IDF captive portal example exactly.
 */
#define OPCODE_MASK     0x7800   /* bits 14:11 of the flags field on the wire */
#define QR_FLAG         (1 << 7) /* bit 7 of the first flags byte  = response */

#define QD_TYPE_A       0x0001   /* DNS A record (IPv4 address)               */

/* ── Packed DNS wire-format structures ───────────────────────────────────── */

typedef struct __attribute__((__packed__)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qd_count;
    uint16_t an_count;
    uint16_t ns_count;
    uint16_t ar_count;
} dns_header_t;

typedef struct {
    uint16_t type;
    uint16_t class;
} dns_question_t;

typedef struct __attribute__((__packed__)) {
    uint16_t ptr_offset;  /* compression pointer back to the question name */
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t addr_len;
    uint32_t ip_addr;     /* network byte order — stored directly from esp_ip4_addr_t */
} dns_answer_t;

/* ── Module state ────────────────────────────────────────────────────────── */
static TaskHandle_t    s_dns_task    = NULL;
static volatile bool   s_running     = false;
static esp_ip4_addr_t  s_redirect_ip = { .addr = 0 };

/* ── DNS name parser ─────────────────────────────────────────────────────── */

/*
 * parse_dns_name
 *
 * Converts a DNS wire-format name (length-prefixed labels) into a
 * human-readable dot-separated string.
 *
 * Returns a pointer to the first byte AFTER the name in the packet
 * (i.e., the start of the dns_question_t that follows), or NULL if
 * the name exceeds parsed_name_max_len.
 *
 * Example:
 *   wire: \x06google\x03com\x00
 *   out:  "google.com"
 */
static char *parse_dns_name(char *raw_name, char *parsed_name,
                             size_t parsed_name_max_len)
{
    char *label    = raw_name;
    char *out      = parsed_name;
    int   name_len = 0;

    do {
        int label_len = (uint8_t)*label;
        name_len += label_len + 1;   /* +1 for the '.' we append */
        if (name_len > (int)parsed_name_max_len) {
            return NULL;
        }
        memcpy(out, label + 1, label_len);
        out[label_len] = '.';
        out   += label_len + 1;
        label += label_len + 1;
    } while (*label != 0);

    /* Replace the trailing '.' with a null terminator */
    parsed_name[name_len - 1] = '\0';

    /* Return pointer to the byte after the terminating zero (= dns_question_t) */
    return label + 1;
}

/* ── DNS reply builder ───────────────────────────────────────────────────── */

/*
 * build_dns_reply
 *
 * Takes an incoming DNS query packet and builds a response in-place.
 * For every A-record question it appends an answer record pointing to
 * s_redirect_ip. Non-A questions receive a header-only response with
 * an_count = 0 (NOERROR, no answers).
 *
 * Returns the total byte length of the reply to send, or -1 on error.
 * Returns 0 for non-standard queries (non-zero OPCODE) — caller skips.
 */
static int build_dns_reply(char *req, size_t req_len,
                           char *reply, size_t reply_max_len)
{
    if (req_len > reply_max_len) {
        ESP_LOGE(TAG, "Query (%zu B) exceeds reply buffer (%zu B)", req_len, reply_max_len);
        return -1;
    }

    /* Start reply as a copy of the request, then modify in place */
    memset(reply, 0, reply_max_len);
    memcpy(reply, req, req_len);

    dns_header_t *hdr = (dns_header_t *)reply;

    ESP_LOGD(TAG, "DNS id=0x%04X flags=0x%04X qd=%u",
             ntohs(hdr->id), ntohs(hdr->flags), ntohs(hdr->qd_count));

    /*
     * Ignore non-standard queries (OPCODE != 0).
     * NOTE: OPCODE_MASK is applied WITHOUT htons() — see module header.
     */
    if ((hdr->flags & OPCODE_MASK) != 0) {
        return 0;
    }

    /* Mark as a response — QR_FLAG applied WITHOUT htons(), same reason */
    hdr->flags |= QR_FLAG;

    uint16_t qd_count = ntohs(hdr->qd_count);

    /* Pre-calculate the full reply length and bounds-check BEFORE writing */
    size_t reply_len = req_len + (size_t)qd_count * sizeof(dns_answer_t);
    if (reply_len > reply_max_len) {
        ESP_LOGE(TAG, "Reply would be %zu B, buffer only %zu B", reply_len, reply_max_len);
        return -1;
    }

    /* Walk questions and build answer records */
    char *ans_ptr = reply + req_len;                  /* answers appended here   */
    char *qd_ptr  = reply + sizeof(dns_header_t);     /* first question          */
    char  name[128];
    uint16_t a_record_answers = 0;

    for (uint16_t qi = 0; qi < qd_count; qi++) {
        char *name_end = parse_dns_name(qd_ptr, name, sizeof(name));
        if (name_end == NULL) {
            ESP_LOGE(TAG, "Failed to parse question name at qi=%u", qi);
            return -1;
        }

        dns_question_t *question = (dns_question_t *)name_end;
        uint16_t qtype  = ntohs(question->type);
        uint16_t qclass = ntohs(question->class);

        ESP_LOGD(TAG, "  Q[%u] type=%u class=%u name=%s", qi, qtype, qclass, name);

        if (qtype == QD_TYPE_A) {
            dns_answer_t *ans = (dns_answer_t *)ans_ptr;

            /*
             * Compression pointer: 0xC000 | byte-offset of the name
             * field within the reply buffer. This avoids repeating the
             * full name string in the answer section.
             */
            ans->ptr_offset = htons(0xC000 | (uint16_t)(qd_ptr - reply));
            ans->type       = htons(qtype);
            ans->class      = htons(qclass);
            ans->ttl        = htonl(ANS_TTL_SEC);
            ans->addr_len   = htons(sizeof(s_redirect_ip.addr));
            ans->ip_addr    = s_redirect_ip.addr;  /* already network byte order */

            ans_ptr += sizeof(dns_answer_t);
            a_record_answers++;
        }

        /* Advance qd_ptr past this question's name + type + class fields */
        qd_ptr = (char *)question + sizeof(dns_question_t);
    }

    hdr->an_count = htons(a_record_answers);

    /*
     * Return the number of bytes actually written, not the pre-allocated
     * maximum (which assumed every question was an A-record). For pure
     * A-record queries these are identical. For mixed queries containing
     * AAAA or other types, this trims the trailing zero bytes that would
     * otherwise be sent past the last real answer record.
     *
     * The up-front bounds check used `qd_count * sizeof(dns_answer_t)`
     * which is conservative — it ensured the buffer can hold the maximum
     * possible reply. The return value here is the precise actual length.
     */
    return (int)(req_len + (size_t)a_record_answers * sizeof(dns_answer_t));
}

/* ── DNS server task ─────────────────────────────────────────────────────── */

static void dns_server_task(void *pvParameters)
{
    char rx[DNS_MAX_LEN];
    char tx[DNS_MAX_LEN];

    while (s_running) {

        /* ── Create and bind socket ───────────────────────────────────── */
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock < 0) {
            ESP_LOGE(TAG, "socket() failed: errno %d — retry in 1 s", errno);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        /*
         * SO_REUSEADDR: allows bind() to succeed immediately if this socket
         * is restarted before the OS has fully released the previous port.
         * In practice the portal always ends with esp_restart() so the full
         * network stack is torn down anyway — but this is a cheap defensive
         * addition that eliminates any risk of EADDRINUSE on rapid restarts.
         */
        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        /*
         * 1-second receive timeout.
         * Allows the task to wake up, check s_running, and exit cleanly
         * after dns_server_stop() sets s_running = false.
         */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in bind_addr = {
            .sin_family      = AF_INET,
            .sin_port        = htons(DNS_PORT),
            .sin_addr.s_addr = htonl(INADDR_ANY),
        };

        if (bind(sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
            ESP_LOGE(TAG, "bind() port %d failed: errno %d — retry in 1 s",
                     DNS_PORT, errno);
            close(sock);
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        ESP_LOGI(TAG, "Listening on UDP port %d — redirect → " IPSTR,
                 DNS_PORT, IP2STR(&s_redirect_ip));

        /* ── Receive / reply loop ────────────────────────────────────── */
        while (s_running) {

            /*
             * Use sockaddr_in6 for the source address: it is large enough
             * to hold both IPv4 and IPv6 addresses, matching the official
             * Espressif captive portal example.
             */
            struct sockaddr_in6 src;
            socklen_t           src_len = sizeof(src);

            int len = recvfrom(sock, rx, sizeof(rx) - 1, 0,
                               (struct sockaddr *)&src, &src_len);

            if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* Normal 1-second timeout — loop back and check s_running */
                    continue;
                }
                ESP_LOGE(TAG, "recvfrom() errno %d — reopening socket", errno);
                break;   /* break inner → outer loop recreates the socket */
            }

            if (len < (int)sizeof(dns_header_t)) {
                ESP_LOGW(TAG, "Packet too short (%d B) — ignored", len);
                continue;
            }

            int tx_len = build_dns_reply(rx, (size_t)len, tx, sizeof(tx));

            if (tx_len < 0) {
                ESP_LOGE(TAG, "build_dns_reply() error — query dropped");
                continue;
            }
            if (tx_len == 0) {
                /* Non-standard opcode — silently ignore */
                continue;
            }

            if (sendto(sock, tx, tx_len, 0,
                       (struct sockaddr *)&src, src_len) < 0) {
                ESP_LOGE(TAG, "sendto() errno %d", errno);
            } else {
                ESP_LOGD(TAG, "Replied %d B to DNS query", tx_len);
            }
        }

        /* ── Clean up socket before outer loop re-checks s_running ──── */
        shutdown(sock, SHUT_RDWR);
        close(sock);
    }

    ESP_LOGI(TAG, "DNS server task exiting");
    s_dns_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

esp_err_t dns_server_start(esp_ip4_addr_t redirect_addr)
{
    if (s_dns_task != NULL) {
        ESP_LOGW(TAG, "Already running — call dns_server_stop() first");
        return ESP_ERR_INVALID_STATE;
    }
    if (redirect_addr.addr == 0) {
        ESP_LOGE(TAG, "redirect_addr is INADDR_ANY — refusing to start");
        return ESP_ERR_INVALID_ARG;
    }

    s_redirect_ip = redirect_addr;
    s_running     = true;

    BaseType_t ret = xTaskCreate(
        dns_server_task,
        "dns_srv",
        4096,         /* 4 KB stack — matches official captive portal example */
        NULL,
        5,            /* priority 5 — same as official example                */
        &s_dns_task
    );

    if (ret != pdPASS) {
        s_running  = false;
        s_dns_task = NULL;
        ESP_LOGE(TAG, "xTaskCreate() failed (out of memory?)");
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "Started — redirecting all A queries to " IPSTR,
             IP2STR(&redirect_addr));
    return ESP_OK;
}

void dns_server_stop(void)
{
    if (s_dns_task == NULL) {
        return;
    }

    /*
     * Signal the task to exit.  It will notice within ~1 second
     * (one SO_RCVTIMEO cycle) and self-delete, clearing s_dns_task.
     */
    s_running = false;

    /* Wait up to 3 seconds for a clean exit */
    const uint32_t poll_ms   = 100;
    const uint32_t timeout_ms = 3000;
    uint32_t elapsed = 0;

    while (s_dns_task != NULL && elapsed < timeout_ms) {
        vTaskDelay(pdMS_TO_TICKS(poll_ms));
        elapsed += poll_ms;
    }

    if (s_dns_task != NULL) {
        /* Force-delete as a last resort (socket will leak, but portal
           always ends with esp_restart() so this is acceptable)       */
        ESP_LOGW(TAG, "Task did not exit within %u ms — force-deleting",
                 timeout_ms);
        vTaskDelete(s_dns_task);
        s_dns_task = NULL;
    }

    ESP_LOGI(TAG, "DNS server stopped");
}
