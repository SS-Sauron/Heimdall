idf_component_register(
    SRCS
        "portal.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        esp_wifi
        esp_netif
        esp_system
        esp_http_server
        nvs_flash
        lwip
        mbedtls
        dns_server
        storage
        identity
        espressif__cjson
        opsec
    PRIV_REQUIRES
        esp_timer
    EMBED_FILES
        "portal_html/index.html"
    EMBED_TXTFILES
        "portal_html/login.html"
        "portal_html/secrets.html"
        "portal_html/rebooting.html"
)

# The EMBED_FILES directive keeps index.html on the existing symbol pair:
#
#   extern const char    index_html_start[] asm("_binary_index_html_start");
#   extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
#
# The EMBED_TXTFILES directive embeds the smaller HTML templates as
# null-terminated strings. HTTP responses must use (end - start - 1)
# so the appended null terminator is not sent.
