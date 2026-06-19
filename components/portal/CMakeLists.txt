idf_component_register(
    SRCS
        "portal.c"
    INCLUDE_DIRS
        "."
    REQUIRES
        esp_wifi
        esp_netif
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
)

# The EMBED_FILES directive causes idf_component_register to compile
# portal_html/index.html into the firmware binary as a named symbol pair:
#
#   extern const char    index_html_start[] asm("_binary_index_html_start");
#   extern const uint8_t index_html_end[]   asm("_binary_index_html_end");
#
# Access the HTML in portal.c with:
#   extern const char index_html_start[] asm("_binary_index_html_start");
#   extern const char index_html_end[]   asm("_binary_index_html_end");
#   size_t html_len = index_html_end - index_html_start;
