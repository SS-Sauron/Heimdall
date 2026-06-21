if(IDF_TARGET STREQUAL "linux")
    # Linux host build: only the pure-mbedtls TOTP test path is compiled.
    # Hardware-specific components (esp_netif, lwip, identity) are not
    # available on linux and are not needed by totp_at_counter_for_test().
    idf_component_register(
        SRCS
            "opsec.c"
        INCLUDE_DIRS
            "."
        REQUIRES
            mbedtls
            log
            storage
    )
else()
    idf_component_register(
        SRCS
            "opsec.c"
        INCLUDE_DIRS
            "."
        REQUIRES
            mbedtls
            esp_system
            esp_netif
            lwip
            storage
        PRIV_REQUIRES
            identity
    )
endif()
