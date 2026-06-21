idf_component_register(
    SRCS
        "opsec.c"
        "mbedtls_host_mem.c"
    INCLUDE_DIRS "."
    REQUIRES mbedtls log
)
