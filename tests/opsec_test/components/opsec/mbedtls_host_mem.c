/*
 * Linux-host mbedTLS allocation hooks for the OPSEC unit-test shadow component.
 *
 * ESP-IDF's mbedTLS configuration maps platform allocation to
 * esp_mbedtls_mem_calloc/free when CONFIG_MBEDTLS_INTERNAL_MEM_ALLOC=y.
 * The production ESP32 build gets those symbols from the IDF mbedtls port,
 * but the linux host target omits that port while still linking PSA Crypto.
 *
 * This shim provides strong definitions so the linker always resolves the
 * symbols. Keep this test-local so firmware behavior is unchanged.
 *
 * NOTE: Do NOT use __attribute__((weak)) here. Weak definitions can be
 * silently discarded by the linker when building a static executable,
 * causing "undefined reference" errors at link time.
 */

#include <stdlib.h>

void *esp_mbedtls_mem_calloc(size_t n, size_t size)
{
    return calloc(n, size);
}

void esp_mbedtls_mem_free(void *ptr)
{
    free(ptr);
}
