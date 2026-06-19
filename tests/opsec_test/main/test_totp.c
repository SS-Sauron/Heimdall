/*
 * test_totp.c
 *
 * Unity tests for totp_at_counter_for_test().
 *
 * Reference vectors
 * -----------------
 * Source: RFC 6238 Appendix B (SHA-1 row, 6-digit truncation).
 *
 * The RFC publishes 8-digit codes; the 6-digit values below are those
 * codes modulo 10^6, which is exactly what totp_at_counter_for_test()
 * returns when called with digits=6.
 *
 * Seed  : ASCII "12345678901234567890" (20 bytes, the RFC SHA-1 test key)
 * Step  : 30 s  (RFC default)
 *
 * Unix time   Counter T (= time/30)   RFC 8-digit   Expected 6-digit
 * ----------  ----------------------  ------------  ----------------
 *          59                     1   94287082           287082
 *  1111111109              37037036   07081804             81804
 *  1111111111              37037037   14050471             50471
 *  1234567890              41152263   89005924              5924
 *  2000000000              66666666   69279037            279037
 * 20000000000             666666666   65353130            353130
 */

#include <stdint.h>
#include <stddef.h>
#include "unity.h"
#include "opsec.h"

/* RFC 6238 Appendix B SHA-1 test seed: ASCII "12345678901234567890" */
static const uint8_t SEED_RFC[] = {
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0',
    '1', '2', '3', '4', '5', '6', '7', '8', '9', '0'
};
#define SEED_LEN  ((size_t)(sizeof(SEED_RFC)))
#define DIGITS    ((uint8_t)6)

/* -------------------------------------------------------------------------
 * RFC 6238 Appendix B vectors (SHA-1, 6-digit)
 * ------------------------------------------------------------------------- */

static void test_rfc_vector_T1(void)
{
    /* Unix 59 s → T = floor(59/30) = 1  →  287082 */
    TEST_ASSERT_EQUAL_UINT32(287082, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 1ULL, DIGITS));
}

static void test_rfc_vector_T37037036(void)
{
    /* Unix 1111111109 s → T = 37037036  →  081804 */
    TEST_ASSERT_EQUAL_UINT32(81804, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037036ULL, DIGITS));
}

static void test_rfc_vector_T37037037(void)
{
    /* Unix 1111111111 s → T = 37037037  →  050471 */
    TEST_ASSERT_EQUAL_UINT32(50471, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037037ULL, DIGITS));
}

static void test_rfc_vector_T41152263(void)
{
    /* Unix 1234567890 s → T = 41152263  →  005924 */
    TEST_ASSERT_EQUAL_UINT32(5924, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 41152263ULL, DIGITS));
}

static void test_rfc_vector_T66666666(void)
{
    /* Unix 2000000000 s → T = 66666666  →  279037 */
    TEST_ASSERT_EQUAL_UINT32(279037, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 66666666ULL, DIGITS));
}

static void test_rfc_vector_T666666666(void)
{
    /* Unix 20000000000 s → T = 666666666  →  353130 */
    TEST_ASSERT_EQUAL_UINT32(353130, totp_at_counter_for_test(SEED_RFC, SEED_LEN, 666666666ULL, DIGITS));
}

/* -------------------------------------------------------------------------
 * Stability: same inputs → same output (idempotent, no hidden state)
 * ------------------------------------------------------------------------- */

static void test_stability_same_inputs_same_output(void)
{
    uint32_t first  = totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037036ULL, DIGITS);
    uint32_t second = totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037036ULL, DIGITS);
    TEST_ASSERT_EQUAL_UINT32(first, second);
}

/* -------------------------------------------------------------------------
 * Sensitivity: adjacent counters must produce different codes.
 *
 * Using T=37037036 and T=37037037, which are consecutive values that
 * both appear as RFC 6238 vectors, so we know both produce valid,
 * distinct codes (81804 vs 50471).
 * ------------------------------------------------------------------------- */

static void test_sensitivity_adjacent_counters_differ(void)
{
    uint32_t code_T  = totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037036ULL, DIGITS);
    uint32_t code_T1 = totp_at_counter_for_test(SEED_RFC, SEED_LEN, 37037037ULL, DIGITS);
    TEST_ASSERT_NOT_EQUAL(code_T, code_T1);
}

/* -------------------------------------------------------------------------
 * Entry point
 * ------------------------------------------------------------------------- */

void app_main(void)
{
    UNITY_BEGIN();

    /* RFC 6238 Appendix B vectors */
    RUN_TEST(test_rfc_vector_T1);
    RUN_TEST(test_rfc_vector_T37037036);
    RUN_TEST(test_rfc_vector_T37037037);
    RUN_TEST(test_rfc_vector_T41152263);
    RUN_TEST(test_rfc_vector_T66666666);
    RUN_TEST(test_rfc_vector_T666666666);

    /* Algorithm properties */
    RUN_TEST(test_stability_same_inputs_same_output);
    RUN_TEST(test_sensitivity_adjacent_counters_differ);

    UNITY_END();
}
