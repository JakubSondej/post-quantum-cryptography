/**
  ******************************************************************************
  * @file    bench.c
  * @brief   PQC vs classic key agreement benchmark on STM32F446RE.
  *
  *   Implementations measured:
  *     - PQClean "clean"  ML-KEM-512, ML-KEM-768   (portable C, open source)
  *     - ST CMOX v5       ML-KEM-512, ML-KEM-768   (X-CUBE-CRYPTOLIB, CM4 lib)
  *     - ST CMOX v5       ECDH P-256, X25519       (classic reference)
  *
  *   For every operation we report:
  *     - CPU cycles (DWT->CYCCNT): min / avg / max over BENCH_ITER runs
  *     - time in microseconds at the current SystemCoreClock
  *     - peak stack usage (stack painting)
  *     - peak heap usage (malloc/free wrapped with -Wl,--wrap)
  *     - CMOX working buffer peak usage (ECC only)
  *
  *   Output: human readable table + "CSV,..." lines for scripts.
  *
  *   Mapping KEM <-> ECDH for the comparison (in the report):
  *     KEM keygen       <-> ECDH keygen   (initiator)
  *     KEM encapsulate  <-> ECDH keygen + ECDH shared secret (responder)
  *     KEM decapsulate  <-> ECDH shared secret (initiator)
  ******************************************************************************
  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "main.h"
#include "bench.h"

/* ST cryptographic library (X-CUBE-CRYPTOLIB v5, CMOX) */
#include "cmox_crypto.h"
#include "utils/cmox_utils_membuf.h"

/* PQClean */
#include "randombytes.h"
#include "ml-kem-512/clean/api.h"
#include "ml-kem-768/clean/api.h"

#ifndef PQC_OPT_LEVEL_STR
#define PQC_OPT_LEVEL_STR "?"
#endif

/* ------------------------------------------------------------------------ */
/* Algorithm selection (Etap 5a: Flash per algorithm).                       */
/* CMake option BENCH_ALGO=ALL|NONE|PQCLEAN_512|PQCLEAN_768|CMOX_KEM_512|    */
/* CMOX_KEM_768|CMOX_P256|CMOX_X25519 defines the BENCH_EN_* macros below.   */
/* Code of disabled algorithms is not compiled, so its library objects are   */
/* not linked and the Flash difference to BENCH_ALGO=NONE is its footprint.  */
/* ------------------------------------------------------------------------ */
#ifndef BENCH_ALGO_STR
/* built without CMake option -> everything enabled */
#define BENCH_ALGO_STR "ALL"
#define BENCH_EN_PQCLEAN_512  1
#define BENCH_EN_PQCLEAN_768  1
#define BENCH_EN_CMOX_KEM_512 1
#define BENCH_EN_CMOX_KEM_768 1
#define BENCH_EN_CMOX_P256    1
#define BENCH_EN_CMOX_X25519  1
#endif
#ifndef BENCH_EN_PQCLEAN_512
#define BENCH_EN_PQCLEAN_512  0
#endif
#ifndef BENCH_EN_PQCLEAN_768
#define BENCH_EN_PQCLEAN_768  0
#endif
#ifndef BENCH_EN_CMOX_KEM_512
#define BENCH_EN_CMOX_KEM_512 0
#endif
#ifndef BENCH_EN_CMOX_KEM_768
#define BENCH_EN_CMOX_KEM_768 0
#endif
#ifndef BENCH_EN_CMOX_P256
#define BENCH_EN_CMOX_P256    0
#endif
#ifndef BENCH_EN_CMOX_X25519
#define BENCH_EN_CMOX_X25519  0
#endif

#define BENCH_EN_PQCLEAN   (BENCH_EN_PQCLEAN_512 || BENCH_EN_PQCLEAN_768)
#define BENCH_EN_CMOX_KEM  (BENCH_EN_CMOX_KEM_512 || BENCH_EN_CMOX_KEM_768)
#define BENCH_EN_CMOX_ECC  (BENCH_EN_CMOX_P256 || BENCH_EN_CMOX_X25519)

/* generic helpers are unused in the BENCH_ALGO=NONE baseline build */
#define BENCH_MAYBE_UNUSED __attribute__((unused))

/* ------------------------------------------------------------------------ */
/* Shared buffers, sized for the largest parameter set (ML-KEM-768)          */
/* ------------------------------------------------------------------------ */
#define KEM_PK_MAX  PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES   /* 1184 */
#define KEM_SK_MAX  PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES   /* 2400 */
#define KEM_CT_MAX  PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES  /* 1088 */
#define KEM_SS_LEN  32u

#if BENCH_EN_PQCLEAN || BENCH_EN_CMOX_KEM
static uint8_t kem_pk[KEM_PK_MAX];
static uint8_t kem_sk[KEM_SK_MAX];
static uint8_t kem_ct[KEM_CT_MAX];
static uint8_t kem_ss_enc[KEM_SS_LEN];
static uint8_t kem_ss_dec[KEM_SS_LEN];
#endif

/* ECC: party A (measured) and party B (fixed peer) */
#define ECC_PRIV_MAX   32u
#define ECC_PUB_MAX    64u   /* P-256: X||Y (64 B), X25519: 32 B */
#define ECC_SEC_MAX    64u   /* P-256 secret = X||Y (64 B), X25519: 32 B */
#define ECC_WORKBUF    4096u /* CMOX working buffer; peak usage is reported */

#if BENCH_EN_CMOX_ECC
static uint8_t ecc_a_priv[ECC_PRIV_MAX], ecc_a_pub[ECC_PUB_MAX];
static uint8_t ecc_b_priv[ECC_PRIV_MAX], ecc_b_pub[ECC_PUB_MAX];
static uint8_t ecc_sec_a[ECC_SEC_MAX], ecc_sec_b[ECC_SEC_MAX];
static uint8_t ecc_workbuf[ECC_WORKBUF];
#endif
static size_t  ecc_workbuf_peak;

/* ------------------------------------------------------------------------ */
/* Heap tracking: linker options -Wl,--wrap=malloc,calloc,realloc,free       */
/* (PQClean's fips202.c allocates SHAKE contexts on the heap).               */
/* Every block carries an 8 B header with its size, so ALL allocation entry  */
/* points must be wrapped: GCC -O3 turns "malloc + zero the Keccak state"    */
/* into calloc(), and a calloc block without header passed to __wrap_free    */
/* corrupted the heap (HardFault in _free_r, found in test v1).              */
/* ------------------------------------------------------------------------ */
void *__real_malloc(size_t size);
void  __real_free(void *ptr);

static size_t heap_cur;
static size_t heap_peak;

void *__wrap_malloc(size_t size)
{
  size_t *p = (size_t *)__real_malloc(size + 8u);   /* 8 B header keeps alignment */
  if (p == NULL)
  {
    return NULL;
  }
  p[0] = size;
  heap_cur += size;
  if (heap_cur > heap_peak)
  {
    heap_peak = heap_cur;
  }
  return (uint8_t *)p + 8u;
}

void __wrap_free(void *ptr)
{
  if (ptr == NULL)
  {
    return;
  }
  size_t *p = (size_t *)((uint8_t *)ptr - 8u);
  heap_cur -= p[0];
  __real_free(p);
}

void *__wrap_calloc(size_t nmemb, size_t size)
{
  if ((size != 0u) && (nmemb > (SIZE_MAX / size)))
  {
    return NULL;   /* overflow */
  }
  size_t total = nmemb * size;
  void *q = __wrap_malloc(total);
  if (q != NULL)
  {
    memset(q, 0, total);
  }
  return q;
}

void *__wrap_realloc(void *ptr, size_t size)
{
  if (ptr == NULL)
  {
    return __wrap_malloc(size);
  }
  if (size == 0u)
  {
    __wrap_free(ptr);
    return NULL;
  }
  size_t old = ((size_t *)((uint8_t *)ptr - 8u))[0];
  void *q = __wrap_malloc(size);
  if (q != NULL)
  {
    memcpy(q, ptr, (old < size) ? old : size);
    __wrap_free(ptr);
  }
  return q;
}

/* ------------------------------------------------------------------------ */
/* Cycle counter (DWT)                                                       */
/* ------------------------------------------------------------------------ */
static void dwt_init(void)
{
  CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
  DWT->CYCCNT = 0u;
  DWT->CTRL  |= DWT_CTRL_CYCCNTENA_Msk;
}

/* ------------------------------------------------------------------------ */
/* Stack painting                                                            */
/* _sstack = _estack - _Min_Stack_Size (see STM32F446xx_FLASH.ld)            */
/* ------------------------------------------------------------------------ */
#define STACK_PATTERN 0xA5A5A5A5u
extern uint32_t _sstack;

typedef int (*bench_fn_t)(void);

static uint32_t stack_overflow_flag;

static uint32_t __attribute__((noinline)) BENCH_MAYBE_UNUSED measure_stack(bench_fn_t fn, int *ret)
{
  uint32_t *bottom = &_sstack;
  uint32_t *sp     = (uint32_t *)__get_MSP();
  uint32_t *p;

  for (p = bottom; p < (sp - 16); p++)   /* leave 64 B margin below SP */
  {
    *p = STACK_PATTERN;
  }

  __disable_irq();
  *ret = fn();
  __enable_irq();

  for (p = bottom; (p < sp) && (*p == STACK_PATTERN); p++)
  {
  }
  stack_overflow_flag = (p == bottom) ? 1u : 0u;
  return (uint32_t)((uint8_t *)sp - (uint8_t *)p);
}

/* ------------------------------------------------------------------------ */
/* Generic operation benchmark                                               */
/* ------------------------------------------------------------------------ */
static uint32_t bench_errors;

static void BENCH_MAYBE_UNUSED bench_op(const char *lib, const char *alg, const char *op,
                                        bench_fn_t fn, uint32_t iters)
{
  uint32_t cmin = UINT32_MAX, cmax = 0u;
  uint64_t csum = 0u;
  int ret = 0, err = 0;

  /* 1) one untimed run: stack + heap + working buffer high-water marks */
  heap_peak = heap_cur;
  ecc_workbuf_peak = 0u;
  size_t heap_base = heap_cur;
  uint32_t stack = measure_stack(fn, &ret);
  uint32_t heap  = (uint32_t)(heap_peak - heap_base);
  uint32_t wbuf  = (uint32_t)ecc_workbuf_peak;
  if (ret != 0) { err = ret; }

  /* 2) timed runs, interrupts off so SysTick does not disturb the count */
  for (uint32_t i = 0u; i < iters; i++)
  {
    __disable_irq();
    uint32_t t0 = DWT->CYCCNT;
    ret = fn();
    uint32_t t1 = DWT->CYCCNT;
    __enable_irq();

    uint32_t d = t1 - t0;
    if (d < cmin) { cmin = d; }
    if (d > cmax) { cmax = d; }
    csum += d;
    if (ret != 0) { err = ret; }
  }

  uint32_t cavg   = (uint32_t)(csum / iters);
  uint32_t mhz    = SystemCoreClock / 1000000u;
  uint32_t us_x10 = (uint32_t)(((uint64_t)cavg * 10u) / mhz);

  if (err != 0) { bench_errors++; }

  printf("%-8s %-11s %-7s %10lu %10lu %10lu %8lu.%lu %7lu%s %6lu %6lu %s\r\n",
         lib, alg, op,
         (unsigned long)cmin, (unsigned long)cavg, (unsigned long)cmax,
         (unsigned long)(us_x10 / 10u), (unsigned long)(us_x10 % 10u),
         (unsigned long)stack, stack_overflow_flag ? "!" : " ",
         (unsigned long)heap, (unsigned long)wbuf,
         (err != 0) ? "ERROR" : "ok");

  printf("CSV,%s,%s,%s,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%d\r\n",
         lib, alg, op, (unsigned long)iters,
         (unsigned long)cmin, (unsigned long)cavg, (unsigned long)cmax,
         (unsigned long)(SystemCoreClock / 1000000u),
         (unsigned long)stack, (unsigned long)heap, (unsigned long)wbuf, err);
}

static void BENCH_MAYBE_UNUSED check_equal(const char *what, const uint8_t *a, const uint8_t *b, size_t n)
{
  int ok = (memcmp(a, b, n) == 0);
  if (!ok) { bench_errors++; }
  printf("  check %-28s : %s\r\n", what, ok ? "shared secrets MATCH" : "MISMATCH !!!");
}

/* ======================================================================== */
/* PQClean ML-KEM                                                            */
/* ======================================================================== */
#if BENCH_EN_PQCLEAN_512
static int pqclean512_keygen(void) { return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(kem_pk, kem_sk); }
static int pqclean512_enc(void)    { return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(kem_ct, kem_ss_enc, kem_pk); }
static int pqclean512_dec(void)    { return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(kem_ss_dec, kem_ct, kem_sk); }
#endif

#if BENCH_EN_PQCLEAN_768
static int pqclean768_keygen(void) { return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(kem_pk, kem_sk); }
static int pqclean768_enc(void)    { return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(kem_ct, kem_ss_enc, kem_pk); }
static int pqclean768_dec(void)    { return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(kem_ss_dec, kem_ct, kem_sk); }
#endif

/* ======================================================================== */
/* ST CMOX ML-KEM (based on X-CUBE-CRYPTOLIB example ML-KEM_KeyGen_Enc_Dec)  */
/* Random seed generation is included in the measured time, like in PQClean */
/* ======================================================================== */
#if BENCH_EN_CMOX_KEM
typedef struct
{
  cmox_pqc_kem_keygen_algo_t keygen;
  cmox_pqc_kem_enc_algo_t    enc;
  cmox_pqc_kem_dec_algo_t    dec;
  size_t pk_len, sk_len, ct_len;
} cmox_kem_set_t;

static const cmox_kem_set_t *cmox_kem;   /* currently benchmarked set */

static int cmox_kem_keygen(void)
{
  cmox_pqc_handle_t ctx;
  uint8_t seed[CMOX_PQC_ML_KEM_768_KEYGEN_SEED_LEN];   /* 64 B (d || z) */
  size_t sk_len = sizeof(kem_sk), pk_len = sizeof(kem_pk);

  randombytes(seed, sizeof(seed));
  cmox_pqc_kem_construct(&ctx, CMOX_PQC_LLENGINES_DEFAULT, NULL, 0u);
  cmox_pqc_retval_t rv = cmox_pqc_kem_keyGen(&ctx, cmox_kem->keygen, seed, sizeof(seed),
                                             kem_sk, &sk_len, kem_pk, &pk_len);
  cmox_pqc_kem_cleanup(&ctx);
  return (rv == CMOX_PQC_SUCCESS) ? 0 : (int)rv;
}

static int cmox_kem_enc(void)
{
  cmox_pqc_handle_t ctx;
  uint8_t seed[CMOX_PQC_ML_KEM_768_ENC_SEED_LEN];      /* 32 B */
  size_t ct_len = sizeof(kem_ct), ss_len = sizeof(kem_ss_enc);

  randombytes(seed, sizeof(seed));
  cmox_pqc_kem_construct(&ctx, CMOX_PQC_LLENGINES_DEFAULT, NULL, 0u);
  cmox_pqc_retval_t rv = cmox_pqc_kem_encapsulate(&ctx, cmox_kem->enc, seed, sizeof(seed),
                                                  kem_pk, cmox_kem->pk_len,
                                                  kem_ct, &ct_len, kem_ss_enc, &ss_len);
  cmox_pqc_kem_cleanup(&ctx);
  return (rv == CMOX_PQC_SUCCESS) ? 0 : (int)rv;
}

static int cmox_kem_dec(void)
{
  cmox_pqc_handle_t ctx;
  size_t ss_len = sizeof(kem_ss_dec);

  cmox_pqc_kem_construct(&ctx, CMOX_PQC_LLENGINES_DEFAULT, NULL, 0u);
  cmox_pqc_retval_t rv = cmox_pqc_kem_decapsulate(&ctx, cmox_kem->dec,
                                                  kem_sk, cmox_kem->sk_len,
                                                  kem_ct, cmox_kem->ct_len,
                                                  kem_ss_dec, &ss_len);
  cmox_pqc_kem_cleanup(&ctx);
  return (rv == CMOX_PQC_SUCCESS) ? 0 : (int)rv;
}
#endif /* BENCH_EN_CMOX_KEM */

/* ======================================================================== */
/* ST CMOX ECDH (based on X-CUBE-CRYPTOLIB example ECDH_SharedSecretGeneration) */
/* ======================================================================== */
#if BENCH_EN_CMOX_ECC
typedef struct
{
  const char *name;
  cmox_ecc_impl_t curve;
  size_t priv_len, pub_len, sec_len, cmp_len;
} ecc_set_t;

static const ecc_set_t *ecc;   /* currently benchmarked curve */

static int ecc_keygen_into(uint8_t *priv, uint8_t *pub)
{
  cmox_ecc_handle_t ctx;
  uint8_t rnd[ECC_PRIV_MAX];
  cmox_ecc_retval_t rv = CMOX_ECC_ERR_WRONG_RANDOM;

  cmox_ecc_construct(&ctx, CMOX_MATH_FUNCS_SUPERFAST256, ecc_workbuf, sizeof(ecc_workbuf));
  /* P-256: random must be < N, otherwise CMOX asks for new random material */
  for (uint32_t tries = 0u; (tries < 16u) && (rv == CMOX_ECC_ERR_WRONG_RANDOM); tries++)
  {
    size_t priv_len = ECC_PRIV_MAX, pub_len = ECC_PUB_MAX;
    randombytes(rnd, ecc->priv_len);
    rv = cmox_ecc_keyGen(&ctx, ecc->curve, rnd, ecc->priv_len, priv, &priv_len, pub, &pub_len);
  }
  size_t used = cmox_membuf_getMaxUsed(CMOX_GET_MEMBUF(ctx));
  if (used > ecc_workbuf_peak) { ecc_workbuf_peak = used; }
  cmox_ecc_cleanup(&ctx);
  return (rv == CMOX_ECC_SUCCESS) ? 0 : (int)rv;
}

static int ecdh_into(const uint8_t *priv, const uint8_t *peer_pub, uint8_t *secret)
{
  cmox_ecc_handle_t ctx;
  size_t sec_len = ECC_SEC_MAX;

  cmox_ecc_construct(&ctx, CMOX_MATH_FUNCS_SUPERFAST256, ecc_workbuf, sizeof(ecc_workbuf));
  cmox_ecc_retval_t rv = cmox_ecdh(&ctx, ecc->curve, priv, ecc->priv_len,
                                   peer_pub, ecc->pub_len, secret, &sec_len);
  size_t used = cmox_membuf_getMaxUsed(CMOX_GET_MEMBUF(ctx));
  if (used > ecc_workbuf_peak) { ecc_workbuf_peak = used; }
  cmox_ecc_cleanup(&ctx);
  return (rv == CMOX_ECC_SUCCESS) ? 0 : (int)rv;
}

static int ecc_keygen_a(void) { return ecc_keygen_into(ecc_a_priv, ecc_a_pub); }
static int ecdh_a(void)       { return ecdh_into(ecc_a_priv, ecc_b_pub, ecc_sec_a); }
#endif /* BENCH_EN_CMOX_ECC */

/* ======================================================================== */
/* Benchmark suites                                                          */
/* ======================================================================== */
#if BENCH_EN_PQCLEAN
static void suite_pqclean(const char *alg, bench_fn_t kg, bench_fn_t enc, bench_fn_t dec)
{
  memset(kem_ss_enc, 0, sizeof(kem_ss_enc));
  memset(kem_ss_dec, 0xFF, sizeof(kem_ss_dec));
  bench_op("PQClean", alg, "keygen", kg,  BENCH_ITER);
  bench_op("PQClean", alg, "encaps", enc, BENCH_ITER);
  bench_op("PQClean", alg, "decaps", dec, BENCH_ITER);
  check_equal(alg, kem_ss_enc, kem_ss_dec, KEM_SS_LEN);
}
#endif

#if BENCH_EN_CMOX_KEM
static void suite_cmox_kem(const char *alg, const cmox_kem_set_t *set)
{
  cmox_kem = set;
  memset(kem_ss_enc, 0, sizeof(kem_ss_enc));
  memset(kem_ss_dec, 0xFF, sizeof(kem_ss_dec));
  bench_op("CMOX", alg, "keygen", cmox_kem_keygen, BENCH_ITER);
  bench_op("CMOX", alg, "encaps", cmox_kem_enc,    BENCH_ITER);
  bench_op("CMOX", alg, "decaps", cmox_kem_dec,    BENCH_ITER);
  check_equal(alg, kem_ss_enc, kem_ss_dec, KEM_SS_LEN);
}
#endif

#if BENCH_EN_CMOX_ECC
static void suite_ecdh(const ecc_set_t *set)
{
  ecc = set;
  memset(ecc_sec_a, 0, sizeof(ecc_sec_a));
  memset(ecc_sec_b, 0xFF, sizeof(ecc_sec_b));

  /* fixed peer B */
  if (ecc_keygen_into(ecc_b_priv, ecc_b_pub) != 0)
  {
    bench_errors++;
    printf("  %s: peer key generation FAILED\r\n", set->name);
    return;
  }

  bench_op("CMOX", set->name, "keygen", ecc_keygen_a, BENCH_ITER);
  bench_op("CMOX", set->name, "ecdh",   ecdh_a,       BENCH_ITER);

  /* B computes the secret with A's public key -> must equal A's result */
  if (ecdh_into(ecc_b_priv, ecc_a_pub, ecc_sec_b) != 0) { bench_errors++; }
  check_equal(set->name, ecc_sec_a, ecc_sec_b, set->cmp_len);
}
#endif

/* ======================================================================== */
static void print_header(void)
{
  uint32_t acr = FLASH->ACR;

  printf("\r\n==================================================================\r\n");
  printf(" PQC benchmark  STM32F446RE  (ML-KEM vs ECDH)\r\n");
  printf("==================================================================\r\n");
  printf(" SYSCLK          : %lu MHz\r\n", (unsigned long)(SystemCoreClock / 1000000u));
  printf(" Flash latency   : %lu WS, prefetch %s, I-cache %s, D-cache %s\r\n",
         (unsigned long)(acr & FLASH_ACR_LATENCY),
         (acr & FLASH_ACR_PRFTEN) ? "on" : "off",
         (acr & FLASH_ACR_ICEN)   ? "on" : "off",
         (acr & FLASH_ACR_DCEN)   ? "on" : "off");
  printf(" Compiler        : GCC %s\r\n", __VERSION__);
  printf(" Algorithms      : %s\r\n", BENCH_ALGO_STR);
  printf(" PQClean opt     : %s   (bench harness: build type)\r\n", PQC_OPT_LEVEL_STR);
  printf(" CMOX            : libSTM32Cryptographic_CM4.a (X-CUBE-CRYPTOLIB v5)\r\n");
  printf(" Iterations      : %lu per operation\r\n", (unsigned long)BENCH_ITER);
  printf(" RNG             : SHAKE128 DRBG seeded from UID (NOT SECURE, bench only)\r\n");
  printf("\r\n Sizes [B]       :      pk     sk     ct/peer-pub  ss\r\n");
  printf("   ML-KEM-512    : %7u %6u %8u %8u\r\n",
         (unsigned)PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES,
         (unsigned)PQCLEAN_MLKEM512_CLEAN_CRYPTO_SECRETKEYBYTES,
         (unsigned)PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES, 32u);
  printf("   ML-KEM-768    : %7u %6u %8u %8u\r\n",
         (unsigned)PQCLEAN_MLKEM768_CLEAN_CRYPTO_PUBLICKEYBYTES,
         (unsigned)PQCLEAN_MLKEM768_CLEAN_CRYPTO_SECRETKEYBYTES,
         (unsigned)PQCLEAN_MLKEM768_CLEAN_CRYPTO_CIPHERTEXTBYTES, 32u);
  printf("   ECDH P-256    : %7u %6u %8u %8u\r\n", 64u, 32u, 64u, 32u);
  printf("   X25519        : %7u %6u %8u %8u\r\n", 32u, 32u, 32u, 32u);
  printf("\r\n%-8s %-11s %-7s %10s %10s %10s %10s %8s %6s %6s\r\n",
         "lib", "algorithm", "op", "cyc_min", "cyc_avg", "cyc_max", "avg_us",
         "stack", "heap", "wbuf");
  printf("CSV,lib,alg,op,iters,cyc_min,cyc_avg,cyc_max,mhz,stack_B,heap_B,wbuf_B,err\r\n");
}

void bench_run(void)
{
  /* CMOX algorithm handles are 'extern const' objects of the library, so these
     tables are filled at run time (not allowed in a static initializer in C). */
#if BENCH_EN_CMOX_KEM_512
  const cmox_kem_set_t cmox_mlkem512 =
  {
    CMOX_PQC_ML_KEM_512_KEYGEN_ALGO, CMOX_PQC_ML_KEM_512_ENC_ALGO, CMOX_PQC_ML_KEM_512_DEC_ALGO,
    CMOX_PQC_ML_KEM_512_PUBKEY_LEN, CMOX_PQC_ML_KEM_512_PRIVKEY_LEN, CMOX_PQC_ML_KEM_512_CIPHERTEXT_LEN
  };
#endif
#if BENCH_EN_CMOX_KEM_768
  const cmox_kem_set_t cmox_mlkem768 =
  {
    CMOX_PQC_ML_KEM_768_KEYGEN_ALGO, CMOX_PQC_ML_KEM_768_ENC_ALGO, CMOX_PQC_ML_KEM_768_DEC_ALGO,
    CMOX_PQC_ML_KEM_768_PUBKEY_LEN, CMOX_PQC_ML_KEM_768_PRIVKEY_LEN, CMOX_PQC_ML_KEM_768_CIPHERTEXT_LEN
  };
#endif
  /* P-256 ECDH secret from CMOX is X||Y (64 B); the shared key is X (32 B) */
#if BENCH_EN_CMOX_P256
  const ecc_set_t p256_rt   = { "P-256",  CMOX_ECC_SECP256R1_HIGHMEM, CMOX_ECC_SECP256R1_PRIVKEY_LEN,
                                CMOX_ECC_SECP256R1_PUBKEY_LEN, CMOX_ECC_SECP256R1_SECRET_LEN, 32u };
#endif
#if BENCH_EN_CMOX_X25519
  const ecc_set_t x25519_rt = { "X25519", CMOX_ECC_CURVE25519, CMOX_ECC_CURVE25519_PRIVKEY_LEN,
                                CMOX_ECC_CURVE25519_PUBKEY_LEN, CMOX_ECC_CURVE25519_SECRET_LEN, 32u };
#endif

  setvbuf(stdout, NULL, _IONBF, 0);   /* no hidden malloc for stdout buffer */
  dwt_init();
  pqc_rng_reset();
  bench_errors = 0u;

  print_header();

#if BENCH_EN_PQCLEAN_512
  suite_pqclean("ML-KEM-512", pqclean512_keygen, pqclean512_enc, pqclean512_dec);
#endif
#if BENCH_EN_PQCLEAN_768
  suite_pqclean("ML-KEM-768", pqclean768_keygen, pqclean768_enc, pqclean768_dec);
#endif
#if BENCH_EN_CMOX_KEM_512
  suite_cmox_kem("ML-KEM-512", &cmox_mlkem512);
#endif
#if BENCH_EN_CMOX_KEM_768
  suite_cmox_kem("ML-KEM-768", &cmox_mlkem768);
#endif
#if BENCH_EN_CMOX_P256
  suite_ecdh(&p256_rt);
#endif
#if BENCH_EN_CMOX_X25519
  suite_ecdh(&x25519_rt);
#endif

  printf("\r\nstack = peak bytes below caller SP ('!' = reached _sstack, increase _Min_Stack_Size)\r\n");
  printf("heap  = peak malloc bytes, wbuf = CMOX ECC working buffer peak (of %u B)\r\n",
         (unsigned)ECC_WORKBUF);
  printf("RESULT: %s (%lu error(s))\r\n", bench_errors ? "FAILED" : "ALL OK",
         (unsigned long)bench_errors);
  printf("==================================================================\r\n");
}
