/**
  ******************************************************************************
  * @file    pqc_rng.c
  * @brief   randombytes() for PQClean / CMOX on STM32F446RE.
  *
  * STM32F446 has NO hardware RNG peripheral. For benchmarking we use a
  * deterministic generator: SHAKE128(seed || counter), seeded from the
  * 96-bit device unique ID (UID).
  *
  *   !!! NOT CRYPTOGRAPHICALLY SECURE - FOR PERFORMANCE MEASUREMENTS ONLY !!!
  *
  * A real IoT device would need an entropy source (external TRNG, secure
  * element, or a part with an RNG such as STM32F4x5/F4x7/F439).
  * Determinism is a feature here: every run on the same board produces the
  * same keys, so measurements are reproducible.
  ******************************************************************************
  */
#include <string.h>
#include "stm32f4xx.h"     /* UID_BASE */
#include "fips202.h"       /* shake128() from PQClean */
#include "randombytes.h"   /* #define randombytes PQCLEAN_randombytes */

#define RNG_SEED_LEN 32u

static uint8_t  rng_seed[RNG_SEED_LEN];
static uint32_t rng_counter;
static int      rng_ready;

static void rng_init(void)
{
  static const char tag[] = "quantum-bench-not-secure";   /* 24 B + UID 12 B > 32 */
  memset(rng_seed, 0, sizeof(rng_seed));
  memcpy(rng_seed, (const void *)UID_BASE, 12u);
  memcpy(rng_seed + 12u, tag, RNG_SEED_LEN - 12u);
  rng_counter = 0u;
  rng_ready = 1;
}

void pqc_rng_reset(void)
{
  rng_init();
}

int randombytes(uint8_t *output, size_t n)
{
  uint8_t in[RNG_SEED_LEN + 4u];

  if (!rng_ready)
  {
    rng_init();
  }

  memcpy(in, rng_seed, RNG_SEED_LEN);
  in[RNG_SEED_LEN + 0u] = (uint8_t)(rng_counter);
  in[RNG_SEED_LEN + 1u] = (uint8_t)(rng_counter >> 8);
  in[RNG_SEED_LEN + 2u] = (uint8_t)(rng_counter >> 16);
  in[RNG_SEED_LEN + 3u] = (uint8_t)(rng_counter >> 24);
  rng_counter++;

  shake128(output, n, in, sizeof(in));
  return 0;
}
