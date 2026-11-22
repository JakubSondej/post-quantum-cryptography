/**
  ******************************************************************************
  * @file    bench.h
  * @brief   ML-KEM (PQClean + ST CMOX) vs ECDH (ST CMOX) benchmark.
  ******************************************************************************
  */
#ifndef BENCH_H
#define BENCH_H

#ifdef __cplusplus
extern "C" {
#endif

/* Number of timed repetitions of every operation */
#ifndef BENCH_ITER
#define BENCH_ITER 50u
#endif

/* Run the whole benchmark once and print results over USART2 (printf). */
void bench_run(void);

/* Reset the deterministic RNG (pqc_rng.c) so each run uses the same keys. */
void pqc_rng_reset(void);

#ifdef __cplusplus
}
#endif

#endif /* BENCH_H */
