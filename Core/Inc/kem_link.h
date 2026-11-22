/**
  ******************************************************************************
  * @file    kem_link.h
  * @brief   ML-KEM-768 key exchange + AES-256-GCM messaging with a PC.
  *          Protocol description: see kem_link.c header and tools/pc_link.py.
  ******************************************************************************
  */
#ifndef KEM_LINK_H
#define KEM_LINK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Run the link protocol forever (never returns). */
void kem_link_run(void);

/* RNG (pqc_rng.c): reset to the UID-based seed / mix extra input into it. */
void pqc_rng_reset(void);
void pqc_rng_mix(const uint8_t *data, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* KEM_LINK_H */
