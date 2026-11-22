/**
  ******************************************************************************
  * @file    pqclean_fips202_namespace.h
  * @brief   Rename PQClean's SHA-3/SHAKE (common/fips202.c) public functions.
  *
  * PQClean exports un-prefixed global functions (shake128, sha3_256,
  * shake128_inc_init, ...). The ST CMOX library (X-CUBE-CRYPTOLIB v5) uses
  * internal global functions with the SAME names for its own ML-KEM.
  * With static libraries the linker silently takes the first definition, so
  * CMOX ML-KEM was calling PQClean's SHAKE (different context layout) and
  * returned CMOX_PQC_ERR_NO_ALT_IMPL (found in test v2).
  *
  * This header is force-included (-include) into every PQClean source and
  * into code that calls PQClean's fips202 API (see CMakeLists.txt), so PQClean
  * gets pqclean_* symbols and CMOX keeps its own implementation.
  ******************************************************************************
  */
#ifndef PQCLEAN_FIPS202_NAMESPACE_H
#define PQCLEAN_FIPS202_NAMESPACE_H

#define shake128                   pqclean_shake128
#define shake128_absorb            pqclean_shake128_absorb
#define shake128_squeezeblocks     pqclean_shake128_squeezeblocks
#define shake128_ctx_clone         pqclean_shake128_ctx_clone
#define shake128_ctx_release       pqclean_shake128_ctx_release
#define shake128_inc_init          pqclean_shake128_inc_init
#define shake128_inc_absorb        pqclean_shake128_inc_absorb
#define shake128_inc_finalize      pqclean_shake128_inc_finalize
#define shake128_inc_squeeze       pqclean_shake128_inc_squeeze
#define shake128_inc_ctx_clone     pqclean_shake128_inc_ctx_clone
#define shake128_inc_ctx_release   pqclean_shake128_inc_ctx_release

#define shake256                   pqclean_shake256
#define shake256_absorb            pqclean_shake256_absorb
#define shake256_squeezeblocks     pqclean_shake256_squeezeblocks
#define shake256_ctx_clone         pqclean_shake256_ctx_clone
#define shake256_ctx_release       pqclean_shake256_ctx_release
#define shake256_inc_init          pqclean_shake256_inc_init
#define shake256_inc_absorb        pqclean_shake256_inc_absorb
#define shake256_inc_finalize      pqclean_shake256_inc_finalize
#define shake256_inc_squeeze       pqclean_shake256_inc_squeeze
#define shake256_inc_ctx_clone     pqclean_shake256_inc_ctx_clone
#define shake256_inc_ctx_release   pqclean_shake256_inc_ctx_release

#define sha3_256                   pqclean_sha3_256
#define sha3_256_inc_init          pqclean_sha3_256_inc_init
#define sha3_256_inc_absorb        pqclean_sha3_256_inc_absorb
#define sha3_256_inc_finalize      pqclean_sha3_256_inc_finalize
#define sha3_256_inc_ctx_clone     pqclean_sha3_256_inc_ctx_clone
#define sha3_256_inc_ctx_release   pqclean_sha3_256_inc_ctx_release

#define sha3_384                   pqclean_sha3_384
#define sha3_384_inc_init          pqclean_sha3_384_inc_init
#define sha3_384_inc_absorb        pqclean_sha3_384_inc_absorb
#define sha3_384_inc_finalize      pqclean_sha3_384_inc_finalize
#define sha3_384_inc_ctx_clone     pqclean_sha3_384_inc_ctx_clone
#define sha3_384_inc_ctx_release   pqclean_sha3_384_inc_ctx_release

#define sha3_512                   pqclean_sha3_512
#define sha3_512_inc_init          pqclean_sha3_512_inc_init
#define sha3_512_inc_absorb        pqclean_sha3_512_inc_absorb
#define sha3_512_inc_finalize      pqclean_sha3_512_inc_finalize
#define sha3_512_inc_ctx_clone     pqclean_sha3_512_inc_ctx_clone
#define sha3_512_inc_ctx_release   pqclean_sha3_512_inc_ctx_release

#endif /* PQCLEAN_FIPS202_NAMESPACE_H */
