cmake_minimum_required(VERSION 3.22)

#
# This file is generated only once,
# and is not re-generated if converter is called multiple times.
#
# User is free to modify the file as much as necessary
#

# Setup compiler settings
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)


# Define the build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug")
endif()

# Set the project name
set(CMAKE_PROJECT_NAME quantum)

# Enable compile command to ease indexing with e.g. clangd
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

# Core project settings
project(${CMAKE_PROJECT_NAME})
message("Build type: " ${CMAKE_BUILD_TYPE})

# Enable CMake support for ASM and C languages
enable_language(C ASM)

# Create an executable object type
add_executable(${CMAKE_PROJECT_NAME})

# Add STM32CubeMX generated sources
add_subdirectory(cmake/stm32cubemx)

# Link directories setup
target_link_directories(${CMAKE_PROJECT_NAME} PRIVATE
    # Add user defined library search paths
)

# ---------------------------------------------------------------------------
# PQClean ML-KEM-512 / ML-KEM-768 ("clean" portable C reference)
# Built as a separate static library with its own optimisation level, so the
# crypto code can be benchmarked at -O3/-O2/-Os independently of Debug/Release:
#   cmake --preset Release -DPQC_OPT_LEVEL=-Os
# ---------------------------------------------------------------------------
set(PQC_OPT_LEVEL "-O3" CACHE STRING "Optimisation flag for PQClean sources")

add_library(pqclean STATIC
    third_party/common/fips202.c
    third_party/crypto_kem/ml-kem-512/clean/cbd.c
    third_party/crypto_kem/ml-kem-512/clean/indcpa.c
    third_party/crypto_kem/ml-kem-512/clean/kem.c
    third_party/crypto_kem/ml-kem-512/clean/ntt.c
    third_party/crypto_kem/ml-kem-512/clean/poly.c
    third_party/crypto_kem/ml-kem-512/clean/polyvec.c
    third_party/crypto_kem/ml-kem-512/clean/reduce.c
    third_party/crypto_kem/ml-kem-512/clean/symmetric-shake.c
    third_party/crypto_kem/ml-kem-512/clean/verify.c
    third_party/crypto_kem/ml-kem-768/clean/cbd.c
    third_party/crypto_kem/ml-kem-768/clean/indcpa.c
    third_party/crypto_kem/ml-kem-768/clean/kem.c
    third_party/crypto_kem/ml-kem-768/clean/ntt.c
    third_party/crypto_kem/ml-kem-768/clean/poly.c
    third_party/crypto_kem/ml-kem-768/clean/polyvec.c
    third_party/crypto_kem/ml-kem-768/clean/reduce.c
    third_party/crypto_kem/ml-kem-768/clean/symmetric-shake.c
    third_party/crypto_kem/ml-kem-768/clean/verify.c
)
target_include_directories(pqclean PUBLIC
    third_party/common      # fips202.h, randombytes.h
    third_party/crypto_kem  # "ml-kem-512/clean/api.h", "ml-kem-768/clean/api.h"
)
target_compile_options(pqclean PRIVATE ${PQC_OPT_LEVEL})
# PQClean's fips202 functions (shake128, sha3_256, ...) clash with internal
# symbols of the ST CMOX library -> rename them to pqclean_* everywhere the
# PQClean headers are used (PUBLIC: also applies to pqc_rng.c and bench.c).
target_compile_options(pqclean PUBLIC
    "$<$<COMPILE_LANGUAGE:C>:SHELL:-include ${CMAKE_SOURCE_DIR}/Core/Inc/pqclean_fips202_namespace.h>"
)

# Add sources to executable
target_sources(${CMAKE_PROJECT_NAME} PRIVATE
    Core/Src/bench.c        # ML-KEM vs ECDH benchmark (+ heap wrappers)
    Core/Src/pqc_rng.c      # randombytes() (SHAKE128 DRBG, no TRNG on F446)
    Core/Src/kem_link.c     # ML-KEM-768 + AES-256-GCM link with the PC
)

# ---------------------------------------------------------------------------
# Application: BENCH = measurements (bench.c), LINK = secure link with the PC
# (kem_link.c + tools/pc_link.py).
# ---------------------------------------------------------------------------
set(APP_MODE "BENCH" CACHE STRING "Firmware application: BENCH or LINK")
set_property(CACHE APP_MODE PROPERTY STRINGS BENCH LINK)
if(NOT APP_MODE MATCHES "^(BENCH|LINK)$")
    message(FATAL_ERROR "APP_MODE must be BENCH or LINK")
endif()
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE APP_MODE_${APP_MODE}=1)
message(STATUS "Application mode: ${APP_MODE}")

# Add include paths
target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
    Middlewares/ST/STM32_Cryptographic/include   # ST CMOX (X-CUBE-CRYPTOLIB v5)
)

# ---------------------------------------------------------------------------
# Algorithm selection for the benchmark (Etap 5a: Flash/RAM per algorithm).
# Only the selected algorithm is compiled and linked; NONE = baseline (harness,
# HAL, printf) to subtract from the other variants.
# ---------------------------------------------------------------------------
set(BENCH_ALGO_LIST ALL NONE PQCLEAN_512 PQCLEAN_768 CMOX_KEM_512 CMOX_KEM_768 CMOX_P256 CMOX_X25519)
set(BENCH_ALGO "ALL" CACHE STRING "Benchmarked algorithm(s): ${BENCH_ALGO_LIST}")
set_property(CACHE BENCH_ALGO PROPERTY STRINGS ${BENCH_ALGO_LIST})
if(NOT BENCH_ALGO IN_LIST BENCH_ALGO_LIST)
    message(FATAL_ERROR "BENCH_ALGO='${BENCH_ALGO}' is not one of: ${BENCH_ALGO_LIST}")
endif()
set(BENCH_ALGO_DEFS BENCH_ALGO_STR="${BENCH_ALGO}")
foreach(_alg PQCLEAN_512 PQCLEAN_768 CMOX_KEM_512 CMOX_KEM_768 CMOX_P256 CMOX_X25519)
    if(BENCH_ALGO STREQUAL "ALL" OR BENCH_ALGO STREQUAL _alg)
        list(APPEND BENCH_ALGO_DEFS BENCH_EN_${_alg}=1)
    endif()
endforeach()
message(STATUS "Benchmark algorithms: ${BENCH_ALGO}, PQClean ${PQC_OPT_LEVEL}")

# Add project symbols (macros)
target_compile_definitions(${CMAKE_PROJECT_NAME} PRIVATE
    PQC_OPT_LEVEL_STR="${PQC_OPT_LEVEL}"
    ${BENCH_ALGO_DEFS}
)

# Heap measurement: route every allocator entry point through bench.c wrappers.
# All four are required: GCC may turn malloc+memset into calloc.
target_link_options(${CMAKE_PROJECT_NAME} PRIVATE
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=free
)

# Remove wrong libob.a library dependency when using cpp files
list(REMOVE_ITEM CMAKE_C_IMPLICIT_LINK_LIBRARIES ob)

# Add linked libraries
target_link_libraries(${CMAKE_PROJECT_NAME}
    stm32cubemx

    # Add user defined libraries
    pqclean
    ${CMAKE_SOURCE_DIR}/Middlewares/ST/STM32_Cryptographic/lib/libSTM32Cryptographic_CM4.a
)