# Flash / static RAM per algorithm (STM32F446RE, GCC Release, -Wl,--gc-sections)

| Wariant | Algorytm | Impl. | Opt. | Flash obrazu [B] | Δ Flash vs baseline [B] | Flash biblioteki [B] | w tym SHA-3 PQClean [B] | RAM stat. [B] | Δ RAM stat. [B] |
|---|---|---|---|---:|---:|---:|---:|---:|---:|
| size-none | baseline | - | - | 11576 | 0 | 0 | 0 | 33880 | 0 |
| size-pqclean512 | ML-KEM-512 | PQClean | -O3 | 24148 | 12572 | 11436 | 6592 | 38624 | 4744 |
| size-pqclean512-O2 | ML-KEM-512 | PQClean | -O2 | 22760 | 11184 | 10092 | 6068 | 38624 | 4744 |
| size-pqclean512-Os | ML-KEM-512 | PQClean | -Os | 21256 | 9680 | 8586 | 5074 | 38624 | 4744 |
| size-pqclean768 | ML-KEM-768 | PQClean | -O3 | 24148 | 12572 | 11436 | 6592 | 38624 | 4744 |
| size-pqclean768-O2 | ML-KEM-768 | PQClean | -O2 | 22784 | 11208 | 10116 | 6068 | 38624 | 4744 |
| size-pqclean768-Os | ML-KEM-768 | PQClean | -Os | 21332 | 9756 | 8662 | 5074 | 38624 | 4744 |
| size-cmoxkem512 | ML-KEM-512 | CMOX | lib | 30428 | 18852 | 12700 | 4524 | 38624 | 4744 |
| size-cmoxkem768 | ML-KEM-768 | CMOX | lib | 30428 | 18852 | 12706 | 4524 | 38624 | 4744 |
| size-p256 | ECDH P-256 | CMOX | lib | 38832 | 27256 | 20470 | 4524 | 38304 | 4424 |
| size-x25519 | X25519 | CMOX | lib | 31316 | 19740 | 13570 | 4524 | 38304 | 4424 |
| Release | all | all | -O3 | 67252 | 55676 | 52430 | 6592 | 43048 | 9168 |

- Δ Flash = Flash obrazu − Flash wariantu size-none (dokładne, z arm-none-eabi-size).
- Flash biblioteki = suma sekcji obiektów biblioteki z pliku .map (przybliżone ±~1 KB: napisy .rodata.str są w .map liczone przed scaleniem przez linker).
- PQClean: Flash biblioteki = kod ML-KEM + SHA-3/SHAKE (fips202.c).
- CMOX: Flash biblioteki zawiera własny Keccak CMOX; kolumna 'SHA-3 PQClean' w wierszach CMOX to generator losowy benchmarku (pqc_rng.c), nie część CMOX.
- Δ RAM statycznego = bufory w bench.c, zwymiarowane na ML-KEM-768 (pk+sk+ct+2·ss = 4736 B) lub ECC (klucze + bufor roboczy CMOX 4096 B) - to artefakt benchmarku, nie wymaganie algorytmu.
- RAM dynamiczny (stos, sterta, bufor roboczy) - tests/v3.txt, kolumny stack/heap/wbuf.
