# Kryptografia postkwantowa na STM32F446RE: ML-KEM vs ECDH

Projekt studyjny: *Analiza możliwości zastosowania kryptografii postkwantowej w systemach IoT
opartych na mikrokontrolerach STM32*. Program mierzy na płytce **NUCLEO-F446RE** (Cortex-M4F,
512 KB Flash, 128 KB RAM, **168 MHz**):

| Implementacja | Algorytmy |
|---|---|
| [PQClean](https://github.com/PQClean/PQClean) `clean` (przenośne C, kompilowane z projektem) | ML-KEM-512, ML-KEM-768 |
| ST X-CUBE-CRYPTOLIB v5 (CMOX, biblioteka binarna Cortex-M4) | ML-KEM-512, ML-KEM-768, ECDH P-256, X25519 |

Dla każdej operacji (keygen / encaps / decaps / ECDH) mierzone są: cykle CPU (DWT, min/avg/max
z 50 powtórzeń), szczyt stosu, sterta, bufor roboczy CMOX; osobne buildy dają Flash i RAM
statyczny każdego algorytmu.

**Wyniki:** [`tests/report/report.md`](tests/report/report.md) (tabele + wykresy SVG),
surowe logi z płytki: `tests/v*.txt`, rozmiary: [`tests/size/size_report.md`](tests/size/size_report.md).

## Struktura

```
Core/Src/bench.c                      benchmark (pomiar cykli, stosu, sterty, CSV przez UART)
Core/Src/pqc_rng.c                    randombytes(): SHAKE128 z ziarnem z UID - TYLKO do pomiarów
Core/Inc/pqclean_fips202_namespace.h  zmiana nazw SHA-3/SHAKE PQClean (kolizja z symbolami CMOX)
third_party/                          PQClean: common/ (fips202) + crypto_kem/ml-kem-{512,768}/clean
Middlewares/ST/STM32_Cryptographic/   CMOX: include/ + lib/libSTM32Cryptographic_CM4.a (licencja ST SLA0044)
tools/size_report.py                  Flash/RAM z plików .map  -> tests/size/
tools/report.py                       tabele i wykresy          -> tests/report/
```

## Wymagania

- VS Code + STM32Cube for Visual Studio Code (bundle: cmake, ninja, gnu-tools-for-stm32 14.3)
- Python 3 (tylko biblioteka standardowa) do skryptów w `tools/`
- Terminal szeregowy na porcie ST-LINK VCP, 115200 8N1

## Budowanie i pomiar czasu

```bash
cube cmake -S . --preset Release
cube cmake --build build/Release
STM32_Programmer_CLI -c port=SWD -w build/Release/quantum.elf -v -rst
```

Wynik pojawia się na UART po resecie (kilkanaście sekund) i kończy linią `RESULT: ALL OK`.
Zapisz go jako `tests/vN.txt`.

Presety (`CMakePresets.json`):

| Preset | Do czego |
|---|---|
| `Release` | wszystkie algorytmy, PQClean `-O3` (pomiar czasu) |
| `opt-O2`, `opt-Os` | jak wyżej, PQClean `-O2` / `-Os` (Etap 5b) |
| `size-none` | baseline bez algorytmu (do odejmowania) |
| `size-pqclean512`, `size-pqclean768` (+ `-O2`, `-Os`) | tylko dany algorytm PQClean |
| `size-cmoxkem512`, `size-cmoxkem768`, `size-p256`, `size-x25519` | tylko dany algorytm CMOX |

Opcje CMake: `BENCH_ALGO` (`ALL`, `NONE`, `PQCLEAN_512`, `PQCLEAN_768`, `CMOX_KEM_512`,
`CMOX_KEM_768`, `CMOX_P256`, `CMOX_X25519`) i `PQC_OPT_LEVEL` (`-O3`, `-O2`, `-Os`).

## Tryb komunikacji z PC (LINK)

Firmware `APP_MODE=LINK` (preset `link`): wymiana klucza **ML-KEM-768 (PQClean -Os)** z PC przez
UART (ST-LINK VCP, 115200), klucze sesji HKDF-SHA256, wiadomości **AES-256-GCM** (CMOX).
Opis protokołu (ramki, role, wyprowadzanie kluczy, nonce, replay) - nagłówek `Core/Src/kem_link.c`.

```bash
cube cmake -S . --preset link
cube cmake --build build/link
STM32_Programmer_CLI -c port=SWD -w build/link/quantum.elf -v -rst
python -m pip install --user -r tools/requirements.txt
python tools/pc_link.py --port COM20                 # czat; /role pc|mcu, /rekey, /quit
python tools/pc_link.py --port COM20 --selftest 10   # test + tests/link/*.csv
```

Role: `pc` - PC generuje parę kluczy, STM32 enkapsuluje; `mcu` - STM32 generuje parę kluczy i dekapsuluje.
Komendy po stronie STM32: `led on`, `led off`, `stats`, `uid` (inne wiadomości wracają jako echo).
Brak uwierzytelnienia stron (podpisów) - ochrona przed podsłuchem, nie przed aktywnym MITM.

## Raport

```bash
python tools/size_report.py
python tools/report.py
```

`size_report.py` czyta `build/<preset>/quantum.map` wszystkich presetów `size-*`;
`report.py` łączy logi `tests/v*.txt` (dla każdego poziomu optymalizacji najnowszy z `RESULT: ALL OK`)
z raportem rozmiarów.

## Metodologia i zastrzeżenia

- Zegar 168 MHz z HSE (8 MHz z ST-LINK, bypass) przez PLL, 5 wait states, ART: prefetch + I/D-cache.
- Pomiar: `DWT->CYCCNT`, przerwania wyłączone podczas operacji, 50 powtórzeń; przebiegi są powtarzalne
  co do cyklu (generator losowy jest deterministyczny).
- Stos: wypełnienie wzorcem 0xA5 i odczyt najgłębszego nadpisanego słowa; sterta: wrappery
  `malloc/calloc/realloc/free` (`-Wl,--wrap`).
- **STM32F446 nie ma sprzętowego RNG** - `pqc_rng.c` jest deterministyczny i NIE nadaje się do
  zastosowań produkcyjnych. Czas generowania losowości jest wliczony w keygen/encaps obu bibliotek.
- PQClean i CMOX eksportują funkcje SHA-3/SHAKE o tych samych nazwach (w CMOX jako słabe symbole);
  bez `pqclean_fips202_namespace.h` CMOX ML-KEM używał SHAKE z PQClean i zwracał błąd.
- PQClean zostało zarchiwizowane (VIII 2026); następcą dla ML-KEM jest
  [mlkem-native](https://github.com/pq-code-package/mlkem-native).

## Licencje

- Kod projektu (bench, skrypty): do ustalenia przez autora.
- PQClean: pliki `LICENSE` w katalogach `third_party/crypto_kem/*/clean`; `common/` - public domain / MIT.
- CMOX: `Middlewares/ST/STM32_Cryptographic/LICENSE.html` (ST SLA0044) - wolno używać wyłącznie z
  mikrokontrolerami ST.
- Kod wygenerowany przez STM32CubeMX / HAL: licencje ST w `Drivers/`.
