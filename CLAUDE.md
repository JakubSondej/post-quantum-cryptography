# CLAUDE.md - kontekst projektu dla Claude Code

Rozmawiaj z użytkownikiem **po polsku**. Projekt studyjny (praca/projekt na studia):
*„Analiza możliwości zastosowania kryptografii postkwantowej w systemach IoT opartych na
mikrokontrolerach STM32”*: uruchomienie ML-KEM-512/768, pomiar czasu (keygen/encaps/decaps),
RAM, Flash, CPU, porównanie z ECDH, ocena przydatności PQC; potem komunikacja z PC.

## Preferencje użytkownika (ważne)
- Uczy się **STM32Cube for Agentic AI** w VS Code - przy pracy z narzędziami ST korzystaj ze skilli
  z `.claude/skills/` (np. `cube-agentic-ai-cli-build-launch`, `-build-environment-setup`, `-esw-*`).
- **Firmware wgrywa sam** (`STM32_Programmer_CLI`) i zapisuje logi UART do `tests/`; nie wgrywaj bez pytania.
- **Nie commituje na `main`** - każda wersja na osobnej gałęzi `feature/*`, PR-ów nie zakłada.
  Commit/push tylko na prośbę.
- Wszystkie pomiary przy **168 MHz** (nie zmieniać zegara).
- `gh` nie jest zalogowany; push przez `git` działa.

## Sprzęt i narzędzia
- NUCLEO-F446RE (Cortex-M4F, 512 KB Flash, 128 KB RAM). **Brak sprzętowego RNG i brak Ethernetu** w F446.
- Zegar: HSE bypass 8 MHz (MCO ST-LINK) -> PLL 168 MHz, FLASH_LATENCY_5, ART (prefetch, I/D-cache).
- USART2 PA2/PA3 = ST-LINK VCP, **COM20**, 115200 8N1. Stos `_Min_Stack_Size = 0x8000`.
- Projekt CubeMX **6.18 (klasyczny)** z toolchainem CMake. CubeMX2 / skill `mx2-*` **nie wspiera F446RE**.
- Build: `cube cmake -S . --preset <preset>` potem `cube cmake --build build/<preset>`
  (wymóg skilla ST: tylko `cube cmake`, nie surowe cmake/ninja). GCC 14.3 z bundla STM32Cube.
- Python 3.14 (`python`), pakiety PC: `pip install --user -r tools/requirements.txt`
  (pyserial, cryptography, kyber-py). Uwaga: `python -I` nie widzi pakietów `--user`.

## Gałęzie (każda wychodzi z poprzedniej)
| Gałąź | Zawartość |
|---|---|
| `main` | projekt CubeMX + UART Hello World |
| `feature/mlkem-benchmark` | benchmark ML-KEM vs ECDH (v3) |
| `feature/measurements` | Flash/RAM per algorytm, `-O2`/`-Os`, raport, README |
| `feature/kem-uart-link` | komunikacja ML-KEM-768 + AES-256-GCM z PC przez UART (qlink v1) |

## Struktura
- `Core/Src/bench.c` - benchmark: DWT cykle (min/avg/max, 50 iteracji, IRQ off), stos (malowanie 0xA5),
  sterta (`-Wl,--wrap=malloc,calloc,realloc,free`), bufor ECC CMOX, CSV na UART.
  Opcja CMake `BENCH_ALGO` = ALL|NONE|PQCLEAN_512|PQCLEAN_768|CMOX_KEM_512|CMOX_KEM_768|CMOX_P256|CMOX_X25519.
- `Core/Src/kem_link.c` - tryb `APP_MODE=LINK`: protokół qlink v1 (opis w nagłówku pliku).
  Transport = tylko `port_read`/`port_write` (do podmiany na Ethernet).
- `Core/Src/pqc_rng.c` - `randombytes()` = SHAKE128(seed||ctr), seed z UID; `pqc_rng_mix()` w trybie LINK.
  NIE jest bezpieczny (brak TRNG) - zaznaczać w pracy.
- `Core/Inc/pqclean_fips202_namespace.h` - wymuszony `-include`: zmienia nazwy SHA-3/SHAKE PQClean na `pqclean_*`.
- `third_party/` - PQClean (zarchiwizowany VIII 2026): `common/` + `crypto_kem/ml-kem-{512,768}/clean`.
  Biblioteka `pqclean` w CMake z `PQC_OPT_LEVEL` (domyślnie -O3).
- `Middlewares/ST/STM32_Cryptographic/` - X-CUBE-CRYPTOLIB **v5.0.0** (CMOX), `libSTM32Cryptographic_CM4.a`
  + LICENSE.html (SLA0044, redystrybucja binarna z licencją OK). Zawiera ML-KEM, ML-DSA, ECDH, AES-GCM, HKDF.
  Paczka źródłowa: `C:\work\stm32cube-expansion-crypto\STM32CubeExpansion_Crypto_V5.0.0` (przykłady dla NUCLEO-L476RG/G474RE = M4).
- `tools/size_report.py` (Flash/RAM z .map -> `tests/size/`), `tools/report.py` (tabele + SVG -> `tests/report/`),
  `tools/pc_link.py` (strona PC qlink: czat, `--role pc|mcu`, `--selftest N` -> `tests/link/`).
- Presety: `Debug`, `Release`, `size-*`, `opt-O2`, `opt-Os`, `link`.

## Pułapki, które już wystąpiły
1. GCC -O3 zamienia `malloc`+zerowanie w PQClean na `calloc` -> wrapper sterty musi owijać też calloc/realloc
   (inaczej HardFault w `_free_r`, log v1).
2. PQClean i CMOX mają globalne funkcje `sha3_*`/`shake*` o tych samych nazwach (w CMOX słabe symbole) -> CMOX ML-KEM
   wołał SHAKE z PQClean i zwracał `CMOX_PQC_ERR_NO_ALT_IMPL` (log v2). Rozwiązanie: nagłówek namespace.
3. Wartości `extern const` CMOX (`CMOX_PQC_ML_KEM_*_ALGO` itd.) nie mogą być w statycznych inicjalizatorach.
4. newlib-nano printf: brak `%llu` i float - drukować liczby całkowite 32-bit.
5. Diagnoza HardFault bez debuggera: `cube programmer -c port=SWD mode=HOTPLUG -r32 0xE000ED28 20` (CFSR/HFSR/BFAR),
   ramka stosu z SP, `arm-none-eabi-addr2line` na właściwym ELF (Debug vs Release!).

## Najważniejsze wyniki (168 MHz, tests/v3.txt, tests/report/report.md)
- PQClean -O3 ML-KEM-512: keygen 5,95 / encaps 6,53 / decaps 7,63 ms; ML-KEM-768: 9,66 / 10,65 / 12,18 ms.
- CMOX ML-KEM-768: 7,56 / 20,13 / 22,33 ms (wolniej, ale stos 5,6 KB vs 14,5 KB PQClean).
- CMOX ECDH P-256: keygen 12,67, ECDH 28,39 ms; X25519: 25,74 / 25,56 ms.
- Pełne uzgodnienie: ML-KEM-512 PQClean 20,1 ms vs P-256 82,1 ms (4x szybciej); dane 1568 B vs 128 B.
- Flash: PQClean ML-KEM 11,2 KB (-O3) / 8,4 KB (-Os, tylko +1% czasu); CMOX ML-KEM 12,4 KB; P-256 20 KB.
  512 i 768 mają ten sam rozmiar kodu. -O2 najwolniejszy.
- Przebiegi powtarzalne co do cyklu; szum między buildami <= 0,07 %.
- LINK (UART 115200): handshake 244 ms (rola pc, STM32 encaps 10,7 ms) / 265 ms (rola mcu, keygen+decaps 21,9 ms);
  >90 % czasu to transmisja. AES-GCM ~1,8 us/B. Szacunek: ML-KEM wygrywa z ECDH end-to-end powyżej ~740 kbit/s.
- Protokół nie uwierzytelnia stron (brak podpisów) - chroni przed podsłuchem, nie przed aktywnym MITM.

## Następne kroki (uzgodnione / do wyboru)
- **Ethernet**: F446RE nie ma MAC - rekomendacja moduł **W5500 po SPI** (sprzętowy TCP/IP), podmiana `port_read/port_write`
  w `kem_link.c` + `TcpTransport` w `pc_link.py`. Sprzęt jeszcze niewybrany przez użytkownika.
- Opcjonalnie: uwierzytelnienie ML-DSA (CMOX v5), pqm4 (asm M4), pomiar energii (zworka IDD JP6), wyższa prędkość UART.
