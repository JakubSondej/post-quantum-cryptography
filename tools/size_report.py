#!/usr/bin/env python3
"""
Etap 5a/5b - Flash and static RAM per algorithm.

Reads build/<preset>/quantum.map (and arm-none-eabi-size) for every size
preset from CMakePresets.json and writes:
    tests/size/size_report.csv   - one row per preset
    tests/size/size_report.md    - tables for the thesis

Flash of an algorithm is given two ways:
    delta_flash   = flash(preset) - flash(size-none)        (whole-image view)
    lib_flash     = bytes of the crypto library objects      (component view)
PQClean's SHA-3/SHAKE (fips202.c) is reported separately because the
benchmark RNG (pqc_rng.c) also uses it, so it is present in CMOX builds too.

Usage (from the project root, after building the presets):
    python tools/size_report.py
Only the Python standard library is used.
"""
from __future__ import annotations

import csv
import glob
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = ROOT / "tests" / "size"

# preset -> (algorithm label, implementation label, PQClean opt level)
PRESETS = [
    ("size-none",          "baseline",   "-",       "-"),
    ("size-pqclean512",    "ML-KEM-512", "PQClean", "-O3"),
    ("size-pqclean512-O2", "ML-KEM-512", "PQClean", "-O2"),
    ("size-pqclean512-Os", "ML-KEM-512", "PQClean", "-Os"),
    ("size-pqclean768",    "ML-KEM-768", "PQClean", "-O3"),
    ("size-pqclean768-O2", "ML-KEM-768", "PQClean", "-O2"),
    ("size-pqclean768-Os", "ML-KEM-768", "PQClean", "-Os"),
    ("size-cmoxkem512",    "ML-KEM-512", "CMOX",    "lib"),
    ("size-cmoxkem768",    "ML-KEM-768", "CMOX",    "lib"),
    ("size-p256",          "ECDH P-256", "CMOX",    "lib"),
    ("size-x25519",        "X25519",     "CMOX",    "lib"),
    ("Release",            "all",        "all",     "-O3"),
]

COMPONENTS = ["mlkem_pqclean", "fips202", "cmox", "bench", "hal", "libc", "other"]

SECTION_RE = re.compile(r"^ (\.(?:text|rodata|data|bss)\S*|COMMON)\s*$")
# "<section> 0xADDR 0xSIZE object" on one line, or (long section names)
# "<section>" on its own line followed by an indented "0xADDR 0xSIZE object".
ENTRY_RE = re.compile(
    r"^ (?:(\.(?:text|rodata|data|bss)\S*|COMMON)\s+|\s+)0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)\s+(\S.*)$")


def component_of(path: str) -> str:
    p = path.replace("\\", "/")
    if "libSTM32Cryptographic" in p:
        return "cmox"
    if "libpqclean.a" in p:
        return "fips202" if "fips202" in p else "mlkem_pqclean"
    if "bench.c" in p or "pqc_rng.c" in p:
        return "bench"
    if re.search(r"lib(c|c_nano|g|g_nano|m|nosys|gcc)\.a|crt|newlib", p):
        return "libc"
    if "Drivers/" in p or "/Core/" in p or "startup_" in p or "stm32cubemx" in p:
        return "hal"
    return "other"


def kind_of(section: str) -> str:
    if section.startswith(".text"):
        return "text"
    if section.startswith(".rodata"):
        return "rodata"
    if section.startswith(".data"):
        return "data"
    return "bss"  # .bss* and COMMON


def parse_map(map_path: Path) -> dict[str, dict[str, int]]:
    acc = {c: {"text": 0, "rodata": 0, "data": 0, "bss": 0} for c in COMPONENTS}
    lines = map_path.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Linker script and memory map"))
    except StopIteration:
        raise SystemExit(f"{map_path}: no memory map section")
    pending = None
    for line in lines[start:]:
        m = SECTION_RE.match(line)
        if m:
            pending = m.group(1)
            continue
        m = ENTRY_RE.match(line)
        if m:
            section = m.group(1) or pending
            pending = None
            if not section:
                continue
            size = int(m.group(3), 16)
            if size == 0:
                continue
            addr = int(m.group(2), 16)
            if addr == 0:          # discarded / not allocated
                continue
            acc[component_of(m.group(4))][kind_of(section)] += size
        else:
            pending = None
    return acc


def find_size_tool() -> str | None:
    base = os.environ.get("CUBE_BUNDLE_PATH") or os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "stm32cube", "bundles")
    hits = sorted(glob.glob(os.path.join(base, "gnu-tools-for-stm32", "*", "bin", "arm-none-eabi-size*")))
    return hits[-1] if hits else None


def elf_size(tool: str, elf: Path) -> tuple[int, int, int]:
    out = subprocess.run([tool, str(elf)], capture_output=True, text=True, check=True).stdout
    text, data, bss = (int(x) for x in out.splitlines()[1].split()[:3])
    return text, data, bss


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")   # Windows console (cp1252)
    tool = find_size_tool()
    if not tool:
        print("arm-none-eabi-size not found (STM32Cube bundles)", file=sys.stderr)
        return 1

    rows = []
    for preset, alg, impl, opt in PRESETS:
        bdir = ROOT / "build" / preset
        elf, mp = bdir / "quantum.elf", bdir / "quantum.map"
        if not elf.exists() or not mp.exists():
            print(f"skip {preset}: not built ({bdir})")
            continue
        text, data, bss = elf_size(tool, elf)
        comp = parse_map(mp)
        row = {
            "preset": preset, "algorithm": alg, "impl": impl, "opt": opt,
            "flash_total": text + data, "ram_static_total": data + bss,
        }
        for c in COMPONENTS:
            k = comp[c]
            row[f"{c}_flash"] = k["text"] + k["rodata"] + k["data"]
            row[f"{c}_ram"] = k["data"] + k["bss"]
        rows.append(row)

    base = next((r for r in rows if r["preset"] == "size-none"), None)
    for r in rows:
        r["delta_flash"] = r["flash_total"] - base["flash_total"] if base else ""
        r["delta_ram_static"] = r["ram_static_total"] - base["ram_static_total"] if base else ""
        # crypto library footprint: algorithm code (+ SHA-3 for PQClean)
        if r["impl"] == "PQClean":
            r["lib_flash"] = r["mlkem_pqclean_flash"] + r["fips202_flash"]
        elif r["impl"] == "CMOX":
            r["lib_flash"] = r["cmox_flash"]
        elif r["impl"] == "all":
            r["lib_flash"] = r["mlkem_pqclean_flash"] + r["fips202_flash"] + r["cmox_flash"]
        else:
            r["lib_flash"] = 0

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    fields = ["preset", "algorithm", "impl", "opt", "flash_total", "ram_static_total",
              "delta_flash", "delta_ram_static", "lib_flash"] + \
             [f"{c}_{k}" for c in COMPONENTS for k in ("flash", "ram")]
    with open(OUT_DIR / "size_report.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    md = ["# Flash / static RAM per algorithm (STM32F446RE, GCC Release, -Wl,--gc-sections)", "",
          "| Wariant | Algorytm | Impl. | Opt. | Flash obrazu [B] | Δ Flash vs baseline [B] | "
          "Flash biblioteki [B] | w tym SHA-3 PQClean [B] | RAM stat. [B] | Δ RAM stat. [B] |",
          "|---|---|---|---|---:|---:|---:|---:|---:|---:|"]
    for r in rows:
        md.append(f"| {r['preset']} | {r['algorithm']} | {r['impl']} | {r['opt']} | "
                  f"{r['flash_total']} | {r['delta_flash']} | {r['lib_flash']} | "
                  f"{r['fips202_flash']} | {r['ram_static_total']} | {r['delta_ram_static']} |")
    md += ["",
           "- Δ Flash = Flash obrazu − Flash wariantu size-none (dokładne, z arm-none-eabi-size).",
           "- Flash biblioteki = suma sekcji obiektów biblioteki z pliku .map (przybliżone ±~1 KB: "
           "napisy .rodata.str są w .map liczone przed scaleniem przez linker).",
           "- PQClean: Flash biblioteki = kod ML-KEM + SHA-3/SHAKE (fips202.c).",
           "- CMOX: Flash biblioteki zawiera własny Keccak CMOX; kolumna 'SHA-3 PQClean' w wierszach CMOX "
           "to generator losowy benchmarku (pqc_rng.c), nie część CMOX.",
           "- Δ RAM statycznego = bufory w bench.c, zwymiarowane na ML-KEM-768 (pk+sk+ct+2·ss = 4736 B) "
           "lub ECC (klucze + bufor roboczy CMOX 4096 B) - to artefakt benchmarku, nie wymaganie algorytmu.",
           "- RAM dynamiczny (stos, sterta, bufor roboczy) - tests/v3.txt, kolumny stack/heap/wbuf.", ""]
    (OUT_DIR / "size_report.md").write_text("\n".join(md), encoding="utf-8")

    print("\n".join(md))
    print(f"\nwritten: {OUT_DIR / 'size_report.csv'}\n         {OUT_DIR / 'size_report.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
