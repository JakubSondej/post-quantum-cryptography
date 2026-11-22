#!/usr/bin/env python3
"""
Etap 6 - tables and charts for the thesis.

Inputs
    tests/v*.txt                 UART logs of the benchmark (CSV,... lines)
    tests/size/size_report.csv   Flash/RAM per algorithm (tools/size_report.py)
Outputs
    tests/report/report.md       tables (Polish) + links to charts
    tests/report/*.svg           charts (static SVG, light theme, for print)
    tests/report/timing_all.csv  merged timing data

For every PQClean optimisation level the newest log with "RESULT: ALL OK" is
used; logs with the same level are checked for identical results
(reproducibility). Only the Python standard library is used.

    python tools/report.py
"""
from __future__ import annotations

import csv
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
TESTS = ROOT / "tests"
OUT = TESTS / "report"

# ---------------------------------------------------------------- palette ---
# dataviz reference palette, first three categorical slots (validated all-pairs,
# light mode). Teal is < 3:1 on the surface -> every bar carries a value label.
C_PQCLEAN, C_CMOXKEM, C_ECDH = "#2a78d6", "#eb6834", "#1baf7a"
SURFACE, TEXT1, TEXT2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"

KEM_BYTES = {  # pk, sk, ct, ss  (FIPS 203)
    "ML-KEM-512": (800, 1632, 768, 32),
    "ML-KEM-768": (1184, 2400, 1088, 32),
}
ECC_BYTES = {  # priv, pub, peer-pub, secret (as used by CMOX)
    "P-256": (32, 64, 64, 64),
    "X25519": (32, 32, 32, 32),
}
# wolfSSL blog (NUCLEO-F439ZI, Cortex-M4 168 MHz, Thumb-2 asm), avg ms
WOLFSSL = {
    ("ML-KEM-512", "keygen"): 4.032, ("ML-KEM-512", "encaps"): 3.817, ("ML-KEM-512", "decaps"): 5.051,
    ("ML-KEM-768", "keygen"): 6.519, ("ML-KEM-768", "encaps"): 6.571, ("ML-KEM-768", "decaps"): 8.333,
    ("P-256", "keygen"): 5.594, ("P-256", "ecdh"): 11.814,
}

ORDER = [("PQClean", "ML-KEM-512"), ("PQClean", "ML-KEM-768"),
         ("CMOX", "ML-KEM-512"), ("CMOX", "ML-KEM-768"),
         ("CMOX", "P-256"), ("CMOX", "X25519")]


def color_of(lib: str, alg: str) -> str:
    if alg.startswith("ML-KEM"):
        return C_PQCLEAN if lib == "PQClean" else C_CMOXKEM
    return C_ECDH


def label_of(lib: str, alg: str) -> str:
    return f"{lib} {alg}" if alg.startswith("ML-KEM") else f"ECDH {alg} (CMOX)"


# ---------------------------------------------------------------- parsing ---
def parse_log(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    opt = re.search(r"PQClean opt\s*:\s*(\S+)", text)
    mhz = re.search(r"SYSCLK\s*:\s*(\d+)", text)
    ok = "RESULT: ALL OK" in text
    rows = {}
    for line in text.splitlines():
        if not line.startswith("CSV,") or line.startswith("CSV,lib,"):
            continue
        f = line.strip().split(",")
        if len(f) < 13:
            continue
        lib, alg, op = f[1], f[2], f[3]
        rows[(lib, alg, op)] = {
            "iters": int(f[4]), "cyc_min": int(f[5]), "cyc_avg": int(f[6]), "cyc_max": int(f[7]),
            "mhz": int(f[8]), "stack": int(f[9]), "heap": int(f[10]), "wbuf": int(f[11]), "err": int(f[12]),
        }
    return {"file": path.name, "opt": opt.group(1) if opt else "?",
            "mhz": int(mhz.group(1)) if mhz else 0, "ok": ok, "rows": rows}


def ms(row) -> float:
    return row["cyc_avg"] / (row["mhz"] * 1000.0)


def load_logs():
    logs = [parse_log(p) for p in sorted(TESTS.glob("v*.txt"))]
    by_opt: dict[str, list] = {}
    for lg in logs:
        if lg["ok"] and lg["rows"]:
            by_opt.setdefault(lg["opt"], []).append(lg)
    chosen, repro = {}, {}
    for opt, lst in by_opt.items():
        chosen[opt] = lst[-1]
        cyc = [{k: v["cyc_avg"] for k, v in lg["rows"].items()} for lg in lst]
        repro[opt] = ([lg["file"] for lg in lst], all(c == cyc[0] for c in cyc))
    return logs, chosen, repro


def load_sizes():
    p = TESTS / "size" / "size_report.csv"
    if not p.exists():
        return {}
    return {r["preset"]: r for r in csv.DictReader(open(p, encoding="utf-8"))}


# ------------------------------------------------------------------- svg ----
FONT = "font-family='Segoe UI, Helvetica, Arial, sans-serif'"


def nice_axis(v: float, target_ticks: int = 4) -> tuple[float, float, int]:
    """Axis (max, step, decimals) with a 1/2/2.5/5 x 10^e step and ~target_ticks intervals."""
    import math
    raw = v / target_ticks
    e = math.floor(math.log10(raw)) if raw > 0 else 0
    step = None
    for m in (1, 2, 2.5, 5, 10):
        if m * 10 ** e >= raw:
            step = m * 10 ** e
            break
    vmax = step * math.ceil(v / step)
    dec = 0 if float(step).is_integer() else (1 if float(step * 10).is_integer() else 2)
    return vmax, step, dec


def svg_hbar(path: Path, title: str, unit: str, items, legend, fmt="{:.1f}", note=""):
    """items: [(label, value, color, tooltip)]  legend: [(color, text)]"""
    bar_h, gap, left, right, top = 22, 10, 230, 90, 64 if legend else 44
    width = 760
    plot_w = width - left - right
    height = top + len(items) * (bar_h + gap) + 44 + (16 if note else 0)
    vmax, step, dec = nice_axis(max(v for _, v, _, _ in items) * 1.05)
    x = lambda v: left + plot_w * v / vmax
    s = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
         f"viewBox='0 0 {width} {height}' {FONT}>",
         f"<rect width='100%' height='100%' fill='{SURFACE}'/>",
         f"<text x='16' y='26' font-size='16' font-weight='600' fill='{TEXT1}'>{escape(title)}</text>"]
    lx = 16
    for col, txt in legend:
        s.append(f"<rect x='{lx}' y='38' width='12' height='12' rx='3' fill='{col}'/>"
                 f"<text x='{lx + 18}' y='48' font-size='12' fill='{TEXT2}'>{escape(txt)}</text>")
        lx += 34 + 7 * len(txt)
    bottom = top + len(items) * (bar_h + gap)
    for i in range(int(round(vmax / step)) + 1):          # recessive grid
        v = step * i
        gx = x(v)
        s.append(f"<line x1='{gx:.1f}' y1='{top - 4}' x2='{gx:.1f}' y2='{bottom}' stroke='{GRID}' stroke-width='1'/>"
                 f"<text x='{gx:.1f}' y='{bottom + 16}' font-size='11' fill='{TEXT2}' text-anchor='middle'>"
                 f"{v:.{dec}f}</text>")
    s.append(f"<text x='{left + plot_w / 2:.1f}' y='{bottom + 34}' font-size='12' fill='{TEXT2}' "
             f"text-anchor='middle'>{escape(unit)}</text>")
    for i, (lab, v, col, tip) in enumerate(items):
        y = top + i * (bar_h + gap)
        w = max(x(v) - left, 1)
        s.append(f"<text x='{left - 10}' y='{y + bar_h * 0.7:.1f}' font-size='12.5' fill='{TEXT1}' "
                 f"text-anchor='end'>{escape(lab)}</text>")
        # bar anchored at the axis, 4 px rounded data end
        s.append(f"<g><title>{escape(tip)}</title>"
                 f"<path d='M{left},{y} h{w - 4:.1f} a4,4 0 0 1 4,4 v{bar_h - 8} a4,4 0 0 1 -4,4 h{-(w - 4):.1f} z' "
                 f"fill='{col}'/></g>")
        s.append(f"<text x='{left + w + 6:.1f}' y='{y + bar_h * 0.7:.1f}' font-size='12' fill='{TEXT1}'>"
                 f"{fmt.format(v)}</text>")
    if note:
        s.append(f"<text x='16' y='{height - 10}' font-size='11' fill='{TEXT2}'>{escape(note)}</text>")
    s.append("</svg>")
    path.write_text("\n".join(s), encoding="utf-8")


def svg_grouped(path: Path, title: str, unit: str, groups, series, fmt="{:.1f}", note=""):
    """groups: [(group_label, [v_series0, v_series1, ...])]  series: [(color, name)]"""
    left, right, top = 60, 20, 70
    plot_h, bw, inner, outer = 260, 28, 2, 40
    n = len(series)
    gw = n * bw + (n - 1) * inner
    width = max(560, left + right + len(groups) * (gw + outer) + outer)
    height = top + plot_h + 70 + (16 if note else 0)
    vmax, step, dec = nice_axis(max(max(v for v in vals if v is not None) for _, vals in groups) * 1.08)
    y = lambda v: top + plot_h - plot_h * v / vmax
    s = [f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' "
         f"viewBox='0 0 {width} {height}' {FONT}>",
         f"<rect width='100%' height='100%' fill='{SURFACE}'/>",
         f"<text x='16' y='26' font-size='16' font-weight='600' fill='{TEXT1}'>{escape(title)}</text>"]
    lx = 16
    for col, txt in series:
        s.append(f"<rect x='{lx}' y='38' width='12' height='12' rx='3' fill='{col}'/>"
                 f"<text x='{lx + 18}' y='48' font-size='12' fill='{TEXT2}'>{escape(txt)}</text>")
        lx += 34 + 7 * len(txt)
    for i in range(int(round(vmax / step)) + 1):
        v = step * i
        gy = y(v)
        s.append(f"<line x1='{left}' y1='{gy:.1f}' x2='{width - right}' y2='{gy:.1f}' stroke='{GRID}'/>"
                 f"<text x='{left - 6}' y='{gy + 4:.1f}' font-size='11' fill='{TEXT2}' text-anchor='end'>"
                 f"{v:.{dec}f}</text>")
    s.append(f"<text x='14' y='{top + plot_h / 2:.1f}' font-size='12' fill='{TEXT2}' text-anchor='middle' "
             f"transform='rotate(-90 14 {top + plot_h / 2:.1f})'>{escape(unit)}</text>")
    for gi, (glab, vals) in enumerate(groups):
        gx = left + outer + gi * (gw + outer)
        for si, v in enumerate(vals):
            if v is None:
                continue
            bx = gx + si * (bw + inner)
            by, base = y(v), top + plot_h
            h = max(base - by, 1)
            col, name = series[si]
            s.append(f"<g><title>{escape(glab)} - {escape(name)}: {fmt.format(v)} {escape(unit)}</title>"
                     f"<path d='M{bx},{base} v{-(h - 4):.1f} a4,4 0 0 1 4,-4 h{bw - 8} a4,4 0 0 1 4,4 "
                     f"v{h - 4:.1f} z' fill='{col}'/></g>")
            s.append(f"<text x='{bx + bw / 2:.1f}' y='{by - 4:.1f}' font-size='10' fill='{TEXT1}' "
                     f"text-anchor='middle'>{fmt.format(v)}</text>")
        s.append(f"<text x='{gx + gw / 2:.1f}' y='{top + plot_h + 18}' font-size='11.5' fill='{TEXT1}' "
                 f"text-anchor='middle'>{escape(glab)}</text>")
    if note:
        s.append(f"<text x='16' y='{height - 10}' font-size='11' fill='{TEXT2}'>{escape(note)}</text>")
    s.append("</svg>")
    path.write_text("\n".join(s), encoding="utf-8")


# ------------------------------------------------------------------ report --
def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    OUT.mkdir(parents=True, exist_ok=True)
    logs, chosen, repro = load_logs()
    sizes = load_sizes()
    if "-O3" not in chosen:
        print("no successful -O3 log (tests/v*.txt) found", file=sys.stderr)
        return 1
    base = chosen["-O3"]
    R = base["rows"]
    md = ["# Wyniki pomiarów - ML-KEM vs ECDH na STM32F446RE", "",
          f"Źródło czasów: `tests/{base['file']}` (PQClean -O3), SYSCLK {base['mhz']} MHz, "
          "cache ART włączony, 50 powtórzeń na operację, przerwania wyłączone podczas pomiaru.", ""]

    # reproducibility
    md += ["## Powtarzalność", "", "| Opt. PQClean | Logi | Wyniki identyczne |", "|---|---|---|"]
    for opt, (files, same) in sorted(repro.items()):
        md.append(f"| {opt} | {', '.join(files)} | {'tak' if same else 'NIE'} |")
    bad = [lg["file"] for lg in logs if not lg["ok"]]
    if bad:
        md.append(f"\nPominięte logi bez `RESULT: ALL OK`: {', '.join(bad)}.")
    md.append("")

    # 1) per-operation times
    md += ["## 1. Czas operacji [ms] (średnia; min-max w cyklach)", "",
           "| Implementacja | keygen | encaps / ECDH | decaps | wolfSSL asm (F439) keygen / enc / dec |",
           "|---|---:|---:|---:|---|"]
    timing_rows = []
    for lib, alg in ORDER:
        if alg.startswith("ML-KEM"):
            ops = ["keygen", "encaps", "decaps"]
        else:
            ops = ["keygen", "ecdh"]
        vals = [R.get((lib, alg, op)) for op in ops]
        if any(v is None for v in vals):
            continue
        cells = [f"{ms(v):.2f}" for v in vals] + ([""] if len(vals) == 2 else [])
        # reference shown once per algorithm: next to PQClean (ML-KEM) and CMOX P-256
        show_ref = lib == "PQClean" or not alg.startswith("ML-KEM")
        ref = " / ".join(f"{WOLFSSL[(alg, op)]:.2f}" for op in ops if (alg, op) in WOLFSSL) if show_ref else ""
        md.append(f"| {label_of(lib, alg)} | " + " | ".join(cells) + f" | {ref or '-'} |")
        for op, v in zip(ops, vals):
            timing_rows.append({"opt": base["opt"], "lib": lib, "alg": alg, "op": op, "ms": round(ms(v), 3), **v})
    md.append("")

    # 2) full key agreement
    md += ["## 2. Pełne uzgodnienie klucza (obie strony)", "",
           "KEM: inicjator = keygen + decaps, odpowiadający = encaps. "
           "ECDH: każda strona = keygen + ECDH.", "",
           "| Implementacja | Inicjator [ms] | Odpowiadający [ms] | Razem [ms] | Przesyłane dane [B] | vs P-256 |",
           "|---|---:|---:|---:|---:|---:|"]
    full = {}
    for lib, alg in ORDER:
        if alg.startswith("ML-KEM"):
            k, e, d = (R.get((lib, alg, o)) for o in ("keygen", "encaps", "decaps"))
            if None in (k, e, d):
                continue
            ini, res = ms(k) + ms(d), ms(e)
            pk, sk, ct, ss = KEM_BYTES[alg]
            tx = pk + ct
        else:
            k, x = R.get((lib, alg, "keygen")), R.get((lib, alg, "ecdh"))
            if None in (k, x):
                continue
            ini = res = ms(k) + ms(x)
            tx = 2 * ECC_BYTES[alg][1]
        full[(lib, alg)] = (ini, res, ini + res, tx)
    p256 = full.get(("CMOX", "P-256"), (0, 0, 0, 0))[2]
    for key, (ini, res, tot, tx) in full.items():
        ratio = f"{p256 / tot:.1f}× szybciej" if p256 and tot < p256 else (f"{tot / p256:.1f}× wolniej" if p256 and tot > p256 else "1.0×")
        md.append(f"| {label_of(*key)} | {ini:.2f} | {res:.2f} | {tot:.2f} | {tx} | {ratio} |")
    md += ["", "Przesyłane dane: ML-KEM = klucz publiczny + szyfrogram; ECDH = 2 klucze publiczne "
               "(P-256 bez bajtu 0x04, bez kompresji).", ""]

    # 3) memory
    md += ["## 3. Pamięć RAM", "",
           "Minimalny RAM algorytmu ≈ bufory kluczy + szczyt stosu + sterta + bufor roboczy CMOX.", "",
           "| Implementacja | Bufory kluczy [B] | Szczyt stosu [B] | Sterta [B] | Bufor roboczy [B] | Razem ≈ [B] |",
           "|---|---:|---:|---:|---:|---:|"]
    ram = {}
    for lib, alg in ORDER:
        rows = [v for (l, a, _), v in R.items() if l == lib and a == alg]
        if not rows:
            continue
        keys = sum(KEM_BYTES[alg]) if alg.startswith("ML-KEM") else sum(ECC_BYTES[alg])
        st = max(r["stack"] for r in rows)
        # heap: 200 B in keygen/encaps rows of CMOX/ECC comes from the benchmark RNG only
        hp = max(r["heap"] for r in rows) if lib == "PQClean" else 0
        wb = max(r["wbuf"] for r in rows)
        ram[(lib, alg)] = keys + st + hp + wb
        md.append(f"| {label_of(lib, alg)} | {keys} | {st} | {hp} | {wb} | {keys + st + hp + wb} |")
    md += ["", "Stos zawiera ramki benchmarku i generatora losowego (~kilkaset B). Sterta 200 B w wierszach "
               "CMOX pochodzi z generatora losowego benchmarku, nie z CMOX - pominięta. "
               "PQClean alokuje kontekst SHAKE (200-208 B) przez malloc.", ""]

    # 4) flash
    flash = {}
    if sizes:
        md += ["## 4. Pamięć Flash", "",
               "| Implementacja | Opt. | Flash biblioteki [B] | Δ Flash obrazu vs baseline [B] |",
               "|---|---|---:|---:|"]
        preset_of = {("PQClean", "ML-KEM-512"): "size-pqclean512", ("PQClean", "ML-KEM-768"): "size-pqclean768",
                     ("CMOX", "ML-KEM-512"): "size-cmoxkem512", ("CMOX", "ML-KEM-768"): "size-cmoxkem768",
                     ("CMOX", "P-256"): "size-p256", ("CMOX", "X25519"): "size-x25519"}
        for key in ORDER:
            r = sizes.get(preset_of[key])
            if not r:
                continue
            flash[key] = int(r["lib_flash"])
            md.append(f"| {label_of(*key)} | {r['opt']} | {r['lib_flash']} | {r['delta_flash']} |")
        md += ["", "Flash biblioteki: PQClean = ML-KEM + SHA-3 (fips202.c); CMOX = obiekty biblioteki "
                   "(z własnym Keccakiem). Δ Flash zawiera też kod benchmarku dla danego algorytmu "
                   "i - w wariantach CMOX - SHA-3 generatora losowego. Szczegóły: tests/size/size_report.md.", ""]

    # 5) optimisation levels
    opts = [o for o in ("-O3", "-O2", "-Os") if o in chosen]
    if len(opts) > 1 or sizes:
        md += ["## 5. Poziom optymalizacji PQClean (czas vs Flash)", "",
               "| Algorytm | Opt. | keygen [ms] | encaps [ms] | decaps [ms] | Razem [ms] | Szczyt stosu [B] | Flash biblioteki [B] |",
               "|---|---|---:|---:|---:|---:|---:|---:|"]
        for alg in ("ML-KEM-512", "ML-KEM-768"):
            for o in ("-O3", "-O2", "-Os"):
                lg = chosen.get(o)
                pr = f"size-pqclean{alg[-3:]}" + ("" if o == "-O3" else o)
                fl = sizes.get(pr, {}).get("lib_flash", "-")
                if lg:
                    t = [lg["rows"].get(("PQClean", alg, op)) for op in ("keygen", "encaps", "decaps")]
                    if None in t:
                        continue
                    st = max(r["stack"] for r in t)
                    md.append(f"| {alg} | {o} | " + " | ".join(f"{ms(r):.2f}" for r in t) +
                              f" | {sum(ms(r) for r in t):.2f} | {st} | {fl} |")
                    for op, r in zip(("keygen", "encaps", "decaps"), t):
                        if o != base["opt"]:
                            timing_rows.append({"opt": o, "lib": "PQClean", "alg": alg, "op": op,
                                                "ms": round(ms(r), 3), **r})
                else:
                    md.append(f"| {alg} | {o} | - | - | - | - | - | {fl} |")
        md += ["", "CMOX jest gotową biblioteką binarną - poziom optymalizacji go nie dotyczy.", ""]
        # measurement stability between different builds: CMOX operations without RNG
        if len(opts) > 1:
            md += ["### Stabilność pomiaru między buildami", "",
                   "Operacje CMOX bez generatora losowego (decaps, ECDH) mają identyczny kod binarny w każdym "
                   "buildzie; różnice wynikają tylko z innego rozmieszczenia kodu we Flash (ART cache).", "",
                   "| Operacja | " + " | ".join(f"{o} [cykle]" for o in opts) + " | max różnica |",
                   "|---|" + "---:|" * (len(opts) + 1)]
            for key in (("CMOX", "ML-KEM-512", "decaps"), ("CMOX", "ML-KEM-768", "decaps"),
                        ("CMOX", "P-256", "ecdh"), ("CMOX", "X25519", "ecdh")):
                vals = [chosen[o]["rows"].get(key, {}).get("cyc_avg") for o in opts]
                if None in vals:
                    continue
                spread = (max(vals) - min(vals)) / min(vals) * 100
                md.append(f"| {key[0]} {key[1]} {key[2]} | " + " | ".join(str(v) for v in vals) +
                          f" | {spread:.3f} % |")
            md += ["", "Operacje z losowością (keygen, encaps) różnią się nieco bardziej, bo generator "
                       "benchmarku (SHAKE128 z PQClean) jest kompilowany z danym poziomem optymalizacji.", ""]

    # charts ---------------------------------------------------------------
    fam = [(C_PQCLEAN, "ML-KEM PQClean"), (C_CMOXKEM, "ML-KEM CMOX"), (C_ECDH, "ECDH CMOX")]
    charts = []
    if full:
        svg_hbar(OUT / "full_exchange_ms.svg", "Pełne uzgodnienie klucza - czas CPU obu stron",
                 "czas [ms] przy 168 MHz",
                 [(label_of(*k), v[2], color_of(*k), f"{label_of(*k)}: {v[2]:.2f} ms") for k, v in full.items()],
                 fam, note="KEM: keygen + encaps + decaps; ECDH: 2 × (keygen + ECDH). Mniej = lepiej.")
        charts.append(("full_exchange_ms.svg", "Pełne uzgodnienie klucza [ms]"))
        svg_hbar(OUT / "bytes_on_air.svg", "Dane przesyłane podczas uzgodnienia klucza",
                 "bajty", [(label_of(*k), v[3], color_of(*k), f"{label_of(*k)}: {v[3]} B") for k, v in full.items()],
                 fam, fmt="{:.0f}", note="ML-KEM: pk + ct; ECDH: 2 klucze publiczne.")
        charts.append(("bytes_on_air.svg", "Przesyłane dane [B]"))
    ops_groups = []
    for lib, alg in ORDER:
        if alg.startswith("ML-KEM"):
            ops_groups.append((f"{lib} {alg[-3:]}",
                               [ms(R[(lib, alg, o)]) for o in ("keygen", "encaps", "decaps")]))
    if ops_groups:
        svg_grouped(OUT / "kem_ops_ms.svg", "ML-KEM - czas poszczególnych operacji", "czas [ms]",
                    ops_groups, [(C_PQCLEAN, "keygen"), (C_CMOXKEM, "encaps"), (C_ECDH, "decaps")],
                    note=f"STM32F446RE @ {base['mhz']} MHz, PQClean {base['opt']}, CMOX v5 (biblioteka binarna).")
        charts.append(("kem_ops_ms.svg", "ML-KEM - czas operacji [ms]"))
    if ram:
        svg_hbar(OUT / "ram_kb.svg", "Szacowany minimalny RAM algorytmu", "RAM [KB]",
                 [(label_of(*k), v / 1024, color_of(*k), f"{label_of(*k)}: {v} B") for k, v in ram.items()],
                 fam, note="Bufory kluczy + szczyt stosu + sterta + bufor roboczy CMOX.")
        charts.append(("ram_kb.svg", "Minimalny RAM [KB]"))
    if flash:
        svg_hbar(OUT / "flash_kb.svg", "Flash biblioteki kryptograficznej", "Flash [KB]",
                 [(label_of(*k), v / 1024, color_of(*k), f"{label_of(*k)}: {v} B") for k, v in flash.items()],
                 fam, note="PQClean -O3 (z SHA-3); CMOX: obiekty biblioteki linkowane dla danego algorytmu.")
        charts.append(("flash_kb.svg", "Flash biblioteki [KB]"))
    if len(opts) > 1:
        groups = []
        for alg in ("ML-KEM-512", "ML-KEM-768"):
            groups.append((alg, [sum(ms(chosen[o]["rows"][("PQClean", alg, op)]) for op in ("keygen", "encaps", "decaps"))
                                 if o in chosen else None for o in ("-O3", "-O2", "-Os")]))
        svg_grouped(OUT / "pqclean_opt_ms.svg", "PQClean - czas pełnego uzgodnienia vs poziom optymalizacji",
                    "czas [ms]", groups, [(C_PQCLEAN, "-O3"), (C_CMOXKEM, "-O2"), (C_ECDH, "-Os")])
        charts.append(("pqclean_opt_ms.svg", "PQClean: czas vs -O3/-O2/-Os"))
    if sizes:
        groups = []
        for alg in ("512", "768"):
            groups.append((f"ML-KEM-{alg}", [int(sizes[p]["lib_flash"]) / 1024 if p in sizes else None
                                             for p in (f"size-pqclean{alg}", f"size-pqclean{alg}-O2", f"size-pqclean{alg}-Os")]))
        if any(v is not None for _, vals in groups for v in vals):
            svg_grouped(OUT / "pqclean_opt_flash.svg", "PQClean - Flash biblioteki vs poziom optymalizacji",
                        "Flash [KB]", groups, [(C_PQCLEAN, "-O3"), (C_CMOXKEM, "-O2"), (C_ECDH, "-Os")])
            charts.append(("pqclean_opt_flash.svg", "PQClean: Flash vs -O3/-O2/-Os"))

    md += ["## Wykresy", ""] + [f"![{t}]({f})" for f, t in charts] + [""]
    (OUT / "report.md").write_text("\n".join(md), encoding="utf-8")

    with open(OUT / "timing_all.csv", "w", newline="", encoding="utf-8") as f:
        fields = ["opt", "lib", "alg", "op", "ms", "iters", "cyc_min", "cyc_avg", "cyc_max",
                  "mhz", "stack", "heap", "wbuf", "err"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(timing_rows)

    print("\n".join(md))
    print(f"\nwritten: {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
