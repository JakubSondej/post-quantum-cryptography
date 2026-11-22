#!/usr/bin/env python3
"""
qlink v1 - PC side of the post-quantum link with the STM32F446RE.

  KEM : ML-KEM-768 (FIPS 203)  - kyber-py (pure Python)
  KDF : HKDF-SHA256            - cryptography
  AEAD: AES-256-GCM            - cryptography
  Transport: serial port (ST-LINK VCP); a TCP transport can be added for Ethernet.

Protocol: see Core/Src/kem_link.c (header comment). Summary:
  frame = A5 5A | type | len(2,LE) | payload | CRC-16/CCITT-FALSE(2,LE)
  role "pc"  (0): PC keygen  -> sends PK,  MCU encapsulates -> CT
  role "mcu" (1): MCU keygen -> sends PK,  PC encapsulates  -> CT
  keys = HKDF-SHA256(ss, salt=SHA-256(pk||ct), info="qlink-v1 aes-256-gcm", 64 B)

Usage:
  pip install -r tools/requirements.txt
  python tools/pc_link.py --port COM20                 # interactive, role pc
  python tools/pc_link.py --port COM20 --role mcu      # MCU generates the keys
  python tools/pc_link.py --port COM20 --selftest 10   # automatic test + timing CSV

Interactive commands: /rekey, /role pc|mcu, /quit ; any other line is sent
encrypted. The STM32 understands "led on", "led off", "stats", "uid" and
echoes everything else.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import os
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path

try:
    import serial                                          # pyserial
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from kyber_py.ml_kem import ML_KEM_768
except ImportError as e:  # pragma: no cover
    sys.exit(f"missing package ({e.name}); run: pip install -r tools/requirements.txt")

SYNC = b"\xA5\x5A"
T_HELLO, T_HELLO_ACK, T_PK, T_CT, T_DATA, T_STAT, T_ERR = 0x01, 0x81, 0x02, 0x03, 0x10, 0x20, 0x7F
ROLE = {"pc": 0, "mcu": 1}
VERSION = 1
PK_LEN, CT_LEN = 1184, 1088
KDF_INFO = b"qlink-v1 aes-256-gcm"
DIR_PC2MCU, DIR_MCU2PC = 1, 2


def crc16_ccitt(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


# ------------------------------------------------------------- transport ---
class SerialTransport:
    def __init__(self, port: str, baud: int):
        self.s = serial.Serial(port, baud, timeout=0.05)
        time.sleep(0.1)
        self.s.reset_input_buffer()

    def write(self, data: bytes) -> None:
        self.s.write(data)
        self.s.flush()

    def read(self, n: int) -> bytes:
        # return as soon as anything arrived (read(n) alone would wait for n bytes
        # or the full timeout and add up to 50 ms to every round trip)
        return self.s.read(min(n, max(1, self.s.in_waiting)))

    def close(self) -> None:
        self.s.close()


class Link:
    def __init__(self, tr, verbose: bool = True):
        self.tr = tr
        self.verbose = verbose
        self.buf = bytearray()
        self.stats: list[dict] = []
        self.last_data_stat: dict = {}

    # framing --------------------------------------------------------------
    def send(self, ftype: int, payload: bytes = b"") -> None:
        hdr = struct.pack("<BH", ftype, len(payload))
        crc = crc16_ccitt(hdr + payload)
        self.tr.write(SYNC + hdr + payload + struct.pack("<H", crc))

    def recv(self, timeout: float = 5.0) -> tuple[int, bytes]:
        """Next frame that is not STAT/ERR (those are printed and stored)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            frame = self._try_parse()
            if frame is None:
                chunk = self.tr.read(4096)
                if chunk:
                    self.buf += chunk
                continue
            ftype, payload = frame
            if ftype == T_STAT:
                text = payload.decode(errors="replace")
                kv = dict(x.split("=", 1) for x in text.split() if "=" in x)
                self.stats.append(kv)
                if self.verbose:
                    print(f"  [STM32 stat] {text}")
                continue
            if ftype == T_ERR:
                raise RuntimeError(f"STM32 error: {payload.decode(errors='replace')}")
            return ftype, payload
        raise TimeoutError("no answer from STM32 (port, baud, firmware APP_MODE=LINK?)")

    def wait_stat(self, op: str, timeout: float = 2.0) -> dict:
        """Wait for the STAT frame with op=<op> (the MCU sends it after its DATA reply)."""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            frame = self._try_parse()
            if frame is None:
                chunk = self.tr.read(4096)
                if chunk:
                    self.buf += chunk
                continue
            ftype, payload = frame
            if ftype == T_ERR:
                raise RuntimeError(f"STM32 error: {payload.decode(errors='replace')}")
            if ftype == T_STAT:
                text = payload.decode(errors="replace")
                kv = dict(x.split("=", 1) for x in text.split() if "=" in x)
                self.stats.append(kv)
                if self.verbose:
                    print(f"  [STM32 stat] {text}")
                if kv.get("op") == op:
                    return kv
        return {}

    def _try_parse(self):
        i = self.buf.find(SYNC)
        if i < 0:
            del self.buf[:-1]
            return None
        del self.buf[:i]
        if len(self.buf) < 5:
            return None
        ftype, length = struct.unpack_from("<BH", self.buf, 2)
        if length > 4096:
            del self.buf[:2]
            return None
        if len(self.buf) < 7 + length:
            return None
        body = bytes(self.buf[2:5 + length])
        crc = struct.unpack_from("<H", self.buf, 5 + length)[0]
        del self.buf[:7 + length]
        if crc16_ccitt(body) != crc:
            print("  [warn] CRC error, frame dropped")
            return None
        return ftype, body[3:]


@dataclass
class Session:
    k_pc2mcu: bytes
    k_mcu2pc: bytes
    seq_tx: int = 0
    seq_rx: int = 0


def derive(ss: bytes, pk: bytes, ct: bytes) -> Session:
    th = hashlib.sha256(pk + ct).digest()
    okm = HKDF(algorithm=hashes.SHA256(), length=64, salt=th, info=KDF_INFO).derive(ss)
    return Session(okm[:32], okm[32:])


def nonce(direction: int, seq: int) -> bytes:
    return struct.pack(">I", direction) + struct.pack("<Q", seq)


def handshake(link: Link, role: str) -> tuple[Session, dict]:
    t = {"role": role}
    t0 = time.perf_counter()
    link.send(T_HELLO, bytes([VERSION, ROLE[role]]) + os.urandom(16))
    ftype, p = link.recv()
    if ftype != T_HELLO_ACK or p[0] != VERSION or p[1] != ROLE[role]:
        raise RuntimeError(f"bad HELLO_ACK ({ftype:#x})")
    alg = p[18:].decode(errors="replace")

    if role == "pc":
        c0 = time.perf_counter()
        ek, dk = ML_KEM_768.keygen()
        t["pc_kem_ms"] = (time.perf_counter() - c0) * 1000
        link.send(T_PK, ek)
        ftype, ct = link.recv()
        if ftype != T_CT or len(ct) != CT_LEN:
            raise RuntimeError("expected CT")
        c0 = time.perf_counter()
        ss = ML_KEM_768.decaps(dk, ct)
        t["pc_kem_ms"] += (time.perf_counter() - c0) * 1000
        pk = ek
    else:
        ftype, pk = link.recv()
        if ftype != T_PK or len(pk) != PK_LEN:
            raise RuntimeError("expected PK")
        c0 = time.perf_counter()
        ss, ct = ML_KEM_768.encaps(pk)
        t["pc_kem_ms"] = (time.perf_counter() - c0) * 1000
        link.send(T_CT, ct)

    sess = derive(ss, pk, ct)
    # key confirmation: first DATA from the MCU must decrypt with the new key
    ftype, p = link.recv()
    if ftype != T_DATA:
        raise RuntimeError("expected confirmation DATA")
    msg = decrypt(sess, p)
    if not msg.startswith(b"SESSION-OK"):
        raise RuntimeError(f"bad confirmation: {msg!r}")
    t["total_ms"] = (time.perf_counter() - t0) * 1000
    mcu = next((s for s in reversed(link.stats) if s.get("op") in ("encaps", "decaps")), {})
    kg = next((s for s in reversed(link.stats) if s.get("op") == "keygen"), {}) if role == "mcu" else {}
    t["mcu_op"] = ("keygen+decaps" if role == "mcu" else "encaps")
    t["mcu_kem_us"] = int(mcu.get("kem_us", 0)) + int(kg.get("kem_us", 0))
    t["mcu_kdf_us"] = int(mcu.get("kdf_us", 0))
    t["bytes"] = PK_LEN + CT_LEN
    t["alg"] = alg
    return sess, t


def decrypt(sess: Session, p: bytes) -> bytes:
    seq = struct.unpack_from("<Q", p)[0]
    if seq <= sess.seq_rx:
        raise RuntimeError("replayed/old sequence number from STM32")
    aad = bytes([T_DATA]) + p[:8]
    msg = AESGCM(sess.k_mcu2pc).decrypt(nonce(DIR_MCU2PC, seq), p[8:], aad)
    sess.seq_rx = seq
    return msg


def send_message(link: Link, sess: Session, text: bytes) -> tuple[bytes, float]:
    sess.seq_tx += 1
    seqb = struct.pack("<Q", sess.seq_tx)
    ct = AESGCM(sess.k_pc2mcu).encrypt(nonce(DIR_PC2MCU, sess.seq_tx), text, bytes([T_DATA]) + seqb)
    t0 = time.perf_counter()
    link.send(T_DATA, seqb + ct)
    ftype, p = link.recv()
    rtt = (time.perf_counter() - t0) * 1000
    if ftype != T_DATA:
        raise RuntimeError("expected DATA reply")
    reply = decrypt(sess, p)
    link.last_data_stat = link.wait_stat("data")   # AES-GCM timings of this message
    return reply, rtt


# ------------------------------------------------------------------ modes ---
def interactive(link: Link, role: str) -> None:
    sess, t = handshake(link, role)
    print(f"Session ready ({t['alg']}), role={role}, handshake {t['total_ms']:.0f} ms "
          f"(STM32 {t['mcu_op']} {t['mcu_kem_us'] / 1000:.2f} ms). Type a message, /help for commands.")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not line:
            continue
        if line in ("/quit", "/q"):
            return
        if line == "/help":
            print("/rekey  /role pc|mcu  /quit ; STM32 commands: led on, led off, stats, uid")
            continue
        if line.startswith("/role"):
            parts = line.split()
            if len(parts) == 2 and parts[1] in ROLE:
                role = parts[1]
                line = "/rekey"
            else:
                print("usage: /role pc|mcu")
                continue
        if line == "/rekey":
            sess, t = handshake(link, role)
            print(f"New session, role={role}, handshake {t['total_ms']:.0f} ms")
            continue
        reply, rtt = send_message(link, sess, line.encode())
        print(f"< {reply.decode(errors='replace')}   ({rtt:.0f} ms)")


def selftest(link: Link, n: int, out: Path) -> None:
    rows, msg_rows = [], []
    link.verbose = False
    for i in range(n):
        role = "pc" if i % 2 == 0 else "mcu"
        sess, t = handshake(link, role)
        rows.append(t)
        print(f"handshake {i + 1:2d} role={role:3s} total={t['total_ms']:7.1f} ms  "
              f"STM32 {t['mcu_op']}={t['mcu_kem_us'] / 1000:6.2f} ms kdf={t['mcu_kdf_us'] / 1000:.2f} ms  "
              f"PC kem={t['pc_kem_ms']:6.2f} ms")
        for size in (16, 256, 1000):
            text = (f"msg{i}-".encode() * 200)[:size]
            reply, rtt = send_message(link, sess, text)
            st = link.last_data_stat
            if not reply.startswith(b"STM32 received"):
                raise RuntimeError(f"unexpected reply {reply[:40]!r}")
            msg_rows.append({"handshake": i + 1, "size": size, "rtt_ms": round(rtt, 2),
                             "mcu_dec_us": st.get("dec_us"), "mcu_enc_us": st.get("enc_us"),
                             "mcu_tx_len": st.get("tx_len")})
    out.mkdir(parents=True, exist_ok=True)
    with open(out / "handshakes.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["role", "mcu_op", "mcu_kem_us", "mcu_kdf_us", "pc_kem_ms",
                                          "total_ms", "bytes", "alg"])
        w.writeheader()
        for r in rows:
            w.writerow({k: (round(v, 2) if isinstance(v, float) else v) for k, v in r.items()})
    with open(out / "messages.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(msg_rows[0].keys()))
        w.writeheader()
        w.writerows(msg_rows)
    for role in ("pc", "mcu"):
        rs = [r for r in rows if r["role"] == role]
        if rs:
            avg = lambda k: sum(r[k] for r in rs) / len(rs)
            print(f"avg role={role}: total {avg('total_ms'):.1f} ms, STM32 {rs[0]['mcu_op']} "
                  f"{avg('mcu_kem_us') / 1000:.2f} ms, PC ML-KEM {avg('pc_kem_ms'):.2f} ms")
    for size in (16, 256, 1000):
        ms_ = [m for m in msg_rows if m["size"] == size]
        print(f"message {size:4d} B: RTT {sum(m['rtt_ms'] for m in ms_) / len(ms_):6.1f} ms, "
              f"STM32 AES-GCM decrypt {ms_[0]['mcu_dec_us']} us, encrypt reply {ms_[0]['mcu_enc_us']} us")
    print(f"SELFTEST OK - written {out / 'handshakes.csv'}, {out / 'messages.csv'}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True, help="serial port, e.g. COM20")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--role", choices=ROLE, default="pc", help="pc: PC generates keys; mcu: STM32 generates keys")
    ap.add_argument("--selftest", type=int, metavar="N", help="run N handshakes (alternating roles) + messages")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "tests" / "link"))
    a = ap.parse_args()

    link = Link(SerialTransport(a.port, a.baud))
    try:
        if a.selftest:
            selftest(link, a.selftest, Path(a.out))
        else:
            interactive(link, a.role)
    except (RuntimeError, TimeoutError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    finally:
        link.tr.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
