#!/usr/bin/env python3
"""
verify_secure_log.py
====================
ArduPilot Secure Log Verifier — DGCA CS-UAS Part 3 Clause 7.1

Implements Ed25519 with Blake2b internally (matching Monocypher crypto_sign).
No external dependencies — uses Python stdlib only (hashlib.blake2b).

Usage:
  # Hash chain only
  python3 verify_secure_log.py 00000001.BIN

  # With public key file (32 raw bytes)
  python3 verify_secure_log.py 00000001.BIN --pubkey SN001_pub.bin

  # With fleet database
  python3 verify_secure_log.py 00000001.BIN --fleet vehicles.json --serial SN-001

  # Verify entire logs directory
  python3 verify_secure_log.py /APM/logs/ --fleet vehicles.json --serial SN-001

  # Derive public key from private key (for testing)
  python3 verify_secure_log.py --derive-pubkey private_key.bin

No pip installs needed — pure Python stdlib.
"""

import sys, os, struct, hashlib, json, argparse, base64
from pathlib import Path

# ── Record layout ────────────────────────────────────────────────────────────
HEADER_SIZE       = 64
CHUNK_MAGIC       = 0x48434831   # "HCH1"
END_MAGIC         = 0x534C4F47   # "SLOG"
CHUNK_RECORD_SIZE = 44
END_RECORD_SIZE   = 101          # magic(4)+final_hash(32)+sig_len(1)+sig(64)

ALGORITHM_SHA256  = 1   # SHA-256 chain + Ed25519  (DGCA target)
ALGORITHM_BLAKE2B = 2   # Blake2b chain + Ed25519  (current firmware)

LINE = "=" * 64

# ── Ed25519 with Blake2b (matches Monocypher crypto_sign / crypto_check) ────
# Pure Python — no external dependencies.
# Reference: RFC 8032 with Blake2b-512 replacing SHA-512.

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493

def _modinv(x): return pow(x, _P - 2, _P)

_d   = -121665 * _modinv(121666) % _P
_Gy  = 4 * _modinv(5) % _P

def _recover_x(y, sign):
    x2 = (y*y - 1) * _modinv(_d*y*y + 1) % _P
    x  = pow(x2, (_P + 3) // 8, _P)
    if (x*x - x2) % _P != 0:
        x = x * pow(2, (_P - 1) // 4, _P) % _P
    if x % 2 != sign:
        x = _P - x
    return x

_Gx = _recover_x(_Gy, 0)
_G  = (_Gx, _Gy, 1, _Gx * _Gy % _P)

def _pt_add(A, B):
    a, b = (A[1]-A[0])*(B[1]-B[0])%_P, (A[1]+A[0])*(B[1]+B[0])%_P
    c, dd = 2*A[3]*B[3]*_d%_P, 2*A[2]*B[2]%_P
    e, f, g, h = b-a, dd-c, dd+c, b+a
    return (e*f%_P, g*h%_P, f*g%_P, e*h%_P)

def _pt_mul(s, P):
    R = None
    while s:
        if s & 1: R = _pt_add(R, P) if R else P
        P = _pt_add(P, P)
        s >>= 1
    return R

def _compress(P):
    zi = _modinv(P[2])
    x, y = P[0]*zi % _P, P[1]*zi % _P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def _decompress(b):
    y = int.from_bytes(b, "little")
    s = y >> 255
    y &= ~(1 << 255)
    x = _recover_x(y, s)
    return (x, y, 1, x*y % _P)

def _blake2b512(*parts):
    h = hashlib.blake2b(digest_size=64)
    for p in parts: h.update(p)
    return h.digest()

def ed25519_blake2b_public_key(sk32: bytes) -> bytes:
    """Derive 32-byte public key from 32-byte private key (Monocypher API)."""
    h = _blake2b512(sk32)
    a = int.from_bytes(h[:32], "little")
    a = (a & ~7) & ~(128 << (8*31)) | (64 << (8*31))
    return _compress(_pt_mul(a, _G))

def ed25519_blake2b_verify(pk32: bytes, sig64: bytes, msg: bytes) -> bool:
    """Verify Ed25519-Blake2b signature. Matches Monocypher crypto_check()."""
    if len(sig64) != 64 or len(pk32) != 32:
        return False
    try:
        R = _decompress(sig64[:32])
        A = _decompress(pk32)
    except Exception:
        return False
    Rb = _compress(R)
    k  = int.from_bytes(_blake2b512(Rb, pk32, msg), "little") % _Q
    S  = int.from_bytes(sig64[32:], "little")
    if S >= _Q:
        return False
    lhs = _compress(_pt_mul(S, _G))
    rhs = _compress(_pt_add(R, _pt_mul(k, A)))
    return lhs == rhs

# ── Hash chain ───────────────────────────────────────────────────────────────

def _chain_hash(algorithm: int, data: bytes, prev: bytes) -> bytes:
    if algorithm == ALGORITHM_SHA256:
        return hashlib.sha256(data + prev).digest()
    return hashlib.blake2b(data + prev, digest_size=32).digest()

def _header_hash(algorithm: int, data: bytes) -> bytes:
    if algorithm == ALGORITHM_SHA256:
        return hashlib.sha256(data).digest()
    return hashlib.blake2b(data, digest_size=32).digest()

# ── Verifier ─────────────────────────────────────────────────────────────────

def verify(path: str, pubkey_bytes: bytes = None) -> int:
    with open(path, "rb") as f:
        data = f.read()

    fname = os.path.basename(path)
    print(LINE)
    print(f"File     : {fname}")
    print(f"Size     : {len(data):,} bytes")
    print(LINE)

    # STEP 1 — HEADER
    print("\nSTEP 1 — HEADER")
    print("-" * 40)

    if len(data) < HEADER_SIZE:
        print("  ❌ File too small"); return 1

    if data[0] != 0xA5:
        print(f"  ❌ Not a secure log (magic=0x{data[0]:02X})"); return 2

    version   = data[1]
    algorithm = data[2]
    device_id = struct.unpack_from("<H", data, 4)[0]
    fw_ver    = struct.unpack_from("<H", data, 6)[0]
    timestamp = struct.unpack_from("<I", data, 8)[0]
    log_ctr   = struct.unpack_from("<H", data, 12)[0]
    H0_stored = bytes(data[16:48])

    algo_str = {
        ALGORITHM_SHA256:  "SHA-256 + Ed25519  ✅ DGCA",
        ALGORITHM_BLAKE2B: "Blake2b-256 + Ed25519",
    }.get(algorithm, f"Unknown ({algorithm})")

    print(f"  magic      : 0xA5  ✅")
    print(f"  version    : {version}")
    print(f"  algorithm  : {algorithm}  — {algo_str}")
    print(f"  device_id  : 0x{device_id:04X}")
    print(f"  firmware   : {fw_ver>>8}.{fw_ver&0xFF}")
    print(f"  timestamp  : {timestamp}")
    print(f"  log #      : {log_ctr}")

    H0_computed = _header_hash(algorithm, bytes(data[0:16]))
    h0_ok = H0_computed == H0_stored
    print(f"\n  H0 stored  : {H0_stored.hex()}")
    print(f"  H0 computed: {H0_computed.hex()}")
    print(f"  H0 match   : {'✅ YES' if h0_ok else '❌ NO — header tampered'}")

    if not h0_ok:
        print("\n  ❌ Header FAIL — aborting"); return 1

    # STEP 2 — HASH CHAIN
    hname = "SHA-256" if algorithm == ALGORITHM_SHA256 else "Blake2b-256"
    print(f"\nSTEP 2 — HASH CHAIN  (Hi = {hname}(chunk_i || H(i-1)))")
    print("-" * 40)

    prev      = H0_computed
    chunks    = 0
    pos       = HEADER_SIZE
    end_rec   = None
    errors    = []

    while pos <= len(data) - 4:
        m = struct.unpack_from("<I", data, pos)[0]

        if m == CHUNK_MAGIC:
            if pos + CHUNK_RECORD_SIZE > len(data):
                errors.append(f"Truncated chunk at {pos}"); break
            _, off, ln, stored = struct.unpack_from("<III32s", data, pos)
            if off + ln > len(data):
                errors.append(f"Chunk {chunks} out of range"); break
            computed = _chain_hash(algorithm, data[off:off+ln], prev)
            if computed != bytes(stored):
                errors.append(
                    f"Chunk {chunks} MISMATCH at offset {pos}\n"
                    f"    computed : {computed.hex()}\n"
                    f"    stored   : {bytes(stored).hex()}")
            prev    = computed
            chunks += 1
            pos    += CHUNK_RECORD_SIZE

        elif m == END_MAGIC:
            if pos + END_RECORD_SIZE > len(data):
                errors.append(f"Truncated end record at {pos}"); break
            fh  = bytes(data[pos+4:pos+36])
            sl  = data[pos+36]
            sig = bytes(data[pos+37:pos+37+sl])
            end_rec = (fh, sl, sig, pos)
            pos += END_RECORD_SIZE
        else:
            pos += 1

    print(f"  Chunks     : {chunks}")
    if not errors:
        print(f"  Result     : ✅ ALL {chunks} {hname} HASHES CORRECT")
    else:
        for e in errors: print(f"  ❌ {e}")

    # STEP 3 — END RECORD
    print(f"\nSTEP 3 — END RECORD")
    print("-" * 40)

    hash_match = sig_ok = sig_checked = False

    if end_rec is None:
        print("  ❌ NOT FOUND — log closed uncleanly")
        print(f"     Chain tail : {prev.hex()}")
    else:
        fh, sl, sig, rec_pos = end_rec
        hash_match = (fh == prev)

        print(f"  Offset     : {rec_pos:,}")
        print(f"  final_hash : {fh.hex()}")
        print(f"  chain tail : {prev.hex()}")
        print(f"  match      : {'✅ YES' if hash_match else '❌ NO'}")
        print(f"  sig_len    : {sl}")

        if sl == 0:
            print("  signature  : ⚠️  ABSENT — key not provisioned")
            print("               Hash chain integrity proven.")
            print("               Provision Sector1/OTP for device binding.")
        elif sl == 64:
            print(f"  signature  : {sig.hex()[:48]}...")
            if pubkey_bytes is not None:
                sig_checked = True
                sig_ok = ed25519_blake2b_verify(pubkey_bytes, sig, fh)
                result_str = "✅ VALID" if sig_ok else "❌ INVALID"
                print(f"  Ed25519    : {result_str}")
                if not sig_ok:
                    print("               Signature does not match public key.")
                    print("               Check: correct vehicle key? firmware updated?")
            else:
                print("  Ed25519    : ⚠️  No public key — use --pubkey or --fleet")
        else:
            print(f"  ❌ Unexpected sig_len={sl}")

    # STEP 4 — RESULT
    print(f"\n{LINE}")
    print("OVERALL RESULT")
    print(LINE)

    has_end = end_rec is not None
    has_sig = has_end and end_rec[1] == 64

    if not h0_ok or errors:
        print("  ❌ FAIL — LOG TAMPERED")
        result = 1
    elif not has_end:
        print("  ⚠️  INCOMPLETE — chain intact, no end record")
        result = 0
    elif not hash_match:
        print("  ❌ FAIL — End record final_hash mismatch")
        result = 1
    elif not has_sig:
        print("  ⚠️  CHAIN PASS — no signature (key not provisioned)")
        print("     Data integrity proven. Device binding: NOT verified.")
        result = 0
    elif has_sig and not sig_checked:
        print("  ✅ CHAIN PASS — signature present, not verified")
        print("     Use --pubkey or --fleet for device binding verification.")
        result = 0
    elif has_sig and sig_checked and sig_ok:
        print("  ✅ FULL PASS — DGCA compliant")
        print(f"     Algorithm : {algo_str}")
        print(f"     Chunks    : {chunks}")
        print(f"     Signature : verified ✅")
        result = 0
    else:
        print("  ❌ FAIL — Signature invalid")
        result = 1

    print(f"\n  File       : {path}")
    print(f"  Chunks     : {chunks}")
    print(f"  Device ID  : 0x{device_id:04X}")
    print(f"  Firmware   : {fw_ver>>8}.{fw_ver&0xFF}")
    print()
    return result


def derive_pubkey(privkey_path: str):
    """Derive and print public key from a 32-byte private key file."""
    with open(privkey_path, "rb") as f:
        sk = f.read(32)
    pk = ed25519_blake2b_public_key(sk)
    pubkey_path = privkey_path.replace("_private", "_public").replace(
        "priv", "pub").replace("private", "public")
    if pubkey_path == privkey_path:
        pubkey_path = privkey_path + ".pub"
    with open(pubkey_path, "wb") as f:
        f.write(pk)
    print(f"Private key : {sk.hex()}")
    print(f"Public key  : {pk.hex()}")
    print(f"Written to  : {pubkey_path}")


def load_pubkey_file(path: str) -> bytes:
    """
    Load a 32-byte public key from either:
      - .bin file  : 32 raw bytes
      - .dat file  : text file containing PUBLIC_KEYV1:<base64>
                     (output of generate_keys.py or generate_log_keys.py)
    """
    content = open(path, "rb").read()

    # Detect .dat text file: starts with "PUBLIC_KEYV1:" or "PRIVATE_KEYV1:"
    try:
        text = content.decode("utf-8").strip()
        if "KEYV1:" in text:
            _, b64 = text.split(":", 1)
            key = base64.b64decode(b64)
            if len(key) == 32:
                return key
            raise ValueError(
                f"Key in {path} is {len(key)} bytes, expected 32")
    except (UnicodeDecodeError, ValueError):
        pass

    # Raw binary fallback
    if len(content) < 32:
        raise ValueError(
            f"Binary key file {path} is {len(content)} bytes, expected 32")
    return content[:32]


def load_fleet_pubkey(fleet: str, serial: str) -> bytes:
    with open(fleet) as f: db = json.load(f)
    if serial not in db:
        avail = list(db.keys())
        raise KeyError(f"Serial '{serial}' not in {fleet}. Available: {avail}")
    return bytes.fromhex(db[serial]["log_public_key"])


def verify_dir(dir_path: str, pubkey: bytes = None) -> int:
    bins = sorted(Path(dir_path).glob("*.BIN")) or \
           sorted(Path(dir_path).glob("*.bin"))
    if not bins:
        print(f"No .BIN files in {dir_path}"); return 1
    results = {}
    for b in bins:
        print(f"\n{'#'*66}")
        results[b.name] = verify(str(b), pubkey)
    print(f"\n{'#'*66}")
    print(f"DIRECTORY SUMMARY: {dir_path}")
    print(f"{'#'*66}")
    for name, r in results.items():
        print(f"  {'✅' if r==0 else '❌'}  {name}")
    passed = sum(1 for r in results.values() if r == 0)
    print(f"\n  Total: {len(results)}   Pass: {passed}   "
          f"Fail: {len(results)-passed}")
    return 0 if all(r==0 for r in results.values()) else 1


def main():
    ap = argparse.ArgumentParser(
        description="ArduPilot Secure Log Verifier — DGCA CS-UAS Part 3",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Chain integrity only (no signature check)
  python3 verify_secure_log.py 00000001.BIN

  # With public key file (32 raw bytes)
  python3 verify_secure_log.py 00000001.BIN --pubkey SN001_pub.bin

  # With fleet database (vehicles.json)
  python3 verify_secure_log.py 00000001.BIN \\
      --fleet vehicles.json --serial SN-001

  # All logs in a directory
  python3 verify_secure_log.py /APM/logs/ \\
      --fleet vehicles.json --serial SN-001

  # Derive public key from private key (for setup/testing)
  python3 verify_secure_log.py --derive-pubkey SN001_priv.bin

vehicles.json format:
  {
    "SN-001": {"log_public_key": "<64 hex chars = 32 bytes>"},
    "SN-002": {"log_public_key": "<64 hex chars = 32 bytes>"}
  }

Note: Uses Ed25519 with Blake2b internally (Monocypher crypto_sign).
      No pip installs needed — pure Python stdlib only.
        """)
    ap.add_argument("path", nargs="?",
                    help=".BIN file or directory of .BIN files")
    ap.add_argument("--pubkey", default=None,
                    help="Public key file: .bin (32 raw bytes) or "
                         ".dat (PUBLIC_KEYV1:<base64> text from generate_log_keys.py)")
    ap.add_argument("--fleet", default=None,
                    help="vehicles.json fleet database")
    ap.add_argument("--serial", default=None,
                    help="Vehicle serial number (use with --fleet)")
    ap.add_argument("--derive-pubkey", default=None, metavar="PRIVKEY",
                    help="Derive public key from 32-byte private key file")
    args = ap.parse_args()

    # Derive mode
    if args.derive_pubkey:
        derive_pubkey(args.derive_pubkey)
        sys.exit(0)

    if not args.path:
        ap.print_help(); sys.exit(1)

    # Load public key
    pubkey = None
    if args.pubkey:
        pubkey = load_pubkey_file(args.pubkey)
        print(f"Public key  : {pubkey.hex()}  (from {args.pubkey})")
    elif args.fleet and args.serial:
        try:
            pubkey = load_fleet_pubkey(args.fleet, args.serial)
            print(f"Public key  : {pubkey.hex()}  (fleet: {args.serial})")
        except Exception as e:
            print(f"❌ {e}"); sys.exit(1)
    elif args.fleet and not args.serial:
        print("❌ --fleet requires --serial"); sys.exit(1)

    if os.path.isdir(args.path):
        sys.exit(verify_dir(args.path, pubkey))
    else:
        sys.exit(verify(args.path, pubkey))


if __name__ == "__main__":
    main()