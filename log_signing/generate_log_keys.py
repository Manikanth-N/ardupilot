#!/usr/bin/env python3
"""
generate_log_keys.py
====================
Generate ArduPilot Secure Log keypair (Ed25519, Monocypher compatible).

No pip installs needed — pure Python stdlib only.
Identical output to pymonocypher==3.1.3.2.

Usage:
  python3 generate_log_keys.py SN-001
  python3 generate_log_keys.py SN-001 --from-dat  SN001_private_key.dat
  python3 generate_log_keys.py SN-001 --from-private "PRIVATE_KEYV1:..."
  python3 generate_log_keys.py SN-001 --from-hex   13aa65a9...
"""

import sys, os, hashlib, base64, json, secrets, argparse
from pathlib import Path

# ── Ed25519-Blake2b (identical to monocypher.compute_signing_public_key) ─────

_P = 2**255 - 19
_Q = 2**252 + 27742317777372353535851937790883648493
def _mi(x): return pow(x,_P-2,_P)
_d=(-121665*_mi(121666))%_P; _Gy=(4*_mi(5))%_P
def _rx(y,s):
    x2=(y*y-1)*_mi(_d*y*y+1)%_P; x=pow(x2,(_P+3)//8,_P)
    if (x*x-x2)%_P!=0: x=x*pow(2,(_P-1)//4,_P)%_P
    if x%2!=s: x=_P-x
    return x
_Gx=_rx(_Gy,0); _G=(_Gx,_Gy,1,_Gx*_Gy%_P)
def _pa(A,B):
    a,b=(A[1]-A[0])*(B[1]-B[0])%_P,(A[1]+A[0])*(B[1]+B[0])%_P
    c,d=2*A[3]*B[3]*_d%_P,2*A[2]*B[2]%_P; e,f,g,h=b-a,d-c,d+c,b+a
    return (e*f%_P,g*h%_P,f*g%_P,e*h%_P)
def _pm(s,Pt):
    R=None
    while s:
        if s&1: R=_pa(R,Pt) if R else Pt
        Pt=_pa(Pt,Pt); s>>=1
    return R
def _cp(Pt):
    zi=_mi(Pt[2]); x,y=Pt[0]*zi%_P,Pt[1]*zi%_P
    return int.to_bytes(y|((x&1)<<255),32,"little")
def _bh(*p):
    h=hashlib.blake2b(digest_size=64)
    for x in p: h.update(x)
    return h.digest()
def compute_signing_public_key(sk):
    h=_bh(sk); a=int.from_bytes(h[:32],"little")
    a=(a&~7)&~(128<<(8*31))|(64<<(8*31))
    return _cp(_pm(a,_G))

# ── Helpers ───────────────────────────────────────────────────────────────────

def encode_keyv1(label, key):
    return f"{label}_KEYV1:{base64.b64encode(key).decode()}"

def decode_keyv1(s):
    s = s.strip()
    if ":" not in s:
        raise ValueError(f"Expected LABEL_KEYV1:base64 — got: {s!r}")
    return base64.b64decode(s.split(":",1)[1])

def to_c_array(name, data):
    """
    Format as C array — exact format for AP_Logger_File.h:

    static const uint8_t SECURE_LOG_PRIVATE_KEY[32] = {
        0x13,0xaa,0x65,0xa9,0x28,0xd8,0xd3,0x62,
        0x23,0xc8,0xdc,0xc0,0x3e,0x39,0xb8,0x27,
        0xc4,0xbf,0x93,0xa8,0x25,0x43,0x07,0x63,
        0x2a,0xf5,0xd5,0x9e,0x8a,0xda,0xbb,0xf3,
    };
    """
    rows = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        rows.append("    " + ",".join(f"0x{b:02x}" for b in chunk) + ",")
    return (f"static const uint8_t {name}[{len(data)}] = {{\n"
            + "\n".join(rows) + "\n};")

def to_c_array_compact(name, data):
    """
    Alternate format — first row 4-space indent, remaining rows no indent.
    Matches the variant format used in some ArduPilot codebases.
    """
    rows = []
    for i in range(0, len(data), 8):
        chunk = data[i:i+8]
        vals  = ",".join(f"0x{b:02x}" for b in chunk) + ","
        indent = "    " if i == 0 else ""
        rows.append(f"{indent}{vals}")
    return (f"static const uint8_t {name}[{len(data)}] = {{\n"
            + "\n".join(rows) + "\n};" )

# ── Main ──────────────────────────────────────────────────────────────────────

SEP = "=" * 62

def run(serial, outdir, private_key=None):
    Path(outdir).mkdir(parents=True, exist_ok=True)

    if private_key is None:
        private_key = secrets.token_bytes(32)

    public_key = compute_signing_public_key(private_key)

    # ── Write files ──────────────────────────────────────────
    priv_dat = os.path.join(outdir, f"{serial}_log_private_key.dat")
    pub_dat  = os.path.join(outdir, f"{serial}_log_public_key.dat")
    pub_bin  = os.path.join(outdir, f"{serial}_log_public.bin")
    fleet_f  = os.path.join(outdir, "vehicles.json")

    Path(priv_dat).write_text(encode_keyv1("PRIVATE", private_key))
    Path(pub_dat ).write_text(encode_keyv1("PUBLIC",  public_key))
    Path(pub_bin ).write_bytes(public_key)

    fleet = {}
    if os.path.exists(fleet_f):
        try: fleet = json.loads(Path(fleet_f).read_text())
        except: pass
    fleet[serial] = {"log_public_key": public_key.hex()}
    Path(fleet_f).write_text(json.dumps(fleet, indent=2))

    # Write C array file — ready to paste into AP_Logger_File.h
    c_array_f = os.path.join(outdir, f"{serial}_log_private_key.h")
    c_content  = (
        f"// Vehicle  : {serial}\n"
        f"// Public   : {public_key.hex()}\n"
        f"//\n"
        f"// Format 1 — uniform indent (paste into AP_Logger_File.h)\n"
        + to_c_array("SECURE_LOG_PRIVATE_KEY", private_key)
        + "\n\n"
        f"// Format 2 — compact indent (alternate)\n"
        + to_c_array_compact("SECURE_LOG_PRIVATE_KEY", private_key)
        + "\n"
    )
    Path(c_array_f).write_text(c_content)

    # ── Print output ─────────────────────────────────────────
    print()
    print(SEP)
    print(f"  Vehicle : {serial}")
    print(SEP)

    print()
    print("── ArduPilot Key Strings ────────────────────────────────")
    print(encode_keyv1("PRIVATE", private_key))
    print(encode_keyv1("PUBLIC",  public_key))

    print()
    print("── Private Key — paste into AP_Logger_File.h ────────────")
    print(to_c_array("SECURE_LOG_PRIVATE_KEY", private_key))

    print()
    print("── Private Key (compact format) — alternate paste ────────")
    print(to_c_array_compact("SECURE_LOG_PRIVATE_KEY", private_key))

    print()
    print("── Public Key (hex) — submit to DGCA CB ─────────────────")
    print(public_key.hex())

    print()
    print("── Files ────────────────────────────────────────────────")
    print(f"  Private key  : {priv_dat}  ← keep secret")
    print(f"  Public key   : {pub_dat}")
    print(f"  Public (bin) : {pub_bin}   ← for verifier --pubkey")
    print(f"  C array file : {c_array_f}  ← paste into AP_Logger_File.h")
    print(f"  Fleet DB     : {fleet_f}")

    print()
    print("── Verify logs ──────────────────────────────────────────")
    print(f"  python3 verify_secure_log.py 00000001.BIN \\")
    print(f"      --pubkey {pub_bin}")
    print()
    print(f"  python3 verify_secure_log.py 00000001.BIN \\")
    print(f"      --fleet {fleet_f} --serial {serial}")
    print()
    print(SEP)


def main():
    ap = argparse.ArgumentParser(
        description="ArduPilot Secure Log Key Generator — no pip needed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 generate_log_keys.py SN-001
  python3 generate_log_keys.py SN-001 --from-dat SN001_log_private_key.dat
  python3 generate_log_keys.py SN-001 --from-private "PRIVATE_KEYV1:E6plq..."
  python3 generate_log_keys.py SN-001 --from-hex 13aa65a9...
  python3 generate_log_keys.py SN-001 --outdir /secure/keys/
        """)
    ap.add_argument("serial", help="Vehicle serial number e.g. SN-001")
    ap.add_argument("--outdir", default=".", help="Output directory")

    src = ap.add_mutually_exclusive_group()
    src.add_argument("--from-dat",     metavar="FILE",
                     help="Load from .dat file (PRIVATE_KEYV1:... text)")
    src.add_argument("--from-private", metavar="STRING",
                     help="Load from PRIVATE_KEYV1:<base64> string")
    src.add_argument("--from-hex",     metavar="HEX64",
                     help="Load from 64-char hex string")

    args = ap.parse_args()

    private_key = None
    if args.from_dat:
        private_key = decode_keyv1(Path(args.from_dat).read_text())
        print(f"Source  : {args.from_dat}")
    elif args.from_private:
        private_key = decode_keyv1(args.from_private)
        print("Source  : --from-private string")
    elif args.from_hex:
        h = args.from_hex.strip()
        if len(h) != 64:
            print(f"❌ Hex must be 64 chars (32 bytes), got {len(h)}")
            sys.exit(1)
        private_key = bytes.fromhex(h)
        print("Source  : --from-hex string")
    else:
        print("Source  : new random keypair")

    run(args.serial, args.outdir, private_key)

if __name__ == "__main__":
    main()