#!/usr/bin/env python3
"""
metadata_gen.py — Firmware + Parameter Metadata Generator / Verifier

Metadata Layout (92 bytes, little-endian)

  Offset  Size   Field
       0     4   magic          0xDEADBEEF
       4     4   fw_size        byte length of the firmware binary
       8     4   fw_start_addr  flash address where firmware is programmed
      12    32   fw_sha256      SHA-256 of the raw firmware binary
      44    32   param_sha256   SHA-256 of the canonical parameter serialisation
      76     4   version        metadata format version (currently 1)
      80     4   flags          reserved, set to 0
      84     4   build_ts       Unix timestamp of generation (uint32)
      88     4   meta_crc32     CRC-32 of bytes 0–87 (the body above)
     ---    --
      92         TOTAL

Usage
-----
  # Generate:
  python3 metadata_gen.py generate \\
      --firmware   arducopter.bin  \\
      --params     sim_params.params \\
      --whitelist  whitelist.txt \\
      --output     metadata.bin

  # Verify:
  python3 metadata_gen.py verify \\
      --metadata   metadata.bin \\
      --firmware   arducopter.bin \\
      --params     sim_params.params \\
      --whitelist  whitelist.txt

Canonical parameter serialisation (MUST match AP_ParamIntegrity::format_entry())
----------------------------------------------------------------------------------
  Entries are sorted in ASCII-ascending (strcmp / Python str sort) order.
  One entry per line:
      NAME=VALUE\\n
  Every line — including the last — ends with \\n (0x0A).
  No blank lines, no comments, no BOM.

  VALUE formatting rules (identical to firmware format_entry()):
    AP_INT8/16/32 or float with no fractional part  →  decimal integer  "1"
    float with fractional part (|frac| >= 1e-6)     →  "%.6f"           "0.135000"

Supported .params file formats
-------------------------------
  1. Mission Planner CSV:    NAME,VALUE[,...]   (comma-separated)
  2. QGC / plain whitespace: NAME VALUE
  3. ArduPilot onboard export (4 or 5 columns):
       SYSID COMPID NAME VALUE [TYPE]
     First two fields must be decimal integers.

  Inline comments (# ...) are stripped from every field.
  Lines beginning with # and blank lines are ignored.

Whitelist file format
---------------------
  One parameter name per line.
  Lines beginning with # and blank lines are ignored.
  Inline comments (# ...) are stripped.
  Entries need not be pre-sorted; the tool sorts them internally.
"""

import argparse
import binascii
import hashlib
import os
import struct
import sys
import time


# =============================================================================
#  Constants
# =============================================================================

METADATA_MAGIC   = 0xDEADBEEF
METADATA_VERSION = 1
METADATA_FLAGS   = 0

BOOTLOADER_ADDRESS = 0x08000000
METADATA_ADDRESS   = 0x08020000
FW_START_ADDRESS   = 0x08040000   # default; overridable with --fw-addr

# Struct formats (little-endian)
#   body  = everything except the trailing CRC
#   full  = body + CRC
STRUCT_BODY_FMT = "<II32sIII32sI"   # magic,fw_size,fw_sha256,version,flags,fw_start_addr,param_sha256,build_ts
STRUCT_FULL_FMT = "<II32sIII32sII"  # body + meta_crc32

STRUCT_BODY_SIZE = struct.calcsize(STRUCT_BODY_FMT)   # must be 88
STRUCT_FULL_SIZE = struct.calcsize(STRUCT_FULL_FMT)   # must be 92

assert STRUCT_BODY_SIZE == 88, f"body size {STRUCT_BODY_SIZE} != 88"
assert STRUCT_FULL_SIZE == 92, f"full size {STRUCT_FULL_SIZE} != 92"


# =============================================================================
#  Param file parsing
# =============================================================================

def _strip_inline_comment(s: str) -> str:
    """Remove everything from the first '#' onward, then strip whitespace."""
    idx = s.find('#')
    if idx != -1:
        s = s[:idx]
    return s.strip()


def parse_param_file(path: str) -> dict:
    """
    Parse a .params file into a {NAME: value_string} dict.

    Supports three formats (auto-detected per line):
      1. CSV (Mission Planner):          NAME,VALUE[,...]
      2. ArduPilot onboard export:       SYSID COMPID NAME VALUE [TYPE]
         (first two whitespace fields are decimal integers)
      3. Plain whitespace (QGC / plain): NAME VALUE

    Inline comments and trailing whitespace are stripped from every token.
    Duplicate names: last occurrence wins (matches GCS/MP behaviour).
    """
    params: dict[str, str] = {}

    with open(path, 'r', encoding='utf-8') as fh:
        for raw in fh:
            line = _strip_inline_comment(raw)
            if not line:
                continue

            # ── Format 1: CSV ────────────────────────────────────────────────
            if ',' in line:
                parts = [_strip_inline_comment(p) for p in line.split(',')]
                if len(parts) >= 2 and parts[0] and parts[1]:
                    params[parts[0]] = parts[1]
                continue

            # ── Whitespace formats ───────────────────────────────────────────
            parts = line.split()

            # Format 2: ArduPilot export — SYSID COMPID NAME VALUE [TYPE]
            # Detect by checking first two tokens are plain decimal integers.
            if (len(parts) >= 4
                    and parts[0].lstrip('-').isdigit()
                    and parts[1].lstrip('-').isdigit()):
                params[parts[2]] = parts[3]
                continue

            # Format 3: plain NAME VALUE
            if len(parts) == 2:
                params[parts[0]] = parts[1]
                continue

            # Single-token lines (no value) are silently skipped; a missing
            # param will be caught later by build_canonical_param_blob.

    return params


def load_whitelist(path: str) -> list:
    """
    Load a whitelist file into a sorted list of parameter name strings.

    One name per line.  Inline comments and blank lines are stripped.
    The returned list is always in ASCII-ascending (strcmp) order,
    matching the sort used by the firmware's _whitelist[] and
    param_checksum_gen.py.
    """
    names: list[str] = []

    with open(path, 'r', encoding='utf-8') as fh:
        for raw in fh:
            name = _strip_inline_comment(raw)
            if not name:
                continue
            # Names must be uppercase; normalise and warn rather than silently
            # accepting mixed-case entries that would never match AP_Param.
            normalised = name.upper()
            if normalised != name:
                print(
                    f"WARNING: whitelist name {name!r} normalised to "
                    f"{normalised!r}",
                    file=sys.stderr,
                )
            names.append(normalised)

    # Sort in ASCII-ascending order — identical to Python's default str sort
    # for all-uppercase names, and identical to C strcmp on the same strings.
    return sorted(names)


# =============================================================================
#  Canonical value formatting
# =============================================================================

def canonicalize_value(raw: str) -> str:
    """
    Format a parameter value string according to the canonical rules.

    Must produce byte-for-byte identical output to AP_ParamIntegrity::format_entry().

    Rules:
      |frac| < 1e-6  →  decimal integer string, e.g.  "1"
      otherwise       →  "%.6f" string,          e.g.  "0.135000"

    Note on int() truncation:
      Python int() and C (int) cast both truncate toward zero, so
      int(-1.9999997) == -1 in both languages.  This is consistent.

    Note on float precision:
      raw is parsed as a Python float (64-bit double).  The firmware
      reads the AP_Param value as a 32-bit float then casts to double
      for snprintf.  At %.6f precision the outputs agree for all values
      in the practical ArduPilot parameter range.
    """
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"Non-numeric parameter value: {raw!r}")

    frac = val - int(val)       # fractional part; sign matches val
    if abs(frac) < 1e-6:
        return str(int(val))    # integer representation, no decimal point
    return f"{val:.6f}"         # 6 decimal places, C-locale dot separator


# =============================================================================
#  Canonical blob construction
# =============================================================================

def build_canonical_param_blob(params: dict, whitelist: list) -> bytes:
    """
    Build the canonical UTF-8 byte string fed to SHA-256.

    Contract (must match firmware AP_ParamIntegrity::check()):
      • Entries in the order supplied by whitelist (caller must pass a sorted list).
      • Each entry on its own line:  NAME=VALUE\\n
      • Every line ends with \\n — including the last entry.
      • No blank lines, no comments.

    Raises KeyError if a whitelisted name is absent from params.
    """
    lines = []
    for name in whitelist:
        if name not in params:
            raise KeyError(
                f"Parameter {name!r} is in the whitelist but not in the "
                f"supplied .params file"
            )
        value = canonicalize_value(params[name])
        lines.append(f"{name}={value}\n")   # \\n after every entry, including last

    return "".join(lines).encode('utf-8')


# =============================================================================
#  SHA-256 helpers
# =============================================================================

def compute_param_sha256(param_file: str,
                          whitelist_file: str) -> tuple:
    """
    Returns (digest: bytes[32], canonical_blob: bytes).

    The whitelist is loaded and sorted inside load_whitelist(), so the
    caller's whitelist file order does not affect the digest.
    """
    params    = parse_param_file(param_file)
    whitelist = load_whitelist(whitelist_file)   # already sorted
    blob      = build_canonical_param_blob(params, whitelist)
    return hashlib.sha256(blob).digest(), blob


def compute_firmware_sha256(firmware_path: str) -> tuple:
    """Returns (digest: bytes[32], fw_size: int)."""
    with open(firmware_path, 'rb') as fh:
        data = fh.read()
    if not data:
        raise RuntimeError(f"Firmware file is empty: {firmware_path}")
    return hashlib.sha256(data).digest(), len(data)


# =============================================================================
#  CRC-32
# =============================================================================

def compute_meta_crc32(body: bytes) -> int:
    """CRC-32 of the 88-byte metadata body (before the CRC field itself)."""
    return binascii.crc32(body) & 0xFFFF_FFFF


# =============================================================================
#  Generate
# =============================================================================

def generate_metadata(firmware_path: str,
                       param_path: str,
                       whitelist_path: str,
                       output_path: str,
                       fw_start_addr: int) -> None:

    # ── Compute inputs ────────────────────────────────────────────────────────
    fw_sha,    fw_size       = compute_firmware_sha256(firmware_path)
    param_sha, canonical_blob = compute_param_sha256(param_path, whitelist_path)
    build_ts = int(time.time())

    # ── Pack body (88 bytes) ──────────────────────────────────────────────────
    body = struct.pack(
        STRUCT_BODY_FMT,
        METADATA_MAGIC,       # offset  0
        fw_size,              # offset  4
        fw_sha,               # offset  8  ← bootloader sha256 field
        METADATA_VERSION,     # offset 40  ← bootloader version field
        METADATA_FLAGS,       # offset 44  ← bootloader flags field
        fw_start_addr,        # offset 48  ← extension start
        param_sha,            # offset 52
        build_ts,             # offset 84
    )
    assert len(body) == STRUCT_BODY_SIZE

    # ── Append CRC-32 ─────────────────────────────────────────────────────────
    crc      = compute_meta_crc32(body)
    metadata = body + struct.pack("<I", crc)
    assert len(metadata) == STRUCT_FULL_SIZE

    # ── Write output (warn if overwriting) ───────────────────────────────────
    if os.path.exists(output_path):
        print(f"WARNING: overwriting existing file: {output_path}", file=sys.stderr)

    with open(output_path, 'wb') as fh:
        fh.write(metadata)

    # ── Print report ──────────────────────────────────────────────────────────
    print("\n=== CANONICAL PARAM INPUT ===")
    print(canonical_blob.decode('utf-8'), end='')

    print("\n=== HASHES ===")
    print(f"Firmware SHA-256 : {fw_sha.hex().upper()}")
    print(f"Param    SHA-256 : {param_sha.hex().upper()}")

    print("\n=== METADATA ===")
    print(f"Output           : {output_path}")
    print(f"Size             : {len(metadata)} bytes")
    print(f"CRC-32           : 0x{crc:08X}")
    print(f"Build timestamp  : {build_ts}  ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(build_ts))})")

    print("\n=== FLASH LAYOUT ===")
    print(f"Bootloader       : 0x{BOOTLOADER_ADDRESS:08X}")
    print(f"Metadata sector  : 0x{METADATA_ADDRESS:08X}")
    print(f"Firmware start   : 0x{fw_start_addr:08X}")


# =============================================================================
#  Verify
# =============================================================================

def verify_metadata(metadata_path: str,
                     firmware_path: str,
                     param_path: str,
                     whitelist_path: str,
                     fw_start_addr: int) -> bool:

    # ── Read metadata file ────────────────────────────────────────────────────
    with open(metadata_path, 'rb') as fh:
        raw = fh.read()

    if len(raw) != STRUCT_FULL_SIZE:
        print(f"FAIL : Metadata file size {len(raw)} != {STRUCT_FULL_SIZE}")
        return False

    body        = raw[:STRUCT_BODY_SIZE]
    stored_crc  = struct.unpack("<I", raw[STRUCT_BODY_SIZE:])[0]
    computed_crc = compute_meta_crc32(body)

    (
        magic,
        stored_fw_size,
        stored_fw_sha,        # offset  8
        version,              # offset 40
        flags,                # offset 44
        stored_fw_addr,       # offset 48
        stored_param_sha,     # offset 52
        build_ts,             # offset 84
    ) = struct.unpack(STRUCT_BODY_FMT, body)

    # ── Recompute live values ─────────────────────────────────────────────────
    current_fw_sha,    current_fw_size = compute_firmware_sha256(firmware_path)
    current_param_sha, _               = compute_param_sha256(param_path, whitelist_path)

    # ── Run checks ───────────────────────────────────────────────────────────
    checks = [
        ("Magic",       magic          == METADATA_MAGIC,   None),
        ("CRC-32",      stored_crc     == computed_crc,
             f"stored=0x{stored_crc:08X}  computed=0x{computed_crc:08X}"),
        ("Version",     version        == METADATA_VERSION,
             f"stored={version}  expected={METADATA_VERSION}"),
        ("FW address",  stored_fw_addr == fw_start_addr,
             f"stored=0x{stored_fw_addr:08X}  expected=0x{fw_start_addr:08X}"),
        ("FW size",     stored_fw_size == current_fw_size,
             f"stored={stored_fw_size}  current={current_fw_size}"),
        ("FW SHA-256",  stored_fw_sha  == current_fw_sha,
             f"\n    stored  : {stored_fw_sha.hex().upper()}"
             f"\n    current : {current_fw_sha.hex().upper()}"),
        ("Param SHA-256", stored_param_sha == current_param_sha,
             f"\n    stored  : {stored_param_sha.hex().upper()}"
             f"\n    current : {current_param_sha.hex().upper()}"),
    ]

    print("\n=== VERIFY ===")
    all_ok = True
    for label, ok, detail in checks:
        status = "OK  " if ok else "FAIL"
        print(f"  {status} : {label}", end="")
        if not ok:
            all_ok = False
            if detail:
                print(f"  ({detail})", end="")
        print()

    print()
    if all_ok:
        print("Result: PASS — metadata matches firmware and parameters")
    else:
        print("Result: FAIL — see details above")

    return all_ok


# =============================================================================
#  CLI
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Optional global flag: override default FW_START_ADDRESS
    parser.add_argument(
        '--fw-addr',
        type=lambda x: int(x, 0),   # accepts 0x08040000 or decimal
        default=FW_START_ADDRESS,
        metavar='ADDR',
        help=f'Flash address where firmware starts (default: 0x{FW_START_ADDRESS:08X})',
    )

    sub = parser.add_subparsers(dest='cmd', required=True)

    # ── generate ──────────────────────────────────────────────────────────────
    gen = sub.add_parser('generate', help='Generate metadata.bin from firmware + params')
    gen.add_argument('--firmware',  required=True, metavar='FILE',
                     help='Compiled firmware binary (.bin)')
    gen.add_argument('--params',    required=True, metavar='FILE',
                     help='Parameter file (MP CSV, QGC, or ArduPilot export)')
    gen.add_argument('--whitelist', required=True, metavar='FILE',
                     help='Whitelist file — one parameter name per line')
    gen.add_argument('--output',    default='metadata.bin', metavar='FILE',
                     help='Output metadata binary (default: metadata.bin)')

    # ── verify ────────────────────────────────────────────────────────────────
    ver = sub.add_parser('verify', help='Verify metadata.bin against firmware + params')
    ver.add_argument('--metadata',  required=True, metavar='FILE',
                     help='Metadata binary to verify')
    ver.add_argument('--firmware',  required=True, metavar='FILE',
                     help='Compiled firmware binary (.bin)')
    ver.add_argument('--params',    required=True, metavar='FILE',
                     help='Parameter file')
    ver.add_argument('--whitelist', required=True, metavar='FILE',
                     help='Whitelist file')

    args = parser.parse_args()

    try:
        if args.cmd == 'generate':
            generate_metadata(
                firmware_path  = args.firmware,
                param_path     = args.params,
                whitelist_path = args.whitelist,
                output_path    = args.output,
                fw_start_addr  = args.fw_addr,
            )
            return 0

        elif args.cmd == 'verify':
            ok = verify_metadata(
                metadata_path  = args.metadata,
                firmware_path  = args.firmware,
                param_path     = args.params,
                whitelist_path = args.whitelist,
                fw_start_addr  = args.fw_addr,
            )
            return 0 if ok else 1

    except (KeyError, ValueError, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())