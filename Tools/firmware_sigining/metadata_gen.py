#!/usr/bin/env python3
"""
metadata_gen.py — Firmware Metadata Generator
firmware_testings branch

Struct layout (60 bytes, little-endian, must match firmware_metadata.h):
  Offset  Size  Field
  ──────────────────────────────────────────
  0       4     magic           (0xDEADBEEF)
  4       4     fw_size         (bytes, > 0)
  8       4     fw_start_addr   (0x08040000)
  12      32    sha256          (SHA256 of firmware binary)
  44      4     version         (METADATA_VERSION)
  48      4     flags           (reserved, 0)
  52      4     build_ts        (unix timestamp)
  56      4     meta_crc32      (CRC32 of bytes 0..55)
  ──────────────────────────────────────────
  TOTAL   60 bytes
"""

import hashlib
import struct
import binascii
import argparse
import os
import time
import sys

# ===============================================================
# Constants — MUST match firmware_metadata.h in bootloader
# ===============================================================
METADATA_MAGIC       = 0xDEADBEEF
METADATA_VERSION     = 1
METADATA_FLAGS       = 0
FW_START_ADDRESS     = 0x08040000   # STM32H743 firmware flash region
METADATA_ADDRESS     = 0x08020000   # STM32H743 metadata flash region
BOOTLOADER_ADDRESS   = 0x08000000   # STM32H743 bootloader flash region
STRUCT_FMT           = "<III32sIIII"  # 60 bytes total
STRUCT_BODY_FMT      = "<III32sIII"   # 56 bytes (everything except meta_crc32)
STRUCT_SIZE          = struct.calcsize(STRUCT_FMT)      # must be 60
STRUCT_BODY_SIZE     = struct.calcsize(STRUCT_BODY_FMT) # must be 56

# ===============================================================
# Sanity check struct sizes at import time
# ===============================================================
assert STRUCT_SIZE      == 60, f"Struct size mismatch: got {STRUCT_SIZE}, expected 60"
assert STRUCT_BODY_SIZE == 56, f"Body size mismatch: got {STRUCT_BODY_SIZE}, expected 56"

# ===============================================================
# SHA256 of firmware binary
# ===============================================================
def compute_sha256(firmware_path: str):
    with open(firmware_path, "rb") as f:
        data = f.read()
    sha256_hash = hashlib.sha256(data).digest()
    return sha256_hash, len(data)

# ===============================================================
# CRC32 of the first 56 bytes of metadata (self-integrity)
# Uses Python's binascii.crc32 which matches STM32 HAL CRC output
# when seeded with 0xFFFFFFFF and XOR'd — we use simple crc32 here
# which matches the C implementation in firmware_metadata.h
# ===============================================================
def compute_meta_crc32(body_bytes: bytes) -> int:
    assert len(body_bytes) == STRUCT_BODY_SIZE
    return binascii.crc32(body_bytes) & 0xFFFFFFFF

# ===============================================================
# Build full metadata binary
# ===============================================================
def create_metadata(firmware_path: str, output_path: str):
    # --- Issue 2 fix: empty firmware guard ---
    if os.path.getsize(firmware_path) == 0:
        print("❌  Firmware file is empty — aborting.")
        sys.exit(1)

    sha256_hash, fw_size = compute_sha256(firmware_path)
    build_ts = int(time.time())

    # --- Issue 2 fix: explicit size guard ---
    if fw_size == 0:
        print("❌  Firmware size is 0 — aborting.")
        sys.exit(1)

    # --- Issue 3 fix: include fw_start_addr in struct ---
    # --- Issue 4 fix: include build_ts in struct      ---
    # Pack the body (without CRC) first
    body = struct.pack(
        STRUCT_BODY_FMT,
        METADATA_MAGIC,      # I  offset 0
        fw_size,             # I  offset 4
        FW_START_ADDRESS,    # I  offset 8   ← Issue 3
        sha256_hash,         # 32s offset 12
        METADATA_VERSION,    # I  offset 44
        METADATA_FLAGS,      # I  offset 48
        build_ts,            # I  offset 52  ← Issue 4
    )

    # --- Issue 1 fix: CRC32 of metadata body ---
    meta_crc = compute_meta_crc32(body)

    # Final struct: body + CRC
    metadata = body + struct.pack("<I", meta_crc)
    assert len(metadata) == STRUCT_SIZE, f"Final size {len(metadata)} != {STRUCT_SIZE}"

    with open(output_path, "wb") as f:
        f.write(metadata)

    # -------------------------------------------------------
    # Human-readable output
    # -------------------------------------------------------
    print("\n✅  Metadata generated successfully\n")
    print("📦  Firmware Info:")
    print(f"    Path            : {firmware_path}")
    print(f"    Size            : {fw_size} bytes ({fw_size/1024:.1f} KB)")
    print(f"    SHA256          : {sha256_hash.hex()}")
    print(f"    Start Address   : 0x{FW_START_ADDRESS:08X}")

    print("\n📄  Metadata Info:")
    print(f"    Output File     : {output_path}")
    print(f"    Struct Size     : {len(metadata)} bytes")
    print(f"    Magic           : 0x{METADATA_MAGIC:08X}")
    print(f"    Version         : {METADATA_VERSION}")
    print(f"    Flags           : 0x{METADATA_FLAGS:08X}")
    print(f"    Build Timestamp : {build_ts} ({time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(build_ts))})")
    print(f"    Meta CRC32      : 0x{meta_crc:08X}")

    print("\n⚠️   Flash Layout (STM32H743):")
    print(f"    Bootloader      : 0x{BOOTLOADER_ADDRESS:08X}  (sector 0 — 128KB)")
    print(f"    Metadata        : 0x{METADATA_ADDRESS:08X}  (sector 1 — 128KB)")
    print(f"    Firmware        : 0x{FW_START_ADDRESS:08X}  (sector 2 onward)")
    print()

    return metadata

# ===============================================================
# Verify existing metadata.bin against a firmware.bin
# Issue 5 fix: version validation
# Issue 6 fix: --verify CLI mode
# ===============================================================
def verify_metadata(metadata_path: str, firmware_path: str) -> bool:
    print(f"\n🔍  Verifying: {metadata_path} against {firmware_path}\n")
    errors = []

    with open(metadata_path, "rb") as f:
        raw = f.read()

    if len(raw) != STRUCT_SIZE:
        print(f"❌  Metadata size {len(raw)} != expected {STRUCT_SIZE} bytes")
        return False

    # --- Issue 1 fix: verify meta_crc32 first ---
    body_bytes  = raw[:STRUCT_BODY_SIZE]
    stored_crc  = struct.unpack("<I", raw[STRUCT_BODY_SIZE:])[0]
    computed_crc = compute_meta_crc32(body_bytes)
    if stored_crc != computed_crc:
        errors.append(f"Meta CRC32 MISMATCH — stored=0x{stored_crc:08X} computed=0x{computed_crc:08X}")

    # Unpack body
    magic, fw_size, fw_start_addr, sha256_stored, version, flags, build_ts = struct.unpack(
        STRUCT_BODY_FMT, body_bytes
    )

    # Magic check
    if magic != METADATA_MAGIC:
        errors.append(f"Magic MISMATCH — stored=0x{magic:08X} expected=0x{METADATA_MAGIC:08X}")

    # --- Issue 2 fix: fw_size > 0 check ---
    if fw_size == 0:
        errors.append("fw_size is 0 — invalid metadata")

    # --- Issue 3 fix: fw_start_addr check ---
    if fw_start_addr != FW_START_ADDRESS:
        errors.append(f"fw_start_addr MISMATCH — stored=0x{fw_start_addr:08X} expected=0x{FW_START_ADDRESS:08X}")

    # --- Issue 5 fix: version check ---
    if version != METADATA_VERSION:
        errors.append(f"Version MISMATCH — stored={version} expected={METADATA_VERSION}")

    # SHA256 check against actual firmware
    sha256_recomputed, actual_size = compute_sha256(firmware_path)
    if sha256_recomputed != sha256_stored:
        errors.append(
            f"SHA256 MISMATCH\n"
            f"    stored   : {sha256_stored.hex()}\n"
            f"    computed : {sha256_recomputed.hex()}"
        )

    if actual_size != fw_size:
        errors.append(f"fw_size MISMATCH — metadata={fw_size} actual={actual_size}")

    # Print results
    checks = [
        ("Meta CRC32",      stored_crc == computed_crc),
        ("Magic",           magic == METADATA_MAGIC),
        ("fw_size > 0",     fw_size > 0),
        ("fw_start_addr",   fw_start_addr == FW_START_ADDRESS),
        ("Version",         version == METADATA_VERSION),
        ("SHA256",          sha256_recomputed == sha256_stored),
        ("Size match",      actual_size == fw_size),
    ]

    for name, passed in checks:
        status = "✅" if passed else "❌"
        print(f"    {status}  {name}")

    if errors:
        print("\n❌  Verification FAILED:")
        for e in errors:
            print(f"    → {e}")
        return False
    else:
        print(f"\n✅  Verification PASSED")
        print(f"    Firmware     : {fw_size} bytes @ 0x{fw_start_addr:08X}")
        print(f"    SHA256       : {sha256_stored.hex()}")
        print(f"    Build Time   : {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(build_ts))}")
        return True

# ===============================================================
# CLI
# ===============================================================
def main():
    parser = argparse.ArgumentParser(
        description="Firmware Metadata Generator & Verifier"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # generate
    gen = subparsers.add_parser("generate", aliases=["gen"],
                                help="Generate metadata.bin from firmware.bin")
    gen.add_argument("-f", "--firmware", required=True,  help="Path to firmware .bin")
    gen.add_argument("-o", "--output",   default="metadata.bin", help="Output path (default: metadata.bin)")

    # verify — Issue 6 fix
    ver = subparsers.add_parser("verify", aliases=["check"],
                                help="Verify metadata.bin against firmware.bin")
    ver.add_argument("-m", "--metadata", required=True, help="Path to metadata.bin")
    ver.add_argument("-f", "--firmware", required=True, help="Path to firmware .bin")

    args = parser.parse_args()

    if args.command in ("generate", "gen"):
        if not os.path.exists(args.firmware):
            print(f"❌  Firmware file not found: {args.firmware}")
            sys.exit(1)
        create_metadata(args.firmware, args.output)

    elif args.command in ("verify", "check"):
        for p, label in [(args.metadata, "Metadata"), (args.firmware, "Firmware")]:
            if not os.path.exists(p):
                print(f"❌  {label} file not found: {p}")
                sys.exit(1)
        ok = verify_metadata(args.metadata, args.firmware)
        sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()