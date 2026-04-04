#!/usr/bin/env python3

import hashlib
import struct
import argparse
import os

# ===============================
# Constants (MUST match bootloader)
# ===============================
METADATA_MAGIC = 0xDEADBEEF
METADATA_VERSION = 1
METADATA_FLAGS = 0


# ===============================
# Generate SHA256
# ===============================
def compute_sha256(firmware_path):
    with open(firmware_path, "rb") as f:
        data = f.read()

    sha256_hash = hashlib.sha256(data).digest()
    return sha256_hash, len(data)


# ===============================
# Create metadata binary
# ===============================
def create_metadata(firmware_path, output_path):
    sha256_hash, fw_size = compute_sha256(firmware_path)

    metadata = struct.pack(
        "<II32sII",   # little-endian
        METADATA_MAGIC,
        fw_size,
        sha256_hash,
        METADATA_VERSION,
        METADATA_FLAGS
    )

    with open(output_path, "wb") as f:
        f.write(metadata)

    print("\n✅ Metadata generated successfully\n")

    print("📦 Firmware Info:")
    print(f"  Path          : {firmware_path}")
    print(f"  Size          : {fw_size} bytes")
    print(f"  SHA256        : {sha256_hash.hex()}")

    print("\n📄 Metadata Info:")
    print(f"  Output File   : {output_path}")
    print(f"  Size          : {len(metadata)} bytes")
    print(f"  Magic         : 0x{METADATA_MAGIC:X}")
    print(f"  Version       : {METADATA_VERSION}")
    print(f"  Flags         : {METADATA_FLAGS}")

    print("\n⚠️ Flash Addresses:")
    print("  Bootloader    : 0x08000000")
    print("  Metadata      : 0x08020000")
    print("  Firmware      : 0x08040000\n")


# ===============================
# CLI Interface
# ===============================
def main():
    parser = argparse.ArgumentParser(
        description="Generate firmware metadata (SHA256)"
    )

    parser.add_argument(
        "-f", "--firmware",
        required=True,
        help="Path to firmware .bin file"
    )

    parser.add_argument(
        "-o", "--output",
        default="metadata.bin",
        help="Output metadata file (default: metadata.bin)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.firmware):
        print("❌ Firmware file not found!")
        return

    create_metadata(args.firmware, args.output)


if __name__ == "__main__":
    main()