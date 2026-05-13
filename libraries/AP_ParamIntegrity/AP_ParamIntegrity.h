/*
 * AP_ParamIntegrity.h — Runtime parameter integrity verification
 *
 * Verifies that a whitelisted set of critical parameters matches the
 * param_sha256 stored in the Sector 1 metadata block at 0x08020000.
 *
 * ── Why Sector 1, not a compiled-in array ────────────────────────────────────
 *
 *   Storing the reference checksum as a compiled constant requires a
 *   generated .cpp file and complex wscript build machinery that proved
 *   unreliable across SITL and hardware targets.
 *
 *   Instead, metadata_gen.py writes a 92-byte metadata.bin that is
 *   programmed into a dedicated flash sector.  The firmware reads
 *   param_sha256 directly from that sector at arming time.  No generated
 *   files, no build-system changes beyond the two source files here.
 *
 * ── Flash layout (CUAV-X7 / STM32H7) ────────────────────────────────────────
 *
 *   0x08000000  Sector 0  128 KB  Bootloader
 *   0x08020000  Sector 1  128 KB  Metadata   ← programmed by metadata_gen.py
 *   0x08040000  Sector 2+         Firmware
 *
 * ── Metadata sector layout (92 bytes, little-endian) ─────────────────────────
 *
 *   Offset  Size  Field
 *        0     4  magic          0xDEADBEEF
 *        4     4  fw_size
 *        8     4  fw_start_addr
 *       12    32  fw_sha256
 *       44    32  param_sha256   ← read by check()
 *       76     4  version
 *       80     4  flags
 *       84     4  build_ts
 *       88     4  meta_crc32     CRC-32 of bytes 0–87
 *
 * ── Canonical serialisation format ───────────────────────────────────────────
 *
 *   Entries sorted ASCII-ascending (strcmp), one per line ending with \n:
 *
 *     NAME=VALUE\n
 *
 *   VALUE formatting (must match metadata_gen.py exactly):
 *     INT8/16/32 or float with |frac| < 1e-6  →  decimal integer  "1"
 *     float with |frac| >= 1e-6               →  "%.6f"           "0.135000"
 *
 * ── Deployment workflow ───────────────────────────────────────────────────────
 *
 *   1.  Edit _whitelist[] in AP_ParamIntegrity.cpp (keep ASCII-sorted).
 *
 *   2.  Generate metadata.bin:
 *         python3 Tools/scripts/metadata_gen.py generate \
 *             --firmware  build/CUAV-X7/bin/arducopter.bin \
 *             --params    vehicle.params \
 *             --whitelist libraries/AP_ParamIntegrity/params/whitelist.txt \
 *             --output    metadata.bin
 *
 *   3.  Flash metadata.bin to Sector 1:
 *         STM32_Programmer_CLI -c port=SWD \
 *             -d metadata.bin 0x08020000 --verify
 *
 *   4.  Flash firmware as usual and power-cycle.
 *
 *   SITL: place metadata.bin in the working directory where the SITL
 *         binary is launched.  check() reads it via file I/O automatically.
 *
 * ── Security scope ────────────────────────────────────────────────────────────
 *
 *   Detects:  accidental parameter corruption, GCS-driven config drift.
 *   Does NOT prevent: an attacker with full flash-write access.
 */

#pragma once

#include <AP_Param/AP_Param.h>
#include <stdint.h>
#include <stddef.h>

class AP_ParamIntegrity {
public:
    AP_ParamIntegrity() = default;

    /*
     * check()
     *
     * 1.  Reads every whitelisted parameter from the live AP_Param store and
     *     computes the SHA-256 of the canonical serialisation.
     * 2.  Reads the 92-byte metadata block from Sector 1 (hardware) or
     *     metadata.bin (SITL).
     * 3.  Validates the block magic and CRC-32.
     * 4.  Compares the live digest against param_sha256 at offset 44.
     *
     * Returns true only when all parameters are found and the digests match.
     * display_failure == true causes specific GCS CRITICAL messages.
     */
    bool check(bool display_failure) const;

private:
    // ── Metadata sector ───────────────────────────────────────────────────────
    static constexpr uint32_t METADATA_SECTOR_ADDR = 0x08020000;
    static constexpr uint32_t METADATA_MAGIC       = 0xDEADBEEF;
    static constexpr uint32_t METADATA_BODY_SIZE   = 88;  // bytes 0-87 (CRC covers these)
    static constexpr uint32_t METADATA_TOTAL_SIZE  = 92;
    static constexpr uint32_t PARAM_SHA256_OFFSET  = 52;   // offset 52: after magic+fw_size+fw_sha256+version+flags+fw_start_addr
    static constexpr uint32_t META_CRC32_OFFSET    = 88;

    // ── SHA-256 (self-contained FIPS 180-4) ───────────────────────────────────
    static constexpr uint8_t SHA256_DIGEST_SIZE = 32;
    static constexpr uint8_t SHA256_BLOCK_SIZE  = 64;

    struct SHA256_CTX {
        uint32_t state[8];
        uint64_t bit_count;
        uint8_t  buf[SHA256_BLOCK_SIZE];
        uint8_t  buf_len;
    };

    static void sha256_init     (SHA256_CTX &ctx);
    static void sha256_update   (SHA256_CTX &ctx, const uint8_t *data, size_t len);
    static void sha256_final    (SHA256_CTX &ctx, uint8_t digest[SHA256_DIGEST_SIZE]);
    static void sha256_transform(SHA256_CTX &ctx, const uint8_t block[SHA256_BLOCK_SIZE]);

    // ── Canonical serialisation ───────────────────────────────────────────────
    static int format_entry(const char  *name,
                            AP_Param    *param,
                            ap_var_type  type,
                            char        *out_buf,
                            size_t       buf_size);

    // ── Metadata helpers ──────────────────────────────────────────────────────

    /*
     * read_metadata_block()
     *   Hardware: memcpy from METADATA_SECTOR_ADDR (memory-mapped flash).
     *   SITL:     fread from "metadata.bin" in the working directory.
     * Returns true on success.
     */
    static bool read_metadata_block(uint8_t buf[METADATA_TOTAL_SIZE],
                                    bool    display_failure);

    /*
     * validate_metadata_block()
     *   Verifies magic == 0xDEADBEEF and CRC-32 of bytes 0–87.
     * Returns true if valid.
     */
    static bool validate_metadata_block(const uint8_t buf[METADATA_TOTAL_SIZE],
                                        bool          display_failure);

    /*
     * crc32_compute()
     *   ISO 3309 / Ethernet CRC-32 (polynomial 0xEDB88320).
     *   Must match Python binascii.crc32() used by metadata_gen.py.
     */
    static uint32_t crc32_compute(const uint8_t *data, size_t len);

    // ── Whitelist ─────────────────────────────────────────────────────────────
    static const char * const _whitelist[];
    static const uint16_t     _whitelist_count;
};