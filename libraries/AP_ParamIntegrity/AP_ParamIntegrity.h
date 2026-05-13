/*
 * AP_ParamIntegrity.h — Runtime parameter integrity verification
 *
 * Verifies that a whitelisted set of critical parameters matches a SHA-256
 * reference checksum generated at build time by the offline tool
 *   Tools/scripts/param_checksum_gen.py
 *
 * ── Canonical serialisation format ──────────────────────────────────────────
 *
 *   One entry per line, entries sorted in ASCII-ascending (strcmp) order:
 *
 *     NAME=VALUE\n
 *
 *   VALUE formatting rules (must match param_checksum_gen.py exactly):
 *     AP_PARAM_INT8 / INT16 / INT32  →  decimal integer,  e.g.  FENCE_ENABLE=1
 *     AP_PARAM_FLOAT, no fraction    →  decimal integer,  e.g.  FS_THR_ENABLE=1
 *     AP_PARAM_FLOAT, has fraction   →  %.6f (6 d.p.),   e.g.  SOME_GAIN=0.135000
 *
 *   Line endings are always \n (0x0A).  No trailing newline after the last
 *   entry.  No blank lines.  No comments.  Strictly no BOM.
 *
 * ── Workflow ─────────────────────────────────────────────────────────────────
 *
 *   1.  Edit _whitelist[] in AP_ParamIntegrity.cpp.  Keep it ASCII-sorted.
 *   2.  python3 Tools/scripts/param_checksum_gen.py  params/critical.param
 *   3.  Paste the printed 32-byte array into _reference_checksum[].
 *   4.  Rebuild and deploy.
 *
 * ── Security scope ───────────────────────────────────────────────────────────
 *
 *   Detects:  accidental storage corruption, GCS-driven config drift,
 *             unintended changes during integration.
 *   Does NOT prevent: an attacker with full firmware-flash access, or
 *             changes to parameters outside the whitelist.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
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
     * Reads every whitelisted parameter from the live AP_Param store,
     * serialises each one into the canonical format, feeds the result
     * through SHA-256, then compares the digest against the hardcoded
     * reference checksum.
     *
     * Returns true   — all entries found; digest matches reference.
     * Returns false  — a parameter is absent, or the digest mismatches.
     *
     * When display_failure == true, a GCS MAVLink CRITICAL text is emitted
     * identifying the specific sub-failure (missing param / format error).
     * The top-level "Param checksum mismatch" message is left to the caller
     * (AP_Arming_Copter::parameter_checks) so the arming framework controls
     * rate-limiting and severity.
     */
    bool check(bool display_failure) const;

private:
    // ── SHA-256 (self-contained FIPS-180-4) ──────────────────────────────────

    static constexpr uint8_t SHA256_DIGEST_SIZE = 32;
    static constexpr uint8_t SHA256_BLOCK_SIZE  = 64;

    /*
     * Internal SHA-256 state.  Instantiated on the stack inside check(); the
     * total stack cost is ~105 bytes for this struct plus ~256 bytes for the
     * message-schedule array w[64] inside sha256_transform — well within the
     * main-thread budget on any supported ArduPilot target.
     */
    struct SHA256_CTX {
        uint32_t state[8];               // running hash state (H0…H7)
        uint64_t bit_count;              // total bits fed so far
        uint8_t  buf[SHA256_BLOCK_SIZE]; // partial block accumulator
        uint8_t  buf_len;                // bytes currently in buf
    };

    /*
     * Initialise ctx with the SHA-256 initial hash values (FIPS-180-4 §5.3.3).
     */
    static void sha256_init(SHA256_CTX &ctx);

    /*
     * Feed len bytes of data into the running hash.
     * May be called multiple times between init and final.
     */
    static void sha256_update(SHA256_CTX &ctx, const uint8_t *data, size_t len);

    /*
     * Apply padding and length, perform the final transform, and write the
     * 32-byte digest into digest[].  ctx must not be reused after this call.
     */
    static void sha256_final(SHA256_CTX &ctx,
                             uint8_t digest[SHA256_DIGEST_SIZE]);

    /*
     * Core SHA-256 compression function.  Processes exactly one 64-byte block.
     * Called internally by sha256_update and sha256_final.
     */
    static void sha256_transform(SHA256_CTX &ctx,
                                 const uint8_t block[SHA256_BLOCK_SIZE]);

    // ── Canonical serialisation ───────────────────────────────────────────────

    /*
     * format_entry()
     *
     * Writes one canonical entry for parameter `name` (whose live AP_Param
     * pointer and type are supplied) into out_buf as:
     *
     *   NAME=VALUE\n
     *
     * Formatting follows the rules documented in the file header.
     *
     * Returns: number of bytes written (> 0), excluding the NUL terminator.
     *          -1 on buffer overflow, snprintf error, or unsupported type.
     *
     * out_buf must be at least 48 bytes (16-char name + '=' + 20-char value
     * + '\n' + NUL, with margin).
     */
    static int format_entry(const char *name,
                            AP_Param   *param,
                            ap_var_type type,
                            char       *out_buf,
                            size_t      buf_size);

    // ── Whitelist & reference checksum ───────────────────────────────────────

    /*
     * _whitelist[]
     *
     * Parameter names to include in the integrity check.
     * MUST be in strict ASCII-ascending (strcmp) order — this is the same
     * sort order used by the offline Python generator.
     *
     * Change this list in AP_ParamIntegrity.cpp, then regenerate
     * _reference_checksum with param_checksum_gen.py.
     */
    static const char * const _whitelist[];
    static const uint16_t     _whitelist_count;

    /*
     * _reference_checksum[]
     *
     * SHA-256 of the canonical serialisation of _whitelist[] at the
     * expected parameter values, as printed by param_checksum_gen.py.
     *
     * *** PLACEHOLDER (all-zero) — must be replaced before deployment ***
     *
     * A firmware built with the placeholder checksum will always fail
     * arming if ARMING_CHECK includes parameters (the intended behaviour
     * during development before the real checksum is embedded).
     */
    static const uint8_t _reference_checksum[SHA256_DIGEST_SIZE];
};