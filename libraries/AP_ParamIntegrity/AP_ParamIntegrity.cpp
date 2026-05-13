/*
 * AP_ParamIntegrity.cpp — Runtime parameter integrity verification
 *
 * See AP_ParamIntegrity.h for design documentation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 */

#include "AP_ParamIntegrity.h"

#include <AP_HAL/AP_HAL.h>
#include <GCS_MAVLink/GCS.h>

#include <stdio.h>
#include <string.h>
#include <math.h>

extern const AP_HAL::HAL &hal;

// =============================================================================
//  WHITELIST
//
//  Keep in strict ASCII-ascending (strcmp) order.
//  Keep libraries/AP_ParamIntegrity/params/whitelist.txt in sync —
//  that file is the --whitelist argument to metadata_gen.py.
// =============================================================================

const char * const AP_ParamIntegrity::_whitelist[] = {
    "AVOID_ENABLE",
    "FENCE_ENABLE",
    "FS_EKF_ACTION",
    "FS_THR_ENABLE",
};

const uint16_t AP_ParamIntegrity::_whitelist_count =
    sizeof(AP_ParamIntegrity::_whitelist) /
    sizeof(AP_ParamIntegrity::_whitelist[0]);


// =============================================================================
//  CRC-32  (ISO 3309, polynomial 0xEDB88320)
//
//  Must produce identical results to Python's binascii.crc32(), which
//  metadata_gen.py uses to protect the metadata block.
// =============================================================================

uint32_t AP_ParamIntegrity::crc32_compute(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFUL;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; bit++) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320UL;
            } else {
                crc >>= 1;
            }
        }
    }
    return crc ^ 0xFFFFFFFFUL;
}


// =============================================================================
//  METADATA BLOCK I/O
// =============================================================================

bool AP_ParamIntegrity::read_metadata_block(uint8_t buf[METADATA_TOTAL_SIZE],
                                             bool    display_failure)
{
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
    // ── SITL: read from metadata.bin in the working directory ────────────────
    //
    // Run metadata_gen.py generate → metadata.bin, then launch the SITL
    // binary from the same directory.
    FILE *f = fopen("metadata.bin", "rb");
    if (f == nullptr) {
        if (display_failure) {
            GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                          "ParamIntegrity: metadata.bin not found (SITL)");
        }
        return false;
    }

    const size_t n = fread(buf, 1, METADATA_TOTAL_SIZE, f);
    fclose(f);

    if (n != METADATA_TOTAL_SIZE) {
        if (display_failure) {
            GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                          "ParamIntegrity: metadata.bin too short "
                          "(%u bytes, need %u)",
                          (unsigned)n, (unsigned)METADATA_TOTAL_SIZE);
        }
        return false;
    }
    return true;

#else
    // ── Hardware: memory-mapped read from Sector 1 ────────────────────────────
    //
    // STM32H7 flash is memory-mapped from 0x08000000.  Sector 1 starts at
    // 0x08020000.  A plain memcpy is all that is needed; the cast is safe
    // because we only read, never write, through this pointer.
    memcpy(buf,
           reinterpret_cast<const void *>(METADATA_SECTOR_ADDR),
           METADATA_TOTAL_SIZE);
    return true;
#endif
}


bool AP_ParamIntegrity::validate_metadata_block(
        const uint8_t buf[METADATA_TOTAL_SIZE],
        bool          display_failure)
{
    // ── Magic check ───────────────────────────────────────────────────────────
    uint32_t magic;
    memcpy(&magic, buf, sizeof(magic));   // little-endian, matches metadata_gen.py
    if (magic != METADATA_MAGIC) {
        if (display_failure) {
            GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                          "ParamIntegrity: bad magic 0x%08X "
                          "(Sector 1 not programmed?)",
                          (unsigned)magic);
        }
        return false;
    }

    // ── CRC-32 check (covers bytes 0–87) ──────────────────────────────────────
    const uint32_t computed_crc = crc32_compute(buf, METADATA_BODY_SIZE);
    uint32_t stored_crc;
    memcpy(&stored_crc, buf + META_CRC32_OFFSET, sizeof(stored_crc));

    if (computed_crc != stored_crc) {
        if (display_failure) {
            GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                          "ParamIntegrity: metadata CRC mismatch "
                          "computed=0x%08X stored=0x%08X",
                          (unsigned)computed_crc, (unsigned)stored_crc);
        }
        return false;
    }

    return true;
}


// =============================================================================
//  SHA-256  (self-contained FIPS 180-4 implementation)
// =============================================================================

static const uint32_t SHA256_K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL,
};

#define SHA256_ROTR(x, n)   (((x) >> (n)) | ((x) << (32u - (n))))
#define SHA256_CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define SHA256_MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SHA256_EP0(x)  (SHA256_ROTR(x,  2) ^ SHA256_ROTR(x, 13) ^ SHA256_ROTR(x, 22))
#define SHA256_EP1(x)  (SHA256_ROTR(x,  6) ^ SHA256_ROTR(x, 11) ^ SHA256_ROTR(x, 25))
#define SHA256_SIG0(x) (SHA256_ROTR(x,  7) ^ SHA256_ROTR(x, 18) ^ ((x) >>  3))
#define SHA256_SIG1(x) (SHA256_ROTR(x, 17) ^ SHA256_ROTR(x, 19) ^ ((x) >> 10))

void AP_ParamIntegrity::sha256_init(SHA256_CTX &ctx)
{
    ctx.state[0] = 0x6a09e667UL; ctx.state[1] = 0xbb67ae85UL;
    ctx.state[2] = 0x3c6ef372UL; ctx.state[3] = 0xa54ff53aUL;
    ctx.state[4] = 0x510e527fUL; ctx.state[5] = 0x9b05688cUL;
    ctx.state[6] = 0x1f83d9abUL; ctx.state[7] = 0x5be0cd19UL;
    ctx.bit_count = 0;
    ctx.buf_len   = 0;
}

void AP_ParamIntegrity::sha256_transform(SHA256_CTX        &ctx,
                                          const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    for (uint8_t i = 0; i < 16; i++) {
        w[i] =   ((uint32_t)block[i * 4    ] << 24)
               | ((uint32_t)block[i * 4 + 1] << 16)
               | ((uint32_t)block[i * 4 + 2] <<  8)
               | ((uint32_t)block[i * 4 + 3]);
    }
    for (uint8_t i = 16; i < 64; i++) {
        w[i] = SHA256_SIG1(w[i - 2]) + w[i - 7]
             + SHA256_SIG0(w[i - 15]) + w[i - 16];
    }

    uint32_t a = ctx.state[0], b = ctx.state[1],
             c = ctx.state[2], d = ctx.state[3],
             e = ctx.state[4], f = ctx.state[5],
             g = ctx.state[6], h = ctx.state[7];

    for (uint8_t i = 0; i < 64; i++) {
        const uint32_t t1 = h + SHA256_EP1(e) + SHA256_CH(e, f, g)
                            + SHA256_K[i] + w[i];
        const uint32_t t2 = SHA256_EP0(a) + SHA256_MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx.state[0] += a; ctx.state[1] += b;
    ctx.state[2] += c; ctx.state[3] += d;
    ctx.state[4] += e; ctx.state[5] += f;
    ctx.state[6] += g; ctx.state[7] += h;
}

void AP_ParamIntegrity::sha256_update(SHA256_CTX    &ctx,
                                       const uint8_t *data,
                                       size_t         len)
{
    for (size_t i = 0; i < len; i++) {
        ctx.buf[ctx.buf_len++] = data[i];
        ctx.bit_count += 8;
        if (ctx.buf_len == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx.buf);
            ctx.buf_len = 0;
        }
    }
}

void AP_ParamIntegrity::sha256_final(SHA256_CTX &ctx,
                                      uint8_t digest[SHA256_DIGEST_SIZE])
{
    const uint64_t total_bits = ctx.bit_count;
    uint8_t i = ctx.buf_len;

    ctx.buf[i++] = 0x80;

    if (i > 56) {
        while (i < SHA256_BLOCK_SIZE) { ctx.buf[i++] = 0x00; }
        sha256_transform(ctx, ctx.buf);
        i = 0;
    }
    while (i < 56) { ctx.buf[i++] = 0x00; }

    ctx.buf[56] = (uint8_t)(total_bits >> 56);
    ctx.buf[57] = (uint8_t)(total_bits >> 48);
    ctx.buf[58] = (uint8_t)(total_bits >> 40);
    ctx.buf[59] = (uint8_t)(total_bits >> 32);
    ctx.buf[60] = (uint8_t)(total_bits >> 24);
    ctx.buf[61] = (uint8_t)(total_bits >> 16);
    ctx.buf[62] = (uint8_t)(total_bits >>  8);
    ctx.buf[63] = (uint8_t)(total_bits      );
    sha256_transform(ctx, ctx.buf);

    for (uint8_t k = 0; k < 8; k++) {
        digest[k * 4    ] = (uint8_t)(ctx.state[k] >> 24);
        digest[k * 4 + 1] = (uint8_t)(ctx.state[k] >> 16);
        digest[k * 4 + 2] = (uint8_t)(ctx.state[k] >>  8);
        digest[k * 4 + 3] = (uint8_t)(ctx.state[k]      );
    }
}

#undef SHA256_ROTR
#undef SHA256_CH
#undef SHA256_MAJ
#undef SHA256_EP0
#undef SHA256_EP1
#undef SHA256_SIG0
#undef SHA256_SIG1


// =============================================================================
//  CANONICAL SERIALISATION
// =============================================================================

int AP_ParamIntegrity::format_entry(const char *name,
                                     AP_Param   *param,
                                     ap_var_type type,
                                     char       *out_buf,
                                     size_t      buf_size)
{
    int len;

    switch (type) {

    case AP_PARAM_INT8:
        len = snprintf(out_buf, buf_size, "%s=%d\n",
                       name, (int)((AP_Int8 *)param)->get());
        break;

    case AP_PARAM_INT16:
        len = snprintf(out_buf, buf_size, "%s=%d\n",
                       name, (int)((AP_Int16 *)param)->get());
        break;

    case AP_PARAM_INT32:
        len = snprintf(out_buf, buf_size, "%s=%d\n",
                       name, (int)((AP_Int32 *)param)->get());
        break;

    case AP_PARAM_FLOAT: {
        const float value = ((AP_Float *)param)->get();
        float int_part;
        const float frac = modff(value, &int_part);
        if (fabsf(frac) < 1e-6f) {
            len = snprintf(out_buf, buf_size, "%s=%d\n",
                           name, (int)int_part);
        } else {
            len = snprintf(out_buf, buf_size, "%s=%.6f\n",
                           name, (double)value);
        }
        break;
    }

    default:
        return -1;
    }

    if (len <= 0 || (size_t)len >= buf_size) {
        return -1;
    }
    return len;
}


// =============================================================================
//  PUBLIC INTERFACE
// =============================================================================

bool AP_ParamIntegrity::check(bool display_failure) const
{
    // ── Step 1: compute SHA-256 of live parameter values ─────────────────────

    SHA256_CTX ctx;
    sha256_init(ctx);

    char entry_buf[48];

    for (uint16_t i = 0; i < _whitelist_count; i++) {
        const char *param_name = _whitelist[i];

        ap_var_type type;
        AP_Param *param = AP_Param::find(param_name, &type);

        if (param == nullptr) {
            if (display_failure) {
                GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                              "ParamIntegrity: %s not found", param_name);
            }
            return false;
        }

        const int len = format_entry(param_name, param, type,
                                     entry_buf, sizeof(entry_buf));
        if (len < 0) {
            if (display_failure) {
                GCS_SEND_TEXT(MAV_SEVERITY_CRITICAL,
                              "ParamIntegrity: format error for %s", param_name);
            }
            return false;
        }

        sha256_update(ctx, reinterpret_cast<const uint8_t *>(entry_buf),
                      static_cast<size_t>(len));
    }

    uint8_t computed[SHA256_DIGEST_SIZE];
    sha256_final(ctx, computed);

    // ── Step 2: read and validate the metadata block from Sector 1 ───────────

    uint8_t meta[METADATA_TOTAL_SIZE];

    if (!read_metadata_block(meta, display_failure)) {
        return false;
    }

    if (!validate_metadata_block(meta, display_failure)) {
        return false;
    }

    
    // ── Step 3: constant-time compare against param_sha256 at offset 44 ──────

    const uint8_t *reference = meta + PARAM_SHA256_OFFSET;

    uint8_t diff = 0;
    for (uint8_t i = 0; i < SHA256_DIGEST_SIZE; i++) {
        diff |= computed[i] ^ reference[i];
    }

    return (diff == 0);
}