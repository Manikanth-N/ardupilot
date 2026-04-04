#ifndef SECURING_FIRMWARE_H
#define SECURING_FIRMWARE_H

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

// Include your local SHA256 implementation
#include "sha256.h"

// ===============================
// Memory Layout Configuration
// ===============================
#define METADATA_ADDR   0x08020000   // Metadata location (4 KB after bootloader)
#define FW_START        0x08040000   // Firmware start address

#define METADATA_MAGIC  0xDEADBEEF   // Validation magic number

// ===============================
// Metadata Structure
// ===============================
typedef struct {
    uint32_t magic;
    uint32_t firmware_size;
    uint8_t  sha256[32];
    uint32_t version;
    uint32_t flags;
} firmware_metadata_t;

// Global metadata instance
static firmware_metadata_t metadata;


// ===============================
// Read Metadata from Flash
// ===============================
static inline bool read_metadata(void)
{
    // Important for STM32H7 (avoid stale cache reads)
    SCB_InvalidateDCache();

    memcpy(&metadata, (void*)METADATA_ADDR, sizeof(metadata));

    if (metadata.magic != METADATA_MAGIC) {
        return false;
    }

    return true;
}


// ===============================
// Compute Firmware SHA256
// ===============================
static inline void compute_firmware_hash(uint8_t *out_hash)
{
    SHA256_CTX ctx;

    sha256_init(&ctx);

    sha256_update(&ctx,
                  (const uint8_t*)FW_START,
                  metadata.firmware_size);

    sha256_final(&ctx, out_hash);
}


// ===============================
// Verify Firmware Integrity
// ===============================
static inline bool verify_firmware(void)
{
    uint8_t computed_hash[32];

    compute_firmware_hash(computed_hash);

    return (memcmp(computed_hash, metadata.sha256, 32) == 0);
}


// ===============================
// Failure Handler
// ===============================
static inline void handle_verification_failure(void)
{
#ifdef LED_BAD_FW
    led_set(LED_BAD_FW);
#endif

    while (1) {
        // Optional: blink LED or send debug message
    }
}

#endif // SECURING_FIRMWARE_H