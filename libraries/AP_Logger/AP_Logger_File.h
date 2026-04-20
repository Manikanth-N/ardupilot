/* 
   AP_Logger logging - file oriented variant

   This uses posix file IO to create log files called logNN.dat in the
   given directory
 */
#pragma once

#include <AP_Filesystem/AP_Filesystem.h>
#include <AP_HAL/utility/RingBuffer.h>
#include "AP_Logger_Backend.h"

#if HAL_LOGGING_FILESYSTEM_ENABLED

#ifndef HAL_LOGGER_WRITE_CHUNK_SIZE
#define HAL_LOGGER_WRITE_CHUNK_SIZE 4096
#endif

// ============================================================
// SECURE LOGGING
//
// Algorithm  : Blake2b-256 hash chain + Ed25519 signature
// Crypto lib : Monocypher 3.1.2 — already compiled into ArduPilot
//              via libraries/AP_CheckFirmware/monocypher.cpp
// Stack cost : ~200 bytes for Ed25519 signing
// Extra files: NONE — no bundled headers, no wscript changes needed
//
// Binary layout of every .BIN file:
//   [SecureLogHeader  64B ]  first bytes of file
//   [log data chunk 1     ]
//   [SecureChunkRecord 44B]  after every io_timer write
//   ...repeated for every chunk...
//   [SecureEndRecord 101B ]  last bytes of a cleanly-closed log
//
// Hash chain:
//   H0 = Blake2b-256(header bytes[0..15])
//   Hi = Blake2b-256(chunk_i || H(i-1))
//   HN signed with Ed25519 private key → 64-byte signature
// ============================================================
#if HAL_SECURE_LOGGING_ENABLED

// Monocypher compiled from libraries/AP_CheckFirmware/monocypher.cpp
#include <AP_CheckFirmware/monocypher.h>

// ── SecureLogHeader (64 bytes) ─────────────────────────────
struct PACKED SecureLogHeader {
    uint8_t  magic;           // 0xA5
    uint8_t  version;         // 1
    uint8_t  algorithm;       // 2 = Blake2b-256 + Ed25519
    uint8_t  status;          // 0 = IN_PROGRESS
    uint16_t device_id;
    uint16_t firmware_ver;    // MAJ<<8 | MIN
    uint32_t timestamp_utc;
    uint16_t log_counter;
    uint8_t  reserved_a[2];
    uint8_t  H0[32];          // Blake2b-256(bytes[0..15])
    uint8_t  reserved_b[16];
};
static_assert(sizeof(SecureLogHeader) == 64, "SecureLogHeader must be 64 bytes");

// ── SecureChunkRecord (44 bytes) ───────────────────────────
struct PACKED SecureChunkRecord {
    uint32_t magic;      // 0x48434831 "HCH1"
    uint32_t offset;
    uint32_t length;
    uint8_t  hash[32];   // Hi = Blake2b-256(chunk || H(i-1))
};
static_assert(sizeof(SecureChunkRecord) == 44, "SecureChunkRecord must be 44 bytes");

// ── SecureEndRecord (101 bytes) ────────────────────────────
struct PACKED SecureEndRecord {
    uint32_t magic;          // 0x534C4F47 "SLOG"
    uint8_t  final_hash[32];
    uint8_t  sig_len;        // 64 = valid, 0 = signing failed
    uint8_t  signature[64];  // Ed25519 fixed 64-byte output, no DER
};
static_assert(sizeof(SecureEndRecord) == 101, "SecureEndRecord must be 101 bytes");

// ── Ed25519 private key ────────────────────────────────────
// *** REPLACE BEFORE PRODUCTION DEPLOYMENT ***
// Generate: python3 -c "import os; print(os.urandom(32).hex())"
static const uint8_t SECURE_LOG_PRIVATE_KEY[32] = {
    0x63,0x9d,0x82,0xe3,0x85,0x16,0x5f,0xd2,
    0x3c,0x1a,0xe8,0x3c,0x08,0xef,0x00,0x6e,
    0xd9,0x23,0x38,0xc6,0x15,0xfc,0x5c,0xb7,
    0x0e,0x32,0x9b,0x34,0x34,0xe9,0xb4,0xc4,
};

#endif  // HAL_SECURE_LOGGING_ENABLED


class AP_Logger_File : public AP_Logger_Backend
{
public:
    AP_Logger_File(AP_Logger &front, LoggerMessageWriter_DFLogStart *);

    static AP_Logger_Backend *probe(AP_Logger &front,
                                    LoggerMessageWriter_DFLogStart *ls) {
        return NEW_NOTHROW AP_Logger_File(front, ls);
    }

    void Init() override;
    bool CardInserted(void) const override;
    void EraseAll() override;

    bool _WritePrioritisedBlock(const void *pBuffer, uint16_t size, bool is_critical) override;
    uint32_t bufferspace_available() override;

    uint16_t find_last_log() override;
    void get_log_boundaries(uint16_t log_num, uint32_t &start_page, uint32_t &end_page) override;
    void get_log_info(uint16_t log_num, uint32_t &size, uint32_t &time_utc) override;
    int16_t get_log_data(uint16_t log_num, uint16_t page, uint32_t offset, uint16_t len, uint8_t *data) override;
    void end_log_transfer() override;
    uint16_t get_num_logs() override;
    void start_new_log(void) override;
    uint16_t find_oldest_log() override;

#if CONFIG_HAL_BOARD == HAL_BOARD_SITL || CONFIG_HAL_BOARD == HAL_BOARD_LINUX
    void flush(void) override;
#endif
    void periodic_1Hz() override;
    void periodic_fullrate() override;

    bool logging_failed() const override;
    bool logging_started(void) const override { return _write_fd != -1; }
    void io_timer(void) override;

protected:
    bool WritesOK() const override;
    bool StartNewLogOK() const override;
    void PrepForArming_start_logging() override;

private:
    int _write_fd = -1;
    char *_write_filename;
    bool last_log_is_marked_discard;
    uint32_t _last_write_ms;
#if AP_RTC_ENABLED && CONFIG_HAL_BOARD == HAL_BOARD_CHIBIOS
    bool _need_rtc_update;
#endif

    int _read_fd = -1;
    uint16_t _read_fd_log_num;
    uint32_t _read_offset;
    uint32_t _write_offset;
    volatile uint32_t _open_error_ms;
    const char *_log_directory;
    bool _last_write_failed;

    uint32_t _io_timer_heartbeat;
    bool io_thread_alive() const;
    uint8_t io_thread_warning_decimation_counter;

    bool recent_open_error(void) const;

    void Prep_MinSpace();
    int64_t disk_space_avail();
    int64_t disk_space();
    void ensure_log_directory_exists();

    bool file_exists(const char *filename) const;
    bool log_exists(const uint16_t lognum) const;
    bool dirent_to_log_num(const dirent *de, uint16_t &log_num) const;
    bool write_lastlog_file(uint16_t log_num);

    ByteBuffer _writebuf{0};
    const uint16_t _writebuf_chunk = HAL_LOGGER_WRITE_CHUNK_SIZE;
    uint32_t _last_write_time;

    char *_log_file_name(const uint16_t log_num) const;
    char *_lastlog_file_name() const;
    uint32_t _get_log_size(const uint16_t log_num);
    uint32_t _get_log_time(const uint16_t log_num);

    void stop_logging(void) override;

    // Defer log rotation through io_timer() so the buffer is fully
    // drained and SecureEndRecord is written before the file closes.
    void stop_logging_async(void) override {
#if HAL_SECURE_LOGGING_ENABLED
        if (_sec_active) {
            _sec_stop_pending = true;
            return;
        }
#endif
        stop_logging();
    }

    uint32_t last_messagewrite_message_sent;

    uint32_t _free_space_last_check_time;
    const uint32_t _free_space_check_interval = 1000UL;
    const uint32_t _free_space_min_avail = 8388608;

    HAL_Semaphore semaphore;
    HAL_Semaphore write_fd_semaphore;

    struct { bool was_logging; uint16_t log_num; } erase;
    void erase_next(void);

    const char *last_io_operation = "";
    bool start_new_log_pending;

    // ============================================================
    // SECURE LOGGING STATE — only present when enabled
    // ============================================================
#if HAL_SECURE_LOGGING_ENABLED
    uint8_t  _sec_prev_hash[32];  // current chain tail
    bool     _sec_active;         // true after header written
    uint32_t _sec_chunk_start;    // file offset of current chunk

    volatile bool _sec_stop_pending;  // set by disarm, consumed by io_timer

    void request_secure_stop(void) override { _sec_stop_pending = true; }

    void _sec_write_header(uint16_t log_num);
    void _sec_append_chunk_record(const uint8_t *data, uint32_t len);
    void _sec_write_end_record(int fd);
#endif
};

#endif // HAL_LOGGING_FILESYSTEM_ENABLED