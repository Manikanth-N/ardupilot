# Firmware Integrity & Parameter Verification

Custom ArduPilot build for CUAV-X7 with two-layer flash security:
the bootloader verifies the firmware SHA-256 before booting, and
ArduCopter verifies critical parameter values before arming.

---

## Flash Layout

```
0x08000000  Sector 0  128 KB  Bootloader  (factory-flashed, never overwritten)
0x08020000  Sector 1  128 KB  Metadata    (92 bytes used — programmed by metadata_gen.py)
0x08040000  Sector 2+         Firmware    (arducopter.bin)
```

---

## Metadata Block (92 bytes, little-endian)

```
Offset  Size  Field           Description
     0     4  magic           0xDEADBEEF — validity marker
     4     4  fw_size         Firmware binary byte length
     8    32  fw_sha256       SHA-256 of firmware binary     ← bootloader reads here
    40     4  version         Metadata format version (1)
    44     4  flags           Reserved, 0
    48     4  fw_start_addr   0x08040000
    52    32  param_sha256    SHA-256 of canonical params    ← ArduCopter reads here
    84     4  build_ts        Unix timestamp of generation
    88     4  meta_crc32      CRC-32 of bytes 0–87
```

---

## Repository Structure

```
ardupilot/
├── ArduCopter/
│   └── wscript                                  ← recurses AP_ParamIntegrity before build
├── libraries/
│   └── AP_ParamIntegrity/
│       ├── AP_ParamIntegrity.h                  ← reads Sector 1 at runtime
│       ├── AP_ParamIntegrity.cpp
│       └── params/
│           └── whitelist.txt                    ← one param name per line
└── Tools/
    └── scripts/
        ├── metadata_genarator.py                ← generate / verify metadata.bin
        └── param_checksum_gen.py                ← standalone param SHA-256 tool
```

---

## Step 1 — Build Firmware

```bash
cd ardupilot

# SITL
./waf configure --board sitl
./waf copter

# Hardware (CUAV-X7)
./waf configure --board CUAV-X7
./waf copter
```

Output binary: `build/CUAV-X7/bin/arducopter.bin`

---

## Step 2 — Export Parameters from Vehicle

Connect via Mission Planner or MAVProxy and save a full param file.

```bash
# MAVProxy
param save vehicle.params
```

Ensure your whitelist parameters are present in the exported file.
Default whitelist (`params/whitelist.txt`):

```
AVOID_ENABLE
FENCE_ENABLE
FS_EKF_ACTION
FS_THR_ENABLE
```

---

## Step 3 — Generate metadata.bin

```bash
python3 Tools/scripts/metadata_genarator.py generate \
    --firmware  build/CUAV-X7/bin/arducopter.bin \
    --params    vehicle.params \
    --whitelist libraries/AP_ParamIntegrity/params/whitelist.txt \
    --output    metadata.bin
```

Expected output:

```
=== CANONICAL PARAM INPUT ===
AVOID_ENABLE=1
FENCE_ENABLE=1
FS_EKF_ACTION=1
FS_THR_ENABLE=1

=== HASHES ===
Firmware SHA-256 : 27C7E275...
Param    SHA-256 : 02E96CEC...

=== METADATA ===
Output           : metadata.bin
Size             : 92 bytes
CRC-32           : 0x76C6E87D

=== FLASH LAYOUT ===
Bootloader       : 0x08000000
Metadata sector  : 0x08020000
Firmware start   : 0x08040000
```

---

## Step 4 — Flash Metadata to Sector 1

```bash
# Erase Sector 1 only (never erase Sector 0 — that is the bootloader)
STM32_Programmer_CLI -c port=SWD -e [1 1]

# Program and verify
STM32_Programmer_CLI -c port=SWD \
    -d metadata.bin 0x08020000 \
    --verify
```

---

## Step 5 — Flash Firmware

```bash
STM32_Programmer_CLI -c port=SWD \
    -d build/CUAV-X7/bin/arducopter.bin 0x08040000 \
    --verify

# Hard reset
STM32_Programmer_CLI -c port=SWD -hardRst
```

---

## Step 6 — Verify metadata.bin (optional sanity check)

```bash
python3 Tools/scripts/metadata_genarator.py verify \
    --metadata  metadata.bin \
    --firmware  build/CUAV-X7/bin/arducopter.bin \
    --params    vehicle.params \
    --whitelist libraries/AP_ParamIntegrity/params/whitelist.txt
```

All lines must show `OK`:

```
=== VERIFY ===
  OK   : Magic
  OK   : CRC-32
  OK   : Version
  OK   : FW address
  OK   : FW size
  OK   : FW SHA-256
  OK   : Param SHA-256

Result: PASS — metadata matches firmware and parameters
```

---

## Boot Sequence

```
Power ON
  └─ Bootloader (Sector 0)
       ├─ Reads metadata from 0x08020000
       ├─ Checks magic == 0xDEADBEEF
       ├─ Computes SHA-256 of firmware at 0x08040000
       ├─ Compares against fw_sha256 at metadata offset 8
       ├─ PASS → jumps to firmware
       └─ FAIL → blinks LED, prints "BOOT BLOCKED", loops forever

  └─ Firmware (Sector 2+)
       └─ At arming time: AP_ParamIntegrity::check()
            ├─ Reads live parameter values via AP_Param
            ├─ Computes SHA-256 of canonical param string
            ├─ Reads param_sha256 from metadata offset 52
            ├─ Validates metadata magic + CRC-32 first
            ├─ PASS → arming proceeds
            └─ FAIL → GCS message, arming blocked
```

---

## Arming Failure Messages

| GCS Message | Cause | Fix |
|---|---|---|
| `ParamIntegrity: bad magic 0x...` | Sector 1 not programmed or erased | Re-flash metadata.bin to 0x08020000 |
| `ParamIntegrity: metadata CRC mismatch` | metadata.bin corrupted during flash | Re-erase Sector 1 and reflash |
| `ParamIntegrity: FENCE_ENABLE not found` | Whitelist param absent from firmware build | Remove param from whitelist.txt |
| `Param checksum mismatch` | Live param value differs from metadata | Re-export params and regenerate metadata.bin |

---

## Updating Parameters

When you legitimately change a whitelisted parameter:

```bash
# 1. Change the value on the vehicle via GCS

# 2. Export updated params
param save vehicle_updated.params

# 3. Regenerate metadata (no firmware rebuild needed)
python3 Tools/scripts/metadata_genarator.py generate \
    --firmware  build/CUAV-X7/bin/arducopter.bin \
    --params    vehicle_updated.params \
    --whitelist libraries/AP_ParamIntegrity/params/whitelist.txt \
    --output    metadata.bin

# 4. Reflash Sector 1 only
STM32_Programmer_CLI -c port=SWD -e [1 1]
STM32_Programmer_CLI -c port=SWD -d metadata.bin 0x08020000 --verify
```

Firmware does **not** need to be rebuilt or reflashed.

---

## SITL Testing

```bash
# Generate metadata using SITL binary
python3 Tools/scripts/metadata_genarator.py generate \
    --firmware  build/sitl/bin/arducopter \
    --params    sim_param.params \
    --whitelist libraries/AP_ParamIntegrity/params/whitelist.txt \
    --output    metadata.bin

# Launch SITL from the directory containing metadata.bin
# AP_ParamIntegrity::check() reads metadata.bin via fopen() on SITL
./build/sitl/bin/arducopter --sim-address=127.0.0.1
```

---

## Adding or Removing Whitelisted Parameters

```bash
# 1. Edit the whitelist file (names only, one per line, any order)
nano libraries/AP_ParamIntegrity/params/whitelist.txt

# 2. Edit _whitelist[] in AP_ParamIntegrity.cpp to match
#    (must be in ASCII-ascending order)

# 3. Rebuild firmware
./waf --board CUAV-X7 copter

# 4. Export params, regenerate metadata.bin, reflash Sector 1
```

---

## Tools Reference

**`metadata_genarator.py generate`**

| Argument | Description |
|---|---|
| `--firmware FILE` | Compiled `.bin` file |
| `--params FILE` | Parameter file (MP CSV, QGC, or ArduPilot export) |
| `--whitelist FILE` | Whitelist file — one param name per line |
| `--output FILE` | Output metadata binary (default: `metadata.bin`) |
| `--fw-addr ADDR` | Override firmware start address (default: `0x08040000`) |

**`metadata_genarator.py verify`** — same arguments plus `--metadata FILE`

**`STM32_Programmer_CLI` quick reference**

```bash
# Connect check
STM32_Programmer_CLI -c port=SWD -i

# Erase single sector (sector index, not address)
STM32_Programmer_CLI -c port=SWD -e [1 1]

# Program binary at address
STM32_Programmer_CLI -c port=SWD -d file.bin 0xADDRESS --verify

# Full chip erase (DO NOT USE — wipes bootloader)
# STM32_Programmer_CLI -c port=SWD -e all   ← DANGER
```