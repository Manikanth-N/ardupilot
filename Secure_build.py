#!/usr/bin/env python3
"""
secure_build.py — ArduPilot Secure Build Orchestrator
======================================================

Chains the full root-of-trust pipeline in one command:

  Step 1  Key Generation       Tools/scripts/signing/generate_keys.py
  Step 2  Secure Bootloader    Tools/scripts/build_bootloaders.py
  Step 3  Signed Firmware      ./waf configure + ./waf <vehicle> + make_secure_fw.py
  Step 4  Metadata Generation  metadata_gen.py generate
  Step 5  Metadata Verify      metadata_gen.py verify
  Step 6  Summary Report       human-readable manifest

The three trust anchors in play
---------------------------------
  • Code integrity   — Ed25519 signed firmware, verified by secure bootloader
  • Param integrity  — SHA-256 of whitelisted params embedded in metadata.bin
  • Log integrity    — Blake2b-256 hash-chain + Ed25519 tail signature
                       (compiled in when HAL_SECURE_LOGGING_ENABLED=1)

Binary artefacts written to --out-dir
--------------------------------------
  <VENDOR>_private_key.dat     Ed25519 signing private key   *** KEEP SECRET ***
  <VENDOR>_public_key.dat      Ed25519 signing public key
  <BOARD>_bl.bin               Secure bootloader binary
  <vehicle>.apj                Signed firmware image
  metadata.bin                 92-byte metadata blob (fw+param hashes + CRC-32)
  locked_params.txt            Whitelisted params + values (human-readable table)
  locked_params.csv            Whitelisted params + values (CSV)
  secure_build_manifest.txt    Human-readable build report

Usage
-----
  python3 secure_build.py \\
      --board      CubeOrange \\
      --vehicle    copter \\
      --vendor     MyVendor \\
      --params     sim_params.params \\
      --whitelist  whitelist.txt \\
      [--keys-dir  keys/]               existing keys dir (skip keygen)
      [--out-dir   secure_out/]         all artefacts land here
      [--fw-addr   0x08040000]          flash address of firmware sector
      [--omit-ardupilot-keys]           remove ArduPilot's 3 public keys
      [--upload]                        flash board after build
      [--dry-run]                       print commands, do not execute
      [--waf-j     N]                   parallel waf jobs (default: cpu count)
      [--log-level debug|info|warn]

Exit codes
----------
  0  All steps passed
  1  A build/sign step failed
  2  Metadata verify failed
  3  Configuration / argument error
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shlex
import shutil
import struct
import subprocess
import sys
import textwrap
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# ANSI colour helpers  (gracefully degrade on Windows / non-tty)
# ──────────────────────────────────────────────────────────────────────────────

_USE_COLOUR = sys.stdout.isatty() and platform.system() != "Windows"

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

def green(t):  return _c("32;1", t)
def red(t):    return _c("31;1", t)
def yellow(t): return _c("33;1", t)
def cyan(t):   return _c("36;1", t)
def bold(t):   return _c("1",    t)
def dim(t):    return _c("2",    t)


# ──────────────────────────────────────────────────────────────────────────────
# Logger
# ──────────────────────────────────────────────────────────────────────────────

class Logger:
    LEVELS = {"debug": 0, "info": 1, "warn": 2}

    def __init__(self, level: str = "info"):
        self._level = self.LEVELS.get(level, 1)

    def _ts(self) -> str:
        return dim(datetime.now(timezone.utc).strftime("%H:%M:%S"))

    def debug(self, msg: str):
        if self._level <= 0:
            print(f"  {self._ts()} {dim('DBG')} {msg}")

    def info(self, msg: str):
        if self._level <= 1:
            print(f"  {self._ts()} {msg}")

    def warn(self, msg: str):
        print(f"  {self._ts()} {yellow('WRN')} {msg}", file=sys.stderr)

    def step(self, n: int, total: int, title: str):
        bar = "─" * 60
        print(f"\n{cyan(bar)}")
        print(f"  {bold(f'Step {n}/{total}')}  {bold(title)}")
        print(f"{cyan(bar)}")

    def ok(self, msg: str):
        print(f"  {green('✔')} {msg}")

    def fail(self, msg: str):
        print(f"  {red('✘')} {msg}", file=sys.stderr)


log = Logger()   # replaced by main() after arg parsing


# ──────────────────────────────────────────────────────────────────────────────
# Shell helpers
# ──────────────────────────────────────────────────────────────────────────────

def run(cmd: list[str] | str, *,
        dry_run: bool = False,
        cwd: Optional[Path] = None,
        label: str = "") -> subprocess.CompletedProcess:
    """
    Run a command, stream output, raise on non-zero exit.
    """
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    pretty = " ".join(shlex.quote(c) for c in cmd)
    log.info(f"  $ {dim(pretty)}")

    if dry_run:
        log.info(dim("    (dry-run — skipped)"))
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    result = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        capture_output=False,   # stream directly to terminal
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"Command failed (exit {result.returncode}): {pretty}"
        )
    return result


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def ardupilot_root() -> Path:
    """Walk up from this script until we find waf."""
    here = Path(__file__).resolve().parent
    for p in [here, *here.parents]:
        if (p / "waf").exists():
            return p
    raise RuntimeError(
        "Cannot locate ArduPilot root (no 'waf' found). "
        "Place secure_build.py inside the ArduPilot tree."
    )


# ──────────────────────────────────────────────────────────────────────────────
# Step 1 — Key generation
# ──────────────────────────────────────────────────────────────────────────────

def step_keygen(vendor: str, keys_dir: Path, *, dry_run: bool) -> tuple[Path, Path]:
    """
    Generate Ed25519 key pair unless they already exist in keys_dir.

    Returns (private_key_path, public_key_path).
    """
    priv = keys_dir / f"{vendor}_private_key.dat"
    pub  = keys_dir / f"{vendor}_public_key.dat"

    if priv.exists() and pub.exists():
        log.ok(f"Keys already present in {keys_dir} — reusing")
        log.debug(f"  private: {priv}")
        log.debug(f"  public : {pub}")
        return priv, pub

    ensure_dir(keys_dir)
    root = ardupilot_root()
    keygen = root / "Tools" / "scripts" / "signing" / "generate_keys.py"

    if not keygen.exists():
        raise FileNotFoundError(f"Key generator not found: {keygen}")

    # generate_keys.py writes files named <NAME>_private_key.dat in CWD
    run(
        [sys.executable, str(keygen), vendor],
        dry_run=dry_run,
        cwd=keys_dir,
    )

    if not dry_run:
        if not priv.exists():
            raise FileNotFoundError(f"Key generation did not produce: {priv}")
        # Warn loudly about private key security
        log.warn("━" * 56)
        log.warn(f"  PRIVATE KEY: {priv}")
        log.warn("  Store this file in a secure offline location.")
        log.warn("  Anyone with this key can sign firmware for your bootloader.")
        log.warn("━" * 56)

    log.ok("Key pair generated")
    return priv, pub


# ──────────────────────────────────────────────────────────────────────────────
# Step 2 — Secure bootloader
# ──────────────────────────────────────────────────────────────────────────────

def step_bootloader(board: str,
                    pub_key: Path,
                    out_dir: Path,
                    *,
                    omit_ardupilot_keys: bool,
                    dry_run: bool) -> Path:
    """
    Build a secure bootloader binary embedding the vendor public key.

    Returns path to the resulting .bin inside out_dir.
    """
    root = ardupilot_root()
    bl_script = root / "Tools" / "scripts" / "build_bootloaders.py"

    if not bl_script.exists():
        raise FileNotFoundError(f"Bootloader build script not found: {bl_script}")

    cmd = [
        sys.executable, str(bl_script), board,
        f"--signing-key={pub_key}",
    ]
    if omit_ardupilot_keys:
        cmd.append("--omit-ardupilot-keys")
        log.warn("ArduPilot factory signing keys OMITTED — users cannot "
                 "return to stock firmware without your private key.")

    run(cmd, dry_run=dry_run, cwd=root)

    # build_bootloaders.py writes to Tools/bootloaders/<BOARD>_bl.bin
    src_bl = root / "Tools" / "bootloaders" / f"{board}_bl.bin"
    dst_bl = out_dir / f"{board}_bl.bin"

    if not dry_run:
        if not src_bl.exists():
            raise FileNotFoundError(
                f"Expected bootloader binary not found: {src_bl}"
            )
        shutil.copy2(src_bl, dst_bl)
        log.ok(f"Secure bootloader → {dst_bl}  ({dst_bl.stat().st_size:,} bytes)")
    else:
        log.ok(f"(dry-run) Secure bootloader would be → {dst_bl}")

    return dst_bl


# ──────────────────────────────────────────────────────────────────────────────
# Step 3 — Signed firmware
# ──────────────────────────────────────────────────────────────────────────────

def step_firmware(board: str,
                  vehicle: str,
                  priv_key: Path,
                  out_dir: Path,
                  *,
                  waf_j: int,
                  dry_run: bool) -> Path:
    """
    Configure waf for signed firmware and build.

    Returns path to the signed .bin inside out_dir (metadata_gen works on .bin).
    """
    root = ardupilot_root()
    waf  = root / "waf"

    run(
        [sys.executable, str(waf), "configure",
         f"--board={board}",
         "--signed-fw",
         f"--private-key={priv_key}"],
        dry_run=dry_run,
        cwd=root,
    )

    run(
        [sys.executable, str(waf), vehicle,
         f"-j{waf_j}"],
        dry_run=dry_run,
        cwd=root,
    )

    apj_stem = f"ardu{vehicle}" if not vehicle.startswith("ardu") else vehicle
    src_apj  = root / "build" / board / "bin" / f"{apj_stem}.apj"
    dst_apj  = out_dir / f"{apj_stem}.apj"
    src_bin  = root / "build" / board / "bin" / f"{apj_stem}.bin"
    dst_bin  = out_dir / f"{apj_stem}.bin"

    if not dry_run:
        for src, dst in [(src_apj, dst_apj), (src_bin, dst_bin)]:
            if not src.exists():
                raise FileNotFoundError(
                    f"Expected build output not found: {src}\n"
                    f"Check that --vehicle='{vehicle}' is correct "
                    f"(produces 'ardu{vehicle}.apj')."
                )
            shutil.copy2(src, dst)
        log.ok(f"Signed firmware → {dst_apj}  ({dst_apj.stat().st_size:,} bytes)")
        log.ok(f"Raw binary      → {dst_bin}  ({dst_bin.stat().st_size:,} bytes)")
    else:
        log.ok(f"(dry-run) Signed firmware would be → {dst_apj}")

    return dst_bin


# ──────────────────────────────────────────────────────────────────────────────
# Step 4 — Metadata generation  (inline — no subprocess needed)
# ──────────────────────────────────────────────────────────────────────────────

# ── metadata layout constants (mirrors metadata_gen.py exactly) ───────────────
_METADATA_MAGIC   = 0xDEADBEEF
_METADATA_VERSION = 1
_METADATA_FLAGS   = 0
_BOOTLOADER_ADDR  = 0x08000000
_METADATA_ADDR    = 0x08020000
_FW_START_DEFAULT = 0x08040000

_STRUCT_BODY_FMT = "<II32sIII32sI"   # 88 bytes
_STRUCT_FULL_FMT = "<II32sIII32sII"  # 92 bytes
_BODY_SIZE = struct.calcsize(_STRUCT_BODY_FMT)
_FULL_SIZE = struct.calcsize(_STRUCT_FULL_FMT)
assert _BODY_SIZE == 88 and _FULL_SIZE == 92


def _crc32(data: bytes) -> int:
    import binascii
    return binascii.crc32(data) & 0xFFFF_FFFF


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _canonicalize_value(raw: str) -> str:
    val  = float(raw)
    frac = val - int(val)
    return str(int(val)) if abs(frac) < 1e-6 else f"{val:.6f}"


def _load_whitelist(path: Path) -> list[str]:
    names: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        idx = line.find("#")
        name = (line[:idx] if idx != -1 else line).strip()
        if name:
            names.append(name.upper())
    return sorted(names)


def _parse_params(path: Path) -> dict[str, str]:
    params: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        idx = raw.find("#")
        line = (raw[:idx] if idx != -1 else raw).strip()
        if not line:
            continue
        if "," in line:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                params[parts[0]] = parts[1]
        else:
            parts = line.split()
            if len(parts) >= 4 and parts[0].lstrip("-").isdigit() and parts[1].lstrip("-").isdigit():
                params[parts[2]] = parts[3]
            elif len(parts) == 2:
                params[parts[0]] = parts[1]
    return params


def _build_param_blob(params: dict[str, str], whitelist: list[str]) -> bytes:
    lines = []
    missing = [n for n in whitelist if n not in params]
    if missing:
        raise KeyError(
            f"Whitelisted params not found in .params file: {missing}"
        )
    for name in whitelist:
        lines.append(f"{name}={_canonicalize_value(params[name])}\n")
    return "".join(lines).encode("utf-8")


def step_metadata(fw_bin: Path,
                  params_file: Path,
                  whitelist_file: Path,
                  out_dir: Path,
                  fw_start_addr: int,
                  *,
                  dry_run: bool) -> Path:
    """
    Generate metadata.bin from firmware + parameters.

    Returns path to the metadata file.
    """
    out_meta = out_dir / "metadata.bin"

    if dry_run:
        log.ok(f"(dry-run) Metadata would be → {out_meta}")
        return out_meta

    fw_data   = fw_bin.read_bytes()
    fw_sha    = _sha256(fw_data)
    fw_size   = len(fw_data)
    build_ts  = int(time.time())

    params    = _parse_params(params_file)
    whitelist = _load_whitelist(whitelist_file)
    blob      = _build_param_blob(params, whitelist)
    param_sha = _sha256(blob)

    body = struct.pack(
        _STRUCT_BODY_FMT,
        _METADATA_MAGIC,
        fw_size,
        fw_sha,
        _METADATA_VERSION,
        _METADATA_FLAGS,
        fw_start_addr,
        param_sha,
        build_ts,
    )
    crc      = _crc32(body)
    metadata = body + struct.pack("<I", crc)

    out_meta.write_bytes(metadata)

    log.ok(f"Metadata         → {out_meta}  ({len(metadata)} bytes)")
    log.info(f"    FW  SHA-256  : {fw_sha.hex().upper()[:32]}…")
    log.info(f"    Param SHA-256: {param_sha.hex().upper()[:32]}…")
    log.info(f"    CRC-32       : 0x{crc:08X}")
    log.info(f"    Build TS     : {datetime.fromtimestamp(build_ts, timezone.utc).isoformat()}")

    return out_meta


# ──────────────────────────────────────────────────────────────────────────────
# Step 4b — Locked-parameter export
# ──────────────────────────────────────────────────────────────────────────────

def export_locked_params(params_file: Path,
                         whitelist_file: Path,
                         out_dir: Path,
                         *,
                         dry_run: bool) -> tuple[Path, Path]:
    """
    Write two files into out_dir listing every whitelisted parameter and the
    value that was canonicalised and hashed into metadata.bin:

      locked_params.txt   — aligned text table  (human-readable / diff-friendly)
      locked_params.csv   — comma-separated      (spreadsheet / tooling import)

    These files mirror exactly what went into the SHA-256 param hash so you can
    audit which values are locked without decoding the binary metadata blob.

    Returns (txt_path, csv_path).
    """
    txt_out = out_dir / "locked_params.txt"
    csv_out = out_dir / "locked_params.csv"

    if dry_run:
        log.ok(f"(dry-run) Locked-param export would be → {txt_out} / {csv_out}")
        return txt_out, csv_out

    params    = _parse_params(params_file)
    whitelist = _load_whitelist(whitelist_file)   # sorted alphabetically

    # Build rows: (NAME, raw_value, canonical_value)
    rows: list[tuple[str, str, str]] = []
    missing: list[str] = []
    for name in whitelist:
        if name not in params:
            missing.append(name)
            continue
        raw   = params[name]
        canon = _canonicalize_value(raw)
        rows.append((name, raw, canon))

    if missing:
        log.warn(
            f"Whitelisted params missing from .params file (skipped in export): {missing}"
        )

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    # ── .txt — padded table ───────────────────────────────────────────────────
    col_name  = max((len(r[0]) for r in rows), default=9)
    col_raw   = max((len(r[1]) for r in rows), default=9)
    col_canon = max((len(r[2]) for r in rows), default=18)

    sep = f"# {'-' * col_name}  {'-' * col_raw}  {'-' * col_canon}"
    header_txt = "\n".join([
        "# ArduPilot Secure Build — Locked Parameters",
        f"# Generated : {now}",
        f"# Source    : {params_file}",
        f"# Whitelist : {whitelist_file}",
        f"# Count     : {len(rows)}",
        "#",
        f"# {'PARAMETER':<{col_name}}  {'RAW VALUE':<{col_raw}}  CANONICAL (hashed into metadata)",
        sep,
    ]) + "\n"

    body_lines = [
        f"  {name:<{col_name}}  {raw:<{col_raw}}  {canon}"
        for name, raw, canon in rows
    ]
    txt_out.write_text(header_txt + "\n".join(body_lines) + "\n", encoding="utf-8")

    # ── .csv ──────────────────────────────────────────────────────────────────
    csv_lines = [
        f"# ArduPilot Secure Build — Locked Parameters — Generated: {now}",
        "parameter,raw_value,canonical_value",
    ] + [f"{name},{raw},{canon}" for name, raw, canon in rows]
    csv_out.write_text("\n".join(csv_lines) + "\n", encoding="utf-8")

    log.ok(f"Locked params    → {txt_out}  ({len(rows)} params)")
    log.ok(f"Locked params    → {csv_out}  (CSV)")
    return txt_out, csv_out


# ──────────────────────────────────────────────────────────────────────────────
# Step 5 — Metadata verification
# ──────────────────────────────────────────────────────────────────────────────

def step_verify(meta_path: Path,
                fw_bin: Path,
                params_file: Path,
                whitelist_file: Path,
                fw_start_addr: int,
                *,
                dry_run: bool) -> bool:
    """
    Re-read and verify metadata.bin against live firmware + params.

    Returns True on pass.
    """
    if dry_run:
        log.ok("(dry-run) Verification skipped")
        return True

    raw = meta_path.read_bytes()
    if len(raw) != _FULL_SIZE:
        log.fail(f"Metadata size {len(raw)} ≠ {_FULL_SIZE}")
        return False

    body       = raw[:_BODY_SIZE]
    stored_crc = struct.unpack("<I", raw[_BODY_SIZE:])[0]
    computed_crc = _crc32(body)

    (magic, stored_fw_size, stored_fw_sha,
     version, flags, stored_fw_addr,
     stored_param_sha, build_ts) = struct.unpack(_STRUCT_BODY_FMT, body)

    fw_data       = fw_bin.read_bytes()
    current_fw_sha = _sha256(fw_data)
    current_fw_size = len(fw_data)

    params    = _parse_params(params_file)
    whitelist = _load_whitelist(whitelist_file)
    blob      = _build_param_blob(params, whitelist)
    current_param_sha = _sha256(blob)

    checks = [
        ("Magic",        magic            == _METADATA_MAGIC,   None),
        ("CRC-32",       stored_crc       == computed_crc,
             f"stored=0x{stored_crc:08X}  computed=0x{computed_crc:08X}"),
        ("Version",      version          == _METADATA_VERSION,
             f"stored={version}  expected={_METADATA_VERSION}"),
        ("FW address",   stored_fw_addr   == fw_start_addr,
             f"stored=0x{stored_fw_addr:08X}  expected=0x{fw_start_addr:08X}"),
        ("FW size",      stored_fw_size   == current_fw_size,
             f"stored={stored_fw_size}  current={current_fw_size}"),
        ("FW SHA-256",   stored_fw_sha    == current_fw_sha,
             f"\n        stored :{stored_fw_sha.hex().upper()}"
             f"\n        current:{current_fw_sha.hex().upper()}"),
        ("Param SHA-256",stored_param_sha == current_param_sha,
             f"\n        stored :{stored_param_sha.hex().upper()}"
             f"\n        current:{current_param_sha.hex().upper()}"),
    ]

    all_ok = True
    for label, ok, detail in checks:
        if ok:
            log.ok(f"{label}")
        else:
            all_ok = False
            log.fail(f"{label}" + (f"  → {detail}" if detail else ""))

    return all_ok


# ──────────────────────────────────────────────────────────────────────────────
# Step 6 (optional) — Board upload
# ──────────────────────────────────────────────────────────────────────────────

def step_upload(vehicle: str, out_dir: Path, root: Path, *, dry_run: bool):
    waf = root / "waf"
    run(
        [sys.executable, str(waf), vehicle, "--upload"],
        dry_run=dry_run,
        cwd=root,
    )
    log.ok("Firmware uploaded to board")


# ──────────────────────────────────────────────────────────────────────────────
# Manifest writer
# ──────────────────────────────────────────────────────────────────────────────

def write_manifest(args, out_dir: Path, priv_key: Path, pub_key: Path,
                   bl_bin: Path, fw_bin: Path, meta_bin: Path,
                   elapsed: float) -> Path:
    manifest = out_dir / "secure_build_manifest.txt"
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines = [
        "=" * 70,
        "  ArduPilot Secure Build Manifest",
        f"  Generated : {now}",
        f"  Elapsed   : {elapsed:.1f}s",
        "=" * 70,
        "",
        "BUILD PARAMETERS",
        f"  Board    : {args.board}",
        f"  Vehicle  : {args.vehicle}",
        f"  Vendor   : {args.vendor}",
        f"  FW addr  : 0x{args.fw_addr:08X}",
        f"  AP keys  : {'omitted' if args.omit_ardupilot_keys else 'included'}",
        "",
        "ARTEFACTS",
    ]

    txt_locked = out_dir / "locked_params.txt"
    csv_locked = out_dir / "locked_params.csv"

    for label, path in [
        ("Private key (SECRET)", priv_key),
        ("Public key",           pub_key),
        ("Secure bootloader",    bl_bin),
        ("Signed firmware",      fw_bin),
        ("Metadata blob",        meta_bin),
        ("Locked params (text)", txt_locked),
        ("Locked params (CSV)",  csv_locked),
    ]:
        size = f"  ({path.stat().st_size:,} bytes)" if path.exists() else ""
        lines.append(f"  {label:<28} {path}{size}")

    lines += [
        "",
        "TRUST ANCHORS",
        "  • Firmware authenticity  — Ed25519 signature in .apj, verified by secure bootloader",
        "  • Parameter integrity    — SHA-256 of whitelisted params in metadata.bin",
        "  • Log integrity          — Blake2b-256 chain + Ed25519 tail (HAL_SECURE_LOGGING_ENABLED)",
        "",
        "FLASH LAYOUT",
        f"  0x{0x08000000:08X}  Secure bootloader",
        f"  0x{0x08020000:08X}  Metadata sector",
        f"  0x{args.fw_addr:08X}  Firmware start",
        "",
        "NEXT STEPS",
        "  1. Flash secure bootloader via MAVLink 'flashbootloader' command,",
        "     or DFU to address 0x08000000.",
        "  2. Load signed firmware via MissionPlanner > Load Custom Firmware.",
        "  3. Flash metadata.bin to 0x08020000 via the update tool.",
        "  4. Verify logs with the log-verify tool using the matching public key.",
        "  5. Review locked_params.txt to confirm all whitelisted values are correct.",
        "=" * 70,
    ]

    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    req = p.add_argument_group("required")
    req.add_argument("--board",    required=True,  metavar="BOARD",
                     help="Target board name, e.g. CubeOrange")
    req.add_argument("--vehicle",  required=True,  metavar="VEHICLE",
                     help="Vehicle type: copter, plane, rover, sub, …")
    req.add_argument("--vendor",   required=True,  metavar="NAME",
                     help="Vendor name — used for key file names")
    req.add_argument("--params",   required=True,  metavar="FILE",
                     type=Path, help="Parameter file (.params)")
    req.add_argument("--whitelist",required=True,  metavar="FILE",
                     type=Path, help="Whitelist file (one param name per line)")

    opt = p.add_argument_group("optional")
    opt.add_argument("--keys-dir", metavar="DIR",  type=Path, default=None,
                     help="Directory for existing keys (skips keygen if both files present)")
    opt.add_argument("--out-dir",  metavar="DIR",  type=Path, default=Path("secure_out"),
                     help="Output directory for all artefacts (default: secure_out/)")
    opt.add_argument("--fw-addr",  metavar="ADDR", type=lambda x: int(x, 0),
                     default=_FW_START_DEFAULT,
                     help=f"Firmware flash address (default: 0x{_FW_START_DEFAULT:08X})")
    opt.add_argument("--omit-ardupilot-keys", action="store_true",
                     help="Do not embed ArduPilot's 3 public keys in the bootloader")
    opt.add_argument("--upload",   action="store_true",
                     help="Upload firmware to board after build")
    opt.add_argument("--dry-run",  action="store_true",
                     help="Print commands without executing them")
    opt.add_argument("--waf-j",    metavar="N",    type=int,
                     default=os.cpu_count() or 4,
                     help="Parallel jobs for waf (default: cpu count)")
    opt.add_argument("--log-level",metavar="LVL",  default="info",
                     choices=["debug", "info", "warn"],
                     help="Logging verbosity (default: info)")

    return p.parse_args()


def main() -> int:
    global log
    args = parse_args()
    log  = Logger(args.log_level)

    t_start = time.monotonic()
    TOTAL   = 6 if args.upload else 5

    # ── Pre-flight checks ────────────────────────────────────────────────────
    if not args.params.exists():
        log.fail(f"Params file not found: {args.params}")
        return 3
    if not args.whitelist.exists():
        log.fail(f"Whitelist file not found: {args.whitelist}")
        return 3

    out_dir  = ensure_dir(args.out_dir)
    keys_dir = ensure_dir(args.keys_dir or out_dir / "keys")

    try:
        root = ardupilot_root()
    except RuntimeError as exc:
        log.fail(str(exc))
        return 3

    log.info(bold(f"\nArduPilot Secure Build  ·  board={args.board}  vehicle={args.vehicle}"))
    log.info(dim(f"  ArduPilot root : {root}"))
    log.info(dim(f"  Output dir     : {out_dir}"))
    log.info(dim(f"  Keys dir       : {keys_dir}"))

    # ── Step 1 ───────────────────────────────────────────────────────────────
    log.step(1, TOTAL, "Key Generation")
    try:
        priv_key, pub_key = step_keygen(
            args.vendor, keys_dir, dry_run=args.dry_run
        )
    except Exception as exc:
        log.fail(str(exc))
        return 1

    # ── Step 2 ───────────────────────────────────────────────────────────────
    log.step(2, TOTAL, "Secure Bootloader")
    try:
        bl_bin = step_bootloader(
            args.board, pub_key, out_dir,
            omit_ardupilot_keys=args.omit_ardupilot_keys,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        log.fail(str(exc))
        return 1

    # ── Step 3 ───────────────────────────────────────────────────────────────
    log.step(3, TOTAL, "Signed Firmware")
    try:
        fw_bin = step_firmware(
            args.board, args.vehicle, priv_key, out_dir,
            waf_j=args.waf_j,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        log.fail(str(exc))
        return 1

    # ── Step 4 ───────────────────────────────────────────────────────────────
    log.step(4, TOTAL, "Metadata Generation")
    try:
        meta_bin = step_metadata(
            fw_bin, args.params, args.whitelist, out_dir,
            fw_start_addr=args.fw_addr,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        log.fail(str(exc))
        return 1

    # ── Step 4b — Export locked params ───────────────────────────────────────
    try:
        export_locked_params(
            args.params, args.whitelist, out_dir,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        # Non-fatal: the build itself is valid; just warn.
        log.warn(f"Locked-param export failed (non-fatal): {exc}")

    # ── Step 5 ───────────────────────────────────────────────────────────────
    log.step(5, TOTAL, "Metadata Verification")
    try:
        ok = step_verify(
            meta_bin, fw_bin, args.params, args.whitelist,
            fw_start_addr=args.fw_addr,
            dry_run=args.dry_run,
        )
    except Exception as exc:
        log.fail(str(exc))
        return 2

    if not ok:
        log.fail("Metadata verification FAILED — build artefacts are inconsistent")
        return 2

    log.ok("Metadata verification PASSED")

    # ── Step 6 (optional) ────────────────────────────────────────────────────
    if args.upload:
        log.step(6, TOTAL, "Board Upload")
        try:
            step_upload(args.vehicle, out_dir, root, dry_run=args.dry_run)
        except Exception as exc:
            log.fail(str(exc))
            return 1

    # ── Manifest ─────────────────────────────────────────────────────────────
    elapsed  = time.monotonic() - t_start
    manifest = write_manifest(
        args, out_dir, priv_key, pub_key, bl_bin, fw_bin, meta_bin, elapsed
    )

    # ── Summary ──────────────────────────────────────────────────────────────
    bar = "═" * 60
    print(f"\n{green(bar)}")
    print(f"  {green(bold('✔  SECURE BUILD COMPLETE'))}")
    print(f"  Elapsed  : {elapsed:.1f}s")
    print(f"  Manifest : {manifest}")
    print(green(bar))
    print(textwrap.dedent(f"""
      Trust anchors sealed
        ├─ Code integrity   Ed25519 bootloader + signed .apj
        ├─ Param integrity  SHA-256 in metadata.bin  (CRC-32 verified)
        └─ Log integrity    Blake2b-256 chain + Ed25519 tail (compile flag)

      Flash order
        1. Secure bootloader → 0x08000000  ({bl_bin.name})
        2. Metadata          → 0x08020000  ({meta_bin.name})
        3. Signed firmware   → 0x{args.fw_addr:08X}  ({fw_bin.with_suffix('.apj').name})

      Locked params audit
        locked_params.txt   — human-readable table
        locked_params.csv   — spreadsheet import
    """))

    return 0


if __name__ == "__main__":
    sys.exit(main())