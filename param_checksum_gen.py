#!/usr/bin/env python3

import sys
import hashlib
from pathlib import Path


# def parse_param_file(path):
#     """
#     Supports:
#       Mission Planner: PARAM,VALUE
#       QGC / whitespace: PARAM VALUE
#     """
#     params = {}

#     with open(path, "r", encoding="utf-8") as f:
#         for line in f:
#             line = line.strip()

#             if not line:
#                 continue

#             if line.startswith("#"):
#                 continue

#             if "," in line:
#                 parts = line.split(",", 1)
#             else:
#                 parts = line.split(None, 1)

#             if len(parts) != 2:
#                 continue

#             name = parts[0].strip()
#             value = parts[1].strip()

#             params[name] = value

#     return params

def parse_param_file(path):
    """
    Supports:
      1) Mission Planner CSV:
         PARAM,VALUE

      2) QGC whitespace:
         PARAM VALUE

      3) ArduPilot onboard export:
         VEHICLE COMPONENT PARAM VALUE TYPE
    """
    params = {}

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            # CSV format
            if "," in line:
                parts = [p.strip() for p in line.split(",")]

                if len(parts) >= 2:
                    params[parts[0]] = parts[1]
                    continue

            parts = line.split()

            # ArduPilot onboard export
            if len(parts) >= 5:
                vehicle_id = parts[0]
                component_id = parts[1]

                if vehicle_id.isdigit() and component_id.isdigit():
                    param_name = parts[2]
                    value = parts[3]
                    params[param_name] = value
                    continue

            # Simple whitespace format
            if len(parts) == 2:
                params[parts[0]] = parts[1]

    return params

def load_whitelist(path):
    whitelist = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            whitelist.append(line)

    return whitelist


def canonicalize_value(raw):
    """
    Match firmware format_entry():

    integer:
        NAME=1

    float whole:
        NAME=100

    float fractional:
        NAME=12.500000
    """
    try:
        val = float(raw)
    except ValueError:
        raise ValueError(f"Unsupported non-numeric value: {raw}")

    if abs(val - int(val)) < 1e-6:
        return str(int(val))

    return f"{val:.6f}"


def build_canonical(params, whitelist):
    lines = []

    for name in whitelist:
        if name not in params:
            raise KeyError(f"Missing whitelist parameter: {name}")

        value = canonicalize_value(params[name])
        lines.append(f"{name}={value}\n")

    return "".join(lines)


def format_c_array(digest):
    items = [f"0x{b:02X}" for b in digest]

    rows = []
    for i in range(0, len(items), 4):
        rows.append("    " + ", ".join(items[i:i+4]))

    return ",\n".join(rows)


def main():
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python3 param_checksum_gen.py <param_file> <whitelist_file>")
        sys.exit(1)

    param_file = Path(sys.argv[1])
    whitelist_file = Path(sys.argv[2])

    params = parse_param_file(param_file)
    whitelist = load_whitelist(whitelist_file)

    canonical = build_canonical(params, whitelist)

    with open("critical.param", "w", encoding="utf-8", newline="\n") as f:
        f.write(canonical)

    digest = hashlib.sha256(canonical.encode("utf-8")).digest()
    digest_hex = digest.hex().upper()

    print("Canonical input:")
    print(canonical, end="")

    print("\nSHA256:")
    print(digest_hex)

    print("\nC array:")
    print("{")
    print(format_c_array(digest))
    print("}")


if __name__ == "__main__":
    main()