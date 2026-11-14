#!/usr/bin/env python3 -I
"""Generate valid seeds for the checksum end-to-end targets.

Usage:
  gen_seeds.py single OUTDIR   -> seed for test-checksum-target
  gen_seeds.py multi  OUTDIR   -> seed for test-checksum-multi-target

Kept dependency-free and run with python3 -I so no ambient modules on
sys.path can interfere.
"""

import os
import struct
import sys


def crc32_zlib(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1))
    return crc ^ 0xFFFFFFFF


def gen_single(outdir: str) -> None:
    payload = b"hello world!!"          # not "PASS", so the seed is benign
    total = 4 + len(payload) + 4
    pay_len = total - 4                 # bytes after the 4-byte header
    head = struct.pack("<HH", total, pay_len) + payload
    record = head + b"\x00\x00\x00\x00"
    crc = crc32_zlib(record)
    record = head + struct.pack("<I", crc)
    with open(os.path.join(outdir, "seed"), "wb") as f:
        f.write(record)


def gen_multi(outdir: str) -> None:
    region_a = b"abcdefgh"             # [0,8)
    region_b = b"01234567"             # [10,18)
    s = sum(region_a) & 0xFFFF
    x = 0
    for b in region_b:
        x ^= b
    x &= 0xFFFF
    head = region_a + struct.pack("<H", s) + region_b
    head += struct.pack("<H", x)
    assert len(head) == 20
    crc = crc32_zlib(head)
    record = head + struct.pack("<I", crc)
    with open(os.path.join(outdir, "seed"), "wb") as f:
        f.write(record)


def main() -> int:
    if len(sys.argv) != 3 or sys.argv[1] not in ("single", "multi"):
        sys.stderr.write("usage: gen_seeds.py {single|multi} OUTDIR\n")
        return 2
    os.makedirs(sys.argv[2], exist_ok=True)
    if sys.argv[1] == "single":
        gen_single(sys.argv[2])
    else:
        gen_multi(sys.argv[2])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
