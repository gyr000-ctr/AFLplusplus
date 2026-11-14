# Checksum-aware mutation

Many targets validate an integrity field — a CRC, an additive checksum, or a
length prefix — before doing any real work. Generic havoc mutations flip
payload bytes and break that field, so the target rejects almost every input
early and coverage stalls. `afl-analyze` can flag a *suspected* checksum
block but cannot repair it.

The checksum-aware mutation layer fixes this: it keeps a bounded table of
known or inferred checksum/length regions and, after the ordinary mutation
pipeline has produced a candidate input, recomputes every region so the
target accepts the mutated payload.

The feature is **off by default**. With no `AFL_CHECKSUM*` variables set the
repair entry points are a single NULL check, no state is allocated, and the
default mutation path is byte-for-byte unchanged.

## Environment variables

| Variable | Purpose |
| --- | --- |
| `AFL_CHECKSUM` | Explicit region specification (see below). |
| `AFL_CHECKSUM_INFER` | Set to `1` to additionally infer regions from valid seeds. |
| `AFL_CHECKSUM_MAX` | Region table capacity. Default `16`, hard upper bound `32`. |

### `AFL_CHECKSUM` region syntax

Regions are separated by `;`. Each region is a colon-separated list:

```
algo:field_off[:width[:endian[:region_off[:region_end[:extra...]]]]]
```

* `algo`: one of `crc8`, `crc16`, `crc32`, `sum8`, `sum16`, `sum32`,
  `xor8`, `xor16`, `xor32`, `len`.
* `field_off`: byte offset of the checksum/length field.
* `width`: field width in bytes, `1`, `2` or `4`. Defaults to the natural
  width of the algorithm.
* `endian`: `0` little-endian (default), `1` big-endian.
* `region_off` / `region_end`: the data span the field covers.
  `region_end = 0` means "up to the end of the input". Both default to the
  whole input. When the field slot lies inside the span it is treated as
  zero bytes while computing, the standard "checksum over everything except
  the checksum slot" convention. For clarity, prefer configuring spans that
  exclude the slot.
* extra fields:
  * for `len`: `len_kind[:anchor_off[:anchor_end]]`, where `len_kind` is
    `0` total length, `1` bytes after the field, `2` bytes before the field,
    `3` anchored (`len - anchor_off`), `4` span (`anchor_end - anchor_off`).
  * for CRC algorithms: an optional polynomial override.

CRC defaults are the common industry variants: CRC-8 poly `0x07`,
CRC-16/CCITT-FALSE (`0x1021`, init `0xffff`), and CRC-32/ISO-HDLC (zlib,
init/xorout `0xffffffff`, reflected).

Example — a 16-bit total length at offset 0, a payload length at offset 2,
and a little-endian CRC-32 at the last four bytes of a 21-byte record:

```sh
AFL_CHECKSUM="len:0:2:0:0:0:0;len:2:2:0:0:0:1;crc32:17:4:0:0:0" \
  afl-fuzz -i in -o out -- ./target
```

## Algorithms

* **CRC**: `crc8` / `crc16` / `crc32`, reflected and non-reflected table
  variants, with configurable polynomial/init/xorout and endianness.
* **Sum**: byte-wise additive checksum folded to 8/16/32 bits.
* **XOR**: byte-wise XOR folded to 8/16/32 bits.
* **Length**: total length, payload-before/after, anchored and span length
  fields, in either endianness. Nested length fields are all re-evaluated
  against the new input length.

## Multiple and nested regions

Any number of regions up to `AFL_CHECKSUM_MAX` may be configured. Length
fields are repaired first (they depend only on layout). Checksum fields are
then iterated to a fixed point, so a CRC that covers a length field always
sees the corrected value. The number of sweeps is bounded by the number of
applicable regions plus one, independent of input size.

Checksums whose spans overlap another checksum's live slot are unusual;
prefer disjoint spans (the common protocol design).

## Inference and misinference

With `AFL_CHECKSUM_INFER=1`, each of the first few valid queue entries is
scanned. For every plausible field offset a small, bounded candidate set is
tested: CRC-32/16/8 (both endiannesses), 32/16/8-bit sums and XORs, and
length relationships. A candidate is kept only if it reproduces the value
already stored in the seed.

Inferred candidates start *unconfirmed*. Target feedback promotes a
candidate when a repaired input produces a find, and retires it after a
fixed number of unproductive repairs, so a wrong guess is removed instead
of corrupting inputs. Explicitly configured regions are always treated as
confirmed.

## Non-repairable inputs and fallback

Repair never destroys an input. If no region applies (e.g. the field is out
of bounds for the current length), a length value does not fit its field
width, or memory cannot be grown, `ck_repair()` returns the original
mutated buffer untouched and the ordinary mutation is executed as-is.

## Allocation and performance guarantees

* The region table is fixed size and allocated once.
* The only scratch buffer is allocated once and grown only when the input
  length grows. The steady-state repair path performs **no heap
  allocation**, even for inputs approaching `MAX_FILE`; per-iteration work
  is proportional to the covered spans and the region count, never to a
  fresh allocation sized to the input.
* CRC tables are `const`-style static globals built a single time.

## Interaction with custom mutators and persistent mode

Repair runs on the buffer produced by the standard havoc/splice pipeline and
also on the output of custom mutators (`afl_custom_fuzz` and the stacked
`afl_custom_havoc_mutation` path). A custom mutator's own buffer is never
modified; repair copies into the reusable scratch first. Because repair sits
in the buffer layer before `common_fuzz_stuff()`, it applies identically to
fork-server and persistent execution.

Repair is applied to the random havoc, splice and custom-mutator stages,
which account for essentially all sustained fuzzing executions. The
one-shot deterministic stages (bit flips, arithmetic, interesting values,
dictionary) are not repaired; for checksum-protected targets pass `-d` to
skip them, as is standard practice.

## Testing

* Unit tests (CRC/length/multi-checksum/misinference/fallback/allocation
  discipline, with a built-in shim when cmocka is absent):
  `make unit_checksum`.
* End-to-end tests using plain-compiled targets in dumb mode:
  `test/test-checksum.sh`.
