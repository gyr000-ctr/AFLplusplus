/*
   american fuzzy lop++ - checksum-aware mutation support
   -------------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

/* This module implements checksum/length-aware post-mutation repair.

   When a target validates integrity fields (CRC, additive checksums,
   length prefixes, ...), generic havoc mutations flip payload bytes and
   get rejected before reaching any interesting code.  This module keeps a
   bounded table of known or inferred checksum regions and, after the
   ordinary mutation pipeline has produced a candidate, recomputes every
   region so the target accepts the mutated input.

   Design constraints (see docs/checksum.md):

   * Disabled by default - when AFL_CHECKSUM / AFL_CHECKSUM_INFER are not
     set, every entry point is a cheap no-op and the default mutation path
     is byte-for-byte unchanged.
   * The hot repair path never allocates heap memory.  The region table is
     fixed size (AFL_CHECKSUM_MAX, hard upper bound AFL_CHECKSUM_HARD_MAX)
     and the only scratch buffer is allocated once and grown only when the
     input length grows.
   * On any failure (region out of bounds, non-repairable layout, dead
     candidate) the caller falls back to the original, unmodified mutation
     instead of shipping a corrupted input.
   * Inference is static (seed-driven) with a bounded candidate set; target
     feedback only promotes/demotes candidates, it never grows the table
     past the configured bound.

 */

#ifndef AFL_CHECKSUM_H
#define AFL_CHECKSUM_H

#include "afl-fuzz.h"

/* Hard upper bound for the region/candidate table, regardless of what
   AFL_CHECKSUM_MAX requests.  Keeps per-iteration repair work and the
   fixed-size state allocation bounded. */
#define AFL_CHECKSUM_HARD_MAX 32

/* Default region table size when the feature is enabled without an
   explicit AFL_CHECKSUM_MAX. */
#define AFL_CHECKSUM_DEFAULT_MAX 16

/* Inputs larger than this are not scanned byte-by-byte by the inference
   engine in auto mode (repair still works on them). */
#define AFL_CHECKSUM_INFER_SCAN_MAX (256 * 1024)

/* How many consecutive target-observed failures retire a candidate that
   static inference could not confirm against the seed. */
#define AFL_CHECKSUM_RETIRE_FAILS 32

/* Auto inference examines at most this many seeds: the candidate table is
   bounded and the first few valid seeds already expose header layouts. */
#define AFL_CHECKSUM_MAX_OBSERVED_SEEDS 16

/* Checksum / integrity field algorithms. */
typedef enum {

  CK_ALGO_NONE = 0,

  /* CRC family, polynomial encoded in the region descriptor. */
  CK_ALGO_CRC8 = 1,
  CK_ALGO_CRC16,
  CK_ALGO_CRC32,

  /* Simple sums (mod 2^width), and XOR folding. */
  CK_ALGO_SUM8,
  CK_ALGO_SUM16,
  CK_ALGO_SUM32,
  CK_ALGO_XOR8,
  CK_ALGO_XOR16,
  CK_ALGO_XOR32,

  /* Length fields: the stored value describes a region of the input. */
  CK_ALGO_LEN,

  CK_ALGO_MAX

} ck_algo_t;

/* Endianness of a multi-byte field. CK_END_NATIVE is only used by
   inference bookkeeping and never stored in an active region. */
typedef enum {

  CK_END_LE = 0,
  CK_END_BE = 1

} ck_endian_t;

/* For CK_ALGO_LEN: what the stored value measures. */
typedef enum {

  /* total input length */
  CK_LEN_TOTAL = 0,
  /* payload length: bytes after the field itself */
  CK_LEN_AFTER,
  /* payload length: bytes before the field */
  CK_LEN_BEFORE,
  /* payload length between an anchor offset and the end of input */
  CK_LEN_ANCHORED,
  /* payload length between two anchor offsets */
  CK_LEN_SPAN

} ck_len_kind_t;

/* Candidate confidence.  Explicit configuration is always CONFIRMED;
   statically inferred candidates start UNCONFIRMED and get promoted by
   target feedback or retired after repeated failures. */
typedef enum {

  CK_CAND_UNCONFIRMED = 0,
  CK_CAND_CONFIRMED = 1,
  CK_CAND_DEAD = 2

} ck_conf_t;

/* One checksum/length region.  Stored in a fixed-size array inside
   ck_state_t, so this struct must stay small and contain no pointers. */
typedef struct ck_region {

  u32 field_off;                       /* offset of the checksum field     */
  u8  field_width;                     /* 1, 2 or 4 bytes                  */
  u8  algo;                            /* ck_algo_t                        */
  u8  endian;                          /* ck_endian_t                      */
  u8  conf;                            /* ck_conf_t                        */

  /* Checksummed data span.  For length fields these describe the measured
     payload instead.  region_end == 0 means "until end of input". */
  u32 region_off;
  u32 region_end;                      /* exclusive; 0 == input len        */

  /* CRC polynomial / init / xorout parameters (width-agnostic, unused
     fields are zero). */
  u32 poly;
  u32 init;
  u32 xorout;
  u8  refin;                           /* reflect input bytes              */
  u8  refout;                          /* reflect remainder                */

  /* CK_ALGO_LEN specifics. */
  u8  len_kind;                        /* ck_len_kind_t                    */
  u32 anchor_off;                      /* CK_LEN_ANCHORED / CK_LEN_SPAN    */
  u32 anchor_end;                      /* CK_LEN_SPAN                      */

  /* Feedback accounting for misinference retirement (unconfirmed only). */
  u32 fail_cnt;
  u32 use_cnt;

  u8 enabled;

} ck_region_t;

/* Whole checksum subsystem state, embedded in afl_state_t (one pointer,
   allocated once).  Contains no per-iteration heap state beyond the single
   reusable scratch buffer. */
typedef struct ck_state {

  ck_region_t *regions;                /* fixed-size table, allocated once */
  u32          region_cap;             /* table capacity (<= HARD_MAX)     */
  u32          region_cnt;             /* active + dead entries            */

  /* Reusable scratch for repair: holds a copy of the mutated input while
     regions are recomputed.  Grown with realloc only when input length
     grows, never per fuzzing round. */
  u8  *scratch;
  u32  scratch_size;

  u8   enabled;                        /* any region configured/inferred?  */
  u8   infer_mode;                     /* 0=off 1=auto 2=off but configured*/
  u32  infer_seed_cnt;                 /* seeds already examined           */
  u32  repair_calls;
  u32  repair_ok;
  u32  repair_fallback;
  u32  retired;

} ck_state_t;

/* Lifecycle ----------------------------------------------------------------
 */

/* Parse AFL_CHECKSUM / AFL_CHECKSUM_INFER / AFL_CHECKSUM_MAX and allocate
   the fixed-size state.  Cheap when the feature is not requested. */
void ck_init(afl_state_t *afl);

/* Free state (called from afl_state_deinit). */
void ck_deinit(afl_state_t *afl);

/* Feed one valid seed to the inference engine.  No-op unless auto inference
   is enabled.  Bounded: returns once the table is full or the scan budget
   for this seed is exhausted. */
void ck_observe_seed(afl_state_t *afl, const u8 *buf, u32 len);

/* Repair -------------------------------------------------------------------
 */

/* Recompute every enabled, currently applicable region over buf/len and
   write the corrected fields.  Returns the buffer to execute (always valid
   for `len` bytes):
     * on success it may be buf (repaired in place) or afl->ck->scratch;
     * on failure it equals buf, left byte-for-byte untouched, so the
       caller simply runs the original mutation.
   Never allocates in the steady state. */
u8 *ck_repair(afl_state_t *afl, u8 *buf, u32 len);

/* Feedback: note whether a repaired input was accepted by the target
   (non-crash early rejection vs. deeper execution is inferred by the
   caller from coverage change).  Used to retire misinferred candidates. */
void ck_report(afl_state_t *afl, u8 accepted);

/* Introspection for the UI / stats file. */
u32  ck_active_count(afl_state_t *afl);
const char *ck_algo_name(u8 algo);

/* Exposed for unit tests: low-level field and algorithm primitives. */
u64  ck_read_field(const u8 *buf, u32 off, u8 width, u8 endian);
void ck_write_field(u8 *buf, u32 off, u8 width, u8 endian, u64 value);
u64  ck_compute(const ck_region_t *r, const u8 *buf, u32 len);
u8   ck_region_applies(const ck_region_t *r, u32 len);

/* Explicit config string parsing, returns number of regions added (0 on
   error).  Format documented in docs/checksum.md:
     algo:off[:width[:endian[:roff[:rend[:extra...]]]][;...] */
u32 ck_parse_config(ck_state_t *ck, const char *spec);

#endif                                               /* AFL_CHECKSUM_H */
