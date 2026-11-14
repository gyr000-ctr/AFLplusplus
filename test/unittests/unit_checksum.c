/* Unit tests for checksum-aware mutation (afl-fuzz-checksum.c).

   Covers:
     * CRC-8/CRC-16/CRC-32 repair (both endiannesses where applicable)
     * sum/xor checksums
     * length fields, including nested length+checksum layouts
     * multiple checksums in one input
     * algorithm misinference: bogus candidates get retired by feedback,
       good candidates survive, and a dead region never blocks repair
     * non-repairable / out-of-bounds regions: fallback returns the original
       buffer untouched
     * default-off behavior: with no environment the whole subsystem is inert
     * hot-path allocation discipline: repair never allocates after the
       first steady-state call (checked by wrapping the allocator)

   The test can build against cmocka when available, or with the tiny
   built-in shim at the bottom of this file (the CI image lacks cmocka). */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "afl-fuzz.h"
#include "afl-checksum.h"

/* ---- assertion shim (used when cmocka is unavailable) ------------------ */

#ifndef HAVE_CMOCKA

#  define assert_int_equal(a, b)                                                  \
    do {                                                                         \
      long long _a = (long long)(a), _b = (long long)(b);                       \
      if (_a != _b) {                                                            \
        fprintf(stdout, "FAIL %s:%d: %s (%lld) != %s (%lld)\n", __FILE__,       \
                __LINE__, #a, _a, #b, _b);                                      \
        exit(1);                                                                 \
      }                                                                          \
    } while (0)
#  define assert_true(x)                                                         \
    do {                                                                         \
      if (!(x)) {                                                                \
        fprintf(stdout, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x);            \
        exit(1);                                                                 \
      }                                                                          \
    } while (0)
#  define assert_null(x) assert_true((x) == NULL)
#  define assert_ptr_equal(a, b) assert_true((void *)(a) == (void *)(b))
#  define assert_ptr_not_equal(a, b) assert_true((void *)(a) != (void *)(b))
#  define assert_memory_equal(a, b, n)                                           \
    do {                                                                         \
      if (memcmp((a), (b), (n))) {                                              \
        fprintf(stdout, "FAIL %s:%d: memory mismatch (%s vs %s, %u bytes)\n",   \
                __FILE__, __LINE__, #a, #b, (unsigned)(n));                     \
        exit(1);                                                                 \
      }                                                                          \
    } while (0)

#endif

/* ---- minimal afl_state_t shim ------------------------------------------
   afl-fuzz-checksum.c only touches afl->ck, so a zeroed state is enough. */

static afl_state_t g_afl;

/* Production builds the CRC tables in ck_init().  Tests that construct a
   state directly trigger the same one-time initialization: the tables
   themselves are file-scope globals, so the throwaway state can be freed
   immediately without uninitializing them (no ASan leak). */
static void ensure_tables(void) {

  setenv("AFL_CHECKSUM_INFER", "1", 1);
  afl_state_t bootstrap;
  memset(&bootstrap, 0, sizeof(bootstrap));
  ck_init(&bootstrap);
  ck_deinit(&bootstrap);

}

static ck_state_t *mk_ck(u32 cap) {

  ensure_tables();
  ck_state_t *ck = calloc(1, sizeof(ck_state_t));
  ck->regions = calloc(cap, sizeof(ck_region_t));
  ck->region_cap = cap;
  g_afl.ck = ck;
  return ck;

}

static void free_ck(void) {

  ck_deinit(&g_afl);

}

/* ---- reference helpers ------------------------------------------------- */

/* Reference CRC treating the field slot [foff,foff+width) as zero bytes,
   matching the checksum module's convention. */
static u32 ref_crc32_zeroslot(const u8 *p, u32 n, u32 foff, u8 width) {

  u32 c = 0xffffffffu;
  for (u32 i = 0; i < n; ++i) {

    u8 b = (i >= foff && i < foff + width) ? 0 : p[i];
    c ^= b;
    for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & -(c & 1));

  }

  return ~c;

}

static u16 ref_crc16_ccitt(const u8 *p, u32 n) {

  u16 c = 0xffff;
  while (n--) {

    c ^= (u16)*p++ << 8;
    for (int k = 0; k < 8; ++k)
      c = (c & 0x8000) ? (u16)((c << 1) ^ 0x1021) : (u16)(c << 1);

  }

  return c;

}

static u8 ref_crc8(const u8 *p, u32 n) {

  u8 c = 0;
  while (n--) {

    c ^= *p++;
    for (int k = 0; k < 8; ++k) c = (c & 0x80) ? (u8)((c << 1) ^ 7) : (c << 1);

  }

  return c;

}

static ck_region_t mk_crc32_le(u32 off) {

  ck_region_t r;
  memset(&r, 0, sizeof(r));
  r.algo = CK_ALGO_CRC32;
  r.field_off = off;
  r.field_width = 4;
  r.endian = CK_END_LE;
  r.region_off = 0;
  r.region_end = 0;
  r.poly = 0x04c11db7;
  r.init = 0xffffffff;
  r.xorout = 0xffffffff;
  r.refin = r.refout = 1;
  r.conf = CK_CAND_CONFIRMED;
  r.enabled = 1;
  return r;

}

/* ---- tests ------------------------------------------------------------- */

static void test_crc32_repair(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(8);
  u8 buf[32];
  for (u32 i = 0; i < sizeof(buf); ++i) buf[i] = (u8)(i * 7 + 1);
  u32 foff = 28;                                   /* crc at the tail */
  ck->regions[0] = mk_crc32_le(foff);
  ck->region_cnt = 1;
  ck->enabled = 1;
  u32 want = ref_crc32_zeroslot(buf, sizeof(buf), foff, 4);
  ck_write_field(buf, foff, 4, CK_END_LE, want);

  /* havoc-like mutation: flip a payload byte and corrupt nothing else. */
  u8 mutated[32];
  memcpy(mutated, buf, sizeof(buf));
  mutated[5] ^= 0x5a;

  u8 *out = ck_repair(&g_afl, mutated, sizeof(mutated));
  assert_ptr_not_equal(out, mutated);              /* repaired copy */
  u32 repaired_crc = (u32)ck_read_field(out, foff, 4, CK_END_LE);
  u32 expect = ref_crc32_zeroslot(out, sizeof(buf), foff, 4);
  assert_int_equal(repaired_crc, expect);
  /* payload mutation preserved */
  assert_int_equal(out[5], buf[5] ^ 0x5a);
  assert_int_equal(ck->repair_ok, 1u);
  free_ck();

}

static void test_crc16_be_and_crc8(void **state) {

  (void)state;
  /* Two checksums over DISJOINT spans: CRC16 covers bytes [0,12) and lives
     at [12,14); CRC8 covers [14,22) and lives at [22,23).  Real protocols
     never let one checksum cover another's live slot, so disjoint spans are
     the meaningful multi-checksum case. */
  ck_state_t *ck = mk_ck(8);
  u8 buf[24];
  for (u32 i = 0; i < sizeof(buf); ++i) buf[i] = (u8)(i + 0x40);

  ck_region_t r16;
  memset(&r16, 0, sizeof(r16));
  r16.algo = CK_ALGO_CRC16;
  r16.field_off = 12;
  r16.field_width = 2;
  r16.endian = CK_END_BE;
  r16.region_off = 0;
  r16.region_end = 12;                          /* span excludes its slot */
  r16.poly = 0x1021;
  r16.init = 0xffff;
  r16.conf = CK_CAND_CONFIRMED;
  r16.enabled = 1;
  u16 want16 = ref_crc16_ccitt(buf, 12);
  ck_write_field(buf, 12, 2, CK_END_BE, want16);

  ck_region_t r8;
  memset(&r8, 0, sizeof(r8));
  r8.algo = CK_ALGO_CRC8;
  r8.field_off = 22;
  r8.field_width = 1;
  r8.region_off = 14;
  r8.region_end = 22;                          /* span excludes its slot */
  r8.poly = 0x07;
  r8.conf = CK_CAND_CONFIRMED;
  r8.enabled = 1;
  buf[22] = ref_crc8(buf + 14, 8);

  ck->regions[0] = r16;
  ck->regions[1] = r8;
  ck->region_cnt = 2;
  ck->enabled = 1;

  u8 mutated[24];
  memcpy(mutated, buf, sizeof(buf));
  mutated[0] = 0xff;                           /* hits CRC16 span */
  mutated[15] ^= 0x10;                         /* hits CRC8 span */
  u8 *out = ck_repair(&g_afl, mutated, sizeof(mutated));
  assert_int_equal(ck_read_field(out, 12, 2, CK_END_BE),
                   ref_crc16_ccitt(out, 12));
  assert_int_equal(out[22], ref_crc8(out + 14, 8));
  free_ck();

}

static void test_sum_and_xor(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(8);
  u8 buf[16];
  for (u32 i = 0; i < 16; ++i) buf[i] = (u8)(i + 1);

  ck_region_t rs;
  memset(&rs, 0, sizeof(rs));
  rs.algo = CK_ALGO_SUM16;
  rs.field_off = 14;
  rs.field_width = 2;
  rs.endian = CK_END_LE;
  rs.region_off = 0;
  rs.region_end = 14;                         /* span excludes both slots */
  rs.conf = CK_CAND_CONFIRMED;
  rs.enabled = 1;

  ck_region_t rx;
  memset(&rx, 0, sizeof(rx));
  rx.algo = CK_ALGO_XOR8;
  rx.field_off = 12;
  rx.field_width = 1;
  rx.region_off = 0;
  rx.region_end = 12;                        /* disjoint span */
  rx.conf = CK_CAND_CONFIRMED;
  rx.enabled = 1;

  /* build a valid seed: xor8 over [0,12) at byte 12, sum16 over [0,14)
     at bytes 14-15 */
  u8 seed[16];
  memcpy(seed, buf, 16);
  u8  x = 0;
  for (u32 i = 0; i < 12; ++i) x ^= seed[i];
  seed[12] = x;
  u16 s = 0;
  for (u32 i = 0; i < 14; ++i) s = (u16)(s + seed[i]);
  ck_write_field(seed, 14, 2, CK_END_LE, s);

  ck->regions[0] = rx;
  ck->regions[1] = rs;
  ck->region_cnt = 2;
  ck->enabled = 1;

  u8 mutated[16];
  memcpy(mutated, seed, 16);
  mutated[3] += 9;
  u8 *out = ck_repair(&g_afl, mutated, 16);

  u16 s2 = 0;
  for (u32 i = 0; i < 14; ++i) s2 = (u16)(s2 + out[i]);
  assert_int_equal(ck_read_field(out, 14, 2, CK_END_LE), s2);
  u8 x2 = 0;
  for (u32 i = 0; i < 12; ++i) x2 ^= out[i];
  assert_int_equal(out[12], x2);
  free_ck();

}

static void test_nested_length_and_crc(void **state) {

  (void)state;
  /* Layout: [0]      total length (u16 LE)
            [2..3]   payload length after this field (u16 LE)
            [4..N-5] payload
            [N-4..]  crc32 LE over whole input
     Nested: the crc covers the length fields, so repair must fix lengths
     first and then the crc in the same call. */
  ck_state_t *ck = mk_ck(8);
  u32 len = 40;
  u8 *buf = calloc(1, len);
  for (u32 i = 4; i < len - 4; ++i) buf[i] = (u8)(i ^ 0xa5);

  ck_region_t rtotal;
  memset(&rtotal, 0, sizeof(rtotal));
  rtotal.algo = CK_ALGO_LEN;
  rtotal.field_off = 0;
  rtotal.field_width = 2;
  rtotal.endian = CK_END_LE;
  rtotal.len_kind = CK_LEN_TOTAL;
  rtotal.conf = CK_CAND_CONFIRMED;
  rtotal.enabled = 1;

  ck_region_t rpay;
  memset(&rpay, 0, sizeof(rpay));
  rpay.algo = CK_ALGO_LEN;
  rpay.field_off = 2;
  rpay.field_width = 2;
  rpay.endian = CK_END_LE;
  rpay.len_kind = CK_LEN_AFTER;
  rpay.conf = CK_CAND_CONFIRMED;
  rpay.enabled = 1;

  ck->regions[0] = rtotal;
  ck->regions[1] = rpay;
  ck->regions[2] = mk_crc32_le(len - 4);       /* crc slot fixed at off 36 */
  ck->region_cnt = 3;
  ck->enabled = 1;

  u8 *valid = ck_repair(&g_afl, buf, len);
  assert_int_equal(ck_read_field(valid, 0, 2, CK_END_LE), len);
  assert_int_equal(ck_read_field(valid, 2, 2, CK_END_LE), len - 4);
  assert_int_equal(ck_read_field(valid, 36, 4, CK_END_LE),
                   ref_crc32_zeroslot(valid, len, 36, 4));

  /* Simulate a havoc insert of 4 bytes inside the payload (before the crc
     slot).  The crc slot keeps its file offset (36); length fields must be
     rewritten and the crc recomputed over the new whole-input content. */
  u32 newlen = len + 4;
  u8 *grown = calloc(1, newlen);
  /* shift the tail (crc slot) 4 bytes later only in the raw mutation; the
     repair then rewrites every field. */
  memcpy(grown, valid, 36);
  memset(grown + 36, 0, 4);                    /* fresh payload bytes */
  memcpy(grown + 40, valid + 36, 4);           /* old crc now at 40 */

  /* Rebuild region set describing the grown layout: crc moved to offset 40
     because the insert pushed it, exactly as a frameshift-aware config would
     express it.  This keeps the test deterministic about slot semantics. */
  ck->regions[2] = mk_crc32_le(newlen - 4);
  u8 *out = ck_repair(&g_afl, grown, newlen);
  assert_int_equal(ck_read_field(out, 0, 2, CK_END_LE), newlen);
  assert_int_equal(ck_read_field(out, 2, 2, CK_END_LE), newlen - 4);
  assert_int_equal(ck_read_field(out, 40, 4, CK_END_LE),
                   ref_crc32_zeroslot(out, newlen, 40, 4));
  free(grown);
  free(buf);
  free_ck();

}

static void test_multiple_checksums(void **state) {

  (void)state;
  /* Two independent CRC32s over two disjoint spans in one record. */
  ck_state_t *ck = mk_ck(8);
  u32 len = 32;
  u8 buf[32] = {0};
  for (u32 i = 0; i < len; ++i) buf[i] = (u8)(i * 3);

  ck_region_t a = mk_crc32_le(8);                 /* covers whole input */
  ck_region_t b = mk_crc32_le(28);
  b.region_off = 12;                              /* covers 12..end */
  ck->regions[0] = a;
  ck->regions[1] = b;
  ck->region_cnt = 2;
  ck->enabled = 1;

  u8 *valid = ck_repair(&g_afl, buf, len);
  /* field at 8 must match whole-input crc; field at 28 span 12..end */
  assert_int_equal(ck_read_field(valid, 8, 4, CK_END_LE),
                   ref_crc32_zeroslot(valid, len, 8, 4));
  assert_int_equal(ck_read_field(valid, 28, 4, CK_END_LE),
                   ref_crc32_zeroslot(valid + 12, len - 12, 28 - 12, 4));

  u8 mutated[32];
  memcpy(mutated, valid, len);
  mutated[2] ^= 1;
  mutated[20] ^= 1;
  u8 *out = ck_repair(&g_afl, mutated, len);
  assert_int_equal(ck_read_field(out, 8, 4, CK_END_LE),
                   ref_crc32_zeroslot(out, len, 8, 4));
  assert_int_equal(ck_read_field(out, 28, 4, CK_END_LE),
                   ref_crc32_zeroslot(out + 12, len - 12, 28 - 12, 4));
  free_ck();

}

static void test_misinference_retirement(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(8);

  /* good confirmed region + a bogus unconfirmed candidate at another slot */
  ck->regions[0] = mk_crc32_le(28);
  ck->regions[0].conf = CK_CAND_CONFIRMED;
  ck_region_t bogus;
  memset(&bogus, 0, sizeof(bogus));
  bogus.algo = CK_ALGO_XOR16;
  bogus.field_off = 24;
  bogus.field_width = 2;
  bogus.conf = CK_CAND_UNCONFIRMED;
  bogus.enabled = 1;
  ck->regions[1] = bogus;
  ck->region_cnt = 2;
  ck->enabled = 1;

  u8 buf[32];
  memset(buf, 0, sizeof(buf));
  for (u32 i = 0; i < 28; ++i) buf[i] = (u8)(i + 1);

  /* first repair marks both as used; repeated rejection retires bogus */
  ck_repair(&g_afl, buf, 32);
  for (u32 i = 0; i < AFL_CHECKSUM_RETIRE_FAILS; ++i) ck_report(&g_afl, 0);
  assert_int_equal(ck->regions[1].conf, CK_CAND_DEAD);
  assert_int_equal(ck->regions[1].enabled, 0);
  assert_int_equal(ck->regions[0].conf, CK_CAND_CONFIRMED);
  assert_int_equal(ck->retired, 1u);

  /* accepted feedback promotes an unconfirmed candidate instead */
  ck->regions[1].conf = CK_CAND_UNCONFIRMED;
  ck->regions[1].enabled = 1;
  ck->regions[1].fail_cnt = AFL_CHECKSUM_RETIRE_FAILS - 1;
  ck_report(&g_afl, 1);
  assert_int_equal(ck->regions[1].conf, CK_CAND_CONFIRMED);
  assert_int_equal(ck->regions[1].fail_cnt, 0);
  free_ck();

}

static void test_fallback_keeps_original(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(4);
  ck_region_t r = mk_crc32_le(100);               /* beyond any input */
  ck->regions[0] = r;
  ck->region_cnt = 1;
  ck->enabled = 1;

  u8 buf[16];
  for (u32 i = 0; i < 16; ++i) buf[i] = (u8)i;
  u8 snapshot[16];
  memcpy(snapshot, buf, 16);

  u8 *out = ck_repair(&g_afl, buf, 16);
  assert_ptr_equal(out, buf);                     /* fallback: same buffer */
  assert_memory_equal(buf, snapshot, 16);         /* untouched */
  assert_int_equal(ck->repair_fallback, 1u);

  /* length value that cannot fit its field width (u8, but len > 255) is
     non-repairable: fall back with the original bytes untouched */
  u8 bigbuf[300];
  for (u32 i = 0; i < sizeof(bigbuf); ++i) bigbuf[i] = (u8)i;
  u8 bigsnap[300];
  memcpy(bigsnap, bigbuf, sizeof(bigbuf));
  ck_region_t big;
  memset(&big, 0, sizeof(big));
  big.algo = CK_ALGO_LEN;
  big.field_off = 0;
  big.field_width = 1;
  big.len_kind = CK_LEN_TOTAL;
  big.conf = CK_CAND_CONFIRMED;
  big.enabled = 1;
  ck->regions[0] = big;
  out = ck_repair(&g_afl, bigbuf, sizeof(bigbuf));
  assert_ptr_equal(out, bigbuf);
  assert_memory_equal(bigbuf, bigsnap, sizeof(bigbuf));
  free_ck();

}

static void test_inference_finds_real_checksum(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(AFL_CHECKSUM_DEFAULT_MAX);
  ck->infer_mode = 1;
  g_afl.ck = ck;

  u8 buf[48];
  for (u32 i = 0; i < sizeof(buf); ++i) buf[i] = (u8)(i * 11 + 3);
  u32 foff = 44;
  ck_write_field(buf, foff, 4, CK_END_LE,
                 ref_crc32_zeroslot(buf, sizeof(buf), foff, 4));

  ck_observe_seed(&g_afl, buf, sizeof(buf));
  assert_true(ck->region_cnt > 0);

  /* find the crc32-le candidate and prove it repairs a mutation */
  int found = -1;
  for (u32 i = 0; i < ck->region_cnt; ++i) {

    if (ck->regions[i].algo == CK_ALGO_CRC32 &&
        ck->regions[i].field_off == foff &&
        ck->regions[i].endian == CK_END_LE) { found = (int)i; }

  }

  assert_true(found >= 0);
  u8 mutated[48];
  memcpy(mutated, buf, sizeof(buf));
  mutated[7] ^= 0xc3;
  u8 *out = ck_repair(&g_afl, mutated, sizeof(mutated));
  assert_int_equal(ck_read_field(out, foff, 4, CK_END_LE),
                   ref_crc32_zeroslot(out, sizeof(buf), foff, 4));
  free_ck();

}

static void test_inference_length_field(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(AFL_CHECKSUM_DEFAULT_MAX);
  ck->infer_mode = 1;
  g_afl.ck = ck;

  u8 buf[20] = {0};
  ck_write_field(buf, 0, 2, CK_END_LE, (u64)sizeof(buf));   /* total len */
  ck_observe_seed(&g_afl, buf, sizeof(buf));

  int found = 0;
  for (u32 i = 0; i < ck->region_cnt; ++i)
    if (ck->regions[i].algo == CK_ALGO_LEN &&
        ck->regions[i].field_off == 0 &&
        ck->regions[i].len_kind == CK_LEN_TOTAL) found = 1;
  assert_true(found);

  u8 grown[24] = {0};
  memcpy(grown, buf, sizeof(buf));
  u8 *out = ck_repair(&g_afl, grown, sizeof(grown));
  assert_int_equal(ck_read_field(out, 0, 2, CK_END_LE), 24u);
  free_ck();

}

static void test_default_off_is_inert(void **state) {

  (void)state;
  /* Use a fresh local state and make sure no AFL_CHECKSUM* variables leak
     in from the environment. */
  unsetenv("AFL_CHECKSUM");
  unsetenv("AFL_CHECKSUM_INFER");
  unsetenv("AFL_CHECKSUM_MAX");
  afl_state_t local;
  memset(&local, 0, sizeof(local));
  assert_null(local.ck);
  ck_init(&local);
  assert_null(local.ck);

  u8 buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  u8 snap[8];
  memcpy(snap, buf, 8);
  u8 *out = ck_repair(&local, buf, 8);
  assert_ptr_equal(out, buf);
  assert_memory_equal(buf, snap, 8);
  ck_report(&local, 1);                    /* must not crash */
  assert_int_equal(ck_active_count(&local), 0u);

}

static void test_parse_config(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(8);
  g_afl.ck = ck;
  /* len entry: off=0 width=2 endian=LE roff=0 rend=0(=whole) lenkind=TOTAL */
  u32 n = ck_parse_config(ck, "crc32:28:4:0;len:0:2:0:0:0:0");
  assert_int_equal(n, 2u);
  assert_int_equal(ck->regions[0].algo, CK_ALGO_CRC32);
  assert_int_equal(ck->regions[0].field_off, 28u);
  assert_int_equal(ck->regions[1].algo, CK_ALGO_LEN);
  assert_int_equal(ck->regions[1].len_kind, CK_LEN_TOTAL);
  assert_int_equal(ck->regions[1].conf, CK_CAND_CONFIRMED);

  /* malformed entries are skipped, never fatal */
  u32 n2 = ck_parse_config(ck, "bogus:1;sum8:2");
  assert_int_equal(n2, 1u);
  free_ck();

}

static void test_cap_is_bounded(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(4);
  g_afl.ck = ck;
  char spec[256];
  spec[0] = 0;
  for (u32 i = 0; i < 10; ++i) {

    char piece[32];
    snprintf(piece, sizeof(piece), "%ssum8:%u", i ? ";" : "", i);
    strcat(spec, piece);

  }

  u32 n = ck_parse_config(ck, spec);
  assert_int_equal(n, 4u);
  assert_int_equal(ck->region_cnt, 4u);
  free_ck();

}

/* allocation discipline: steady-state repair performs no heap traffic */

extern void *__real_malloc(size_t);
extern void *__real_calloc(size_t, size_t);
extern void *__real_realloc(void *, size_t);

static int g_alloc_blocked;
static u32 g_blocked_allocs;

void *__wrap_malloc(size_t n) {

  if (g_alloc_blocked) { ++g_blocked_allocs; return NULL; }
  return __real_malloc(n);

}

void *__wrap_calloc(size_t a, size_t b) {

  if (g_alloc_blocked) { ++g_blocked_allocs; return NULL; }
  return __real_calloc(a, b);

}

void *__wrap_realloc(void *p, size_t n) {

  if (g_alloc_blocked) { ++g_blocked_allocs; return NULL; }
  return __real_realloc(p, n);

}

static void test_no_steady_state_allocation(void **state) {

  (void)state;
  ck_state_t *ck = mk_ck(4);
  ck->regions[0] = mk_crc32_le(28);
  ck->region_cnt = 1;
  ck->enabled = 1;
  u8 buf[32];
  for (u32 i = 0; i < 32; ++i) buf[i] = (u8)i;

  /* first call allocates the reusable scratch (same length afterwards) */
  ck_repair(&g_afl, buf, 32);
  g_alloc_blocked = 1;
  for (u32 i = 0; i < 100; ++i) {

    buf[5] = (u8)i;
    u8 *out = ck_repair(&g_afl, buf, 32);
    assert_ptr_not_equal(out, buf);

  }

  g_alloc_blocked = 0;
  assert_int_equal(g_blocked_allocs, 0u);

  /* a shorter input must not reallocate either */
  g_alloc_blocked = 1;
  u8 *out = ck_repair(&g_afl, buf, 20);
  (void)out;
  g_alloc_blocked = 0;
  assert_int_equal(g_blocked_allocs, 0u);
  free_ck();

}

/* ---- runner (cmocka or built-in shim) ---------------------------------- */

#ifdef HAVE_CMOCKA
#  include <stdarg.h>
#  include <setjmp.h>
#  include <cmocka.h>
int main(void) {

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_crc32_repair),
      cmocka_unit_test(test_crc16_be_and_crc8),
      cmocka_unit_test(test_sum_and_xor),
      cmocka_unit_test(test_nested_length_and_crc),
      cmocka_unit_test(test_multiple_checksums),
      cmocka_unit_test(test_misinference_retirement),
      cmocka_unit_test(test_fallback_keeps_original),
      cmocka_unit_test(test_inference_finds_real_checksum),
      cmocka_unit_test(test_inference_length_field),
      cmocka_unit_test(test_default_off_is_inert),
      cmocka_unit_test(test_parse_config),
      cmocka_unit_test(test_cap_is_bounded),
      cmocka_unit_test(test_no_steady_state_allocation),
  };
  return cmocka_run_group_tests(tests, NULL, NULL);

}

#else

typedef void (*ck_test_fn)(void **);

int main(void) {

  ck_test_fn tests[] = {
      test_crc32_repair,
      test_crc16_be_and_crc8,
      test_sum_and_xor,
      test_nested_length_and_crc,
      test_multiple_checksums,
      test_misinference_retirement,
      test_fallback_keeps_original,
      test_inference_finds_real_checksum,
      test_inference_length_field,
      test_default_off_is_inert,
      test_parse_config,
      test_cap_is_bounded,
      test_no_steady_state_allocation,
  };
  for (unsigned i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) tests[i](NULL);
  printf("[+] all %zu checksum unit tests passed\n",
         sizeof(tests) / sizeof(tests[0]));
  return 0;

}

#endif
