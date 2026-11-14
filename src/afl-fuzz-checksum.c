/*
   american fuzzy lop++ - checksum-aware mutation support
   -------------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

#include "afl-checksum.h"

#include <inttypes.h>

/* Tables are const/static: no per-iteration allocation, and shared across
   all fuzzer instances.  Only the polynomials actually used by inference
   and the documented config syntax are listed. */

/* CRC-32 (ISO 3309 / zlib), reflected. */
static u32 crc32_table[256];
/* CRC-16/CCITT-FALSE and CRC-16/IBM (MODBUS), both non-reflected in. */
static u16 crc16_ccitt_table[256];
static u16 crc16_ibm_table[256];
/* CRC-8/SMBUS (poly 0x07). */
static u8 crc8_table[256];

static u8 tables_initialized = 0;

static u8 reflect8(u8 v) {

  u8 r = 0;
  for (u32 i = 0; i < 8; ++i) {

    r = (u8)((r << 1) | (v & 1));
    v >>= 1;

  }

  return r;

}

static u32 reflect32(u32 v) {

  u32 r = 0;
  for (u32 i = 0; i < 32; ++i) {

    r = (r << 1) | (v & 1);
    v >>= 1;

  }

  return r;

}

static void ck_init_tables(void) {

  if (tables_initialized) return;

  for (u32 i = 0; i < 256; ++i) {

    /* CRC-32 poly 0xEDB88320 (reflected 0x04C11DB7) */
    u32 c32 = i;
    for (u32 k = 0; k < 8; ++k)
      c32 = (c32 & 1) ? (0xEDB88320u ^ (c32 >> 1)) : (c32 >> 1);
    crc32_table[i] = c32;

    /* CRC-16/CCITT poly 0x1021, MSB-first */
    u16 c16 = (u16)(i << 8);
    for (u32 k = 0; k < 8; ++k)
      c16 = (c16 & 0x8000) ? (u16)((c16 << 1) ^ 0x1021) : (u16)(c16 << 1);
    crc16_ccitt_table[i] = c16;

    /* CRC-16/IBM poly 0x8005, MSB-first table (reflected use handled in
       the compute routine) */
    c16 = (u16)(i << 8);
    for (u32 k = 0; k < 8; ++k)
      c16 = (c16 & 0x8000) ? (u16)((c16 << 1) ^ 0x8005) : (u16)(c16 << 1);
    crc16_ibm_table[i] = c16;

    /* CRC-8 poly 0x07 */
    u8 c8 = (u8)i;
    for (u32 k = 0; k < 8; ++k)
      c8 = (c8 & 0x80) ? (u8)((c8 << 1) ^ 0x07) : (u8)(c8 << 1);
    crc8_table[i] = c8;

  }

  tables_initialized = 1;

}

/* ----------------------------------------------------------------------- */
/* Field access                                                            */
/* ----------------------------------------------------------------------- */

u64 ck_read_field(const u8 *buf, u32 off, u8 width, u8 endian) {

  u64 v = 0;

  if (endian == CK_END_BE) {

    for (u8 i = 0; i < width; ++i) v = (v << 8) | buf[off + i];

  } else {

    for (u8 i = 0; i < width; ++i) v |= (u64)buf[off + i] << (8 * i);

  }

  return v;

}

void ck_write_field(u8 *buf, u32 off, u8 width, u8 endian, u64 value) {

  if (endian == CK_END_BE) {

    for (u8 i = 0; i < width; ++i)
      buf[off + i] = (u8)(value >> (8 * (width - 1 - i)));

  } else {

    for (u8 i = 0; i < width; ++i) buf[off + i] = (u8)(value >> (8 * i));

  }

}

/* ----------------------------------------------------------------------- */
/* Span resolution                                                         */
/* ----------------------------------------------------------------------- */

/* Resolve the data span for a region against a concrete input length.
   Returns 0 if the span is not fully inside the input.  The checksum field
   itself is always excluded by the caller after span resolution. */
static u8 ck_resolve_span(const ck_region_t *r, u32 len, u32 *start,
                          u32 *end) {

  u32 s = r->region_off;
  u32 e = r->region_end ? r->region_end : len;

  if (s > e || e > len) return 0;
  *start = s;
  *end = e;
  return 1;

}

u8 ck_region_applies(const ck_region_t *r, u32 len) {

  if (!r->enabled || r->conf == CK_CAND_DEAD) return 0;
  if ((u64)r->field_off + r->field_width > len) return 0;

  u32 s, e;
  if (!ck_resolve_span(r, len, &s, &e)) return 0;

  if (r->algo == CK_ALGO_LEN) {

    /* Length anchors must be inside the input; nested length fields simply
       re-evaluate, there is no ordering constraint. */
    switch (r->len_kind) {

      case CK_LEN_ANCHORED:
        if (r->anchor_off > len) return 0;
        break;
      case CK_LEN_SPAN:
        if (r->anchor_off > r->anchor_end || r->anchor_end > len) return 0;
        break;
      default:
        break;

    }

  }

  return 1;

}

/* Expected field value for a region given a concrete input.  When the
   checksum field lies inside its own data span, its bytes are treated as
   zero during the computation (the standard convention).  A single linear
   pass with a byte iterator keeps this allocation-free for every
   algorithm. */
u64 ck_compute(const ck_region_t *r, const u8 *buf, u32 len) {

  if (r->algo == CK_ALGO_LEN) {

    switch (r->len_kind) {

      case CK_LEN_TOTAL:
        return len;
      case CK_LEN_AFTER:
        return len - (r->field_off + r->field_width);
      case CK_LEN_BEFORE:
        return r->field_off;
      case CK_LEN_ANCHORED:
        return len - r->anchor_off;
      case CK_LEN_SPAN:
        return r->anchor_end - r->anchor_off;

    }

    return 0;

  }

  u32 s, e;
  if (!ck_resolve_span(r, len, &s, &e)) return 0;

  /* If the field slot is inside the span it contributes zero bytes. */
  u32 slot_s = r->field_off;
  u32 slot_e = r->field_off + r->field_width;
  u8  zero_slot = (s <= slot_s) && (slot_e <= e);

  u32 i = s;

  switch (r->algo) {

    case CK_ALGO_CRC8: {

      u8 crc = (u8)r->init;
      for (; i < e; ++i) {

        u8 b = (zero_slot && i >= slot_s && i < slot_e) ? 0 : buf[i];
        if (r->refin) b = reflect8(b);
        crc = crc8_table[crc ^ b];

      }

      return (crc ^ (u8)r->xorout) & 0xff;

    }

    case CK_ALGO_CRC16: {

      u16       crc = (u16)r->init;
      const u16 *tbl =
          (r->poly == 0x8005) ? crc16_ibm_table : crc16_ccitt_table;
      for (; i < e; ++i) {

        u8 b = (zero_slot && i >= slot_s && i < slot_e) ? 0 : buf[i];
        if (r->refin) {

          /* Reflected update yields a reflected remainder; no end-of-loop
             reflection on this path. */
          crc = (u16)(tbl[(crc ^ reflect8(b)) & 0xff] ^ (crc >> 8));

        } else {

          crc = (u16)(tbl[((crc >> 8) ^ b) & 0xff] ^ (crc << 8));
          if (r->refout) {

            u16 o = 0, c = crc;
            for (u32 k = 0; k < 16; ++k) {

              o = (u16)((o << 1) | (c & 1));
              c >>= 1;

            }

            crc = o;

          }

        }

      }

      return (crc ^ (u16)r->xorout) & 0xffff;

    }

    case CK_ALGO_CRC32: {

      u32 crc = r->init;
      for (; i < e; ++i) {

        u8 b = (zero_slot && i >= slot_s && i < slot_e) ? 0 : buf[i];
        if (r->refin)
          /* Reflected table update already produces a reflected remainder;
             no end-of-loop reflect32 on this path. */
          crc = crc32_table[(crc ^ b) & 0xff] ^ (crc >> 8);
        else {

          crc = crc32_table[(crc ^ ((u32)b << 24)) & 0xff] ^ (crc << 8);
          if (r->refout) crc = reflect32(crc);

        }

      }

      return (crc ^ r->xorout) & 0xffffffffu;

    }

    case CK_ALGO_SUM8: {

      u8 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v = (u8)(v + buf[i]);
      return v;

    }

    case CK_ALGO_SUM16: {

      u16 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v = (u16)(v + buf[i]);
      return v;

    }

    case CK_ALGO_SUM32: {

      u32 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v = (u32)(v + buf[i]);
      return v;

    }

    case CK_ALGO_XOR8: {

      u8 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v ^= buf[i];
      return v;

    }

    case CK_ALGO_XOR16: {

      u16 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v ^= buf[i];
      return v;

    }

    case CK_ALGO_XOR32: {

      u32 v = 0;
      for (; i < e; ++i)
        if (!(zero_slot && i >= slot_s && i < slot_e)) v ^= buf[i];
      return v;

    }

  }

  return 0;

}

const char *ck_algo_name(u8 algo) {

  switch (algo) {

    case CK_ALGO_CRC8: return "crc8";
    case CK_ALGO_CRC16: return "crc16";
    case CK_ALGO_CRC32: return "crc32";
    case CK_ALGO_SUM8: return "sum8";
    case CK_ALGO_SUM16: return "sum16";
    case CK_ALGO_SUM32: return "sum32";
    case CK_ALGO_XOR8: return "xor8";
    case CK_ALGO_XOR16: return "xor16";
    case CK_ALGO_XOR32: return "xor32";
    case CK_ALGO_LEN: return "len";

  }

  return "none";

}

/* ----------------------------------------------------------------------- */
/* Configuration parsing                                                   */
/* ----------------------------------------------------------------------- */

static u8 ck_algo_from_name(const char *s, u32 n) {

  if ((n == 4 && !strncmp(s, "crc8", 4))) return CK_ALGO_CRC8;
  if ((n == 5 && !strncmp(s, "crc16", 5))) return CK_ALGO_CRC16;
  if ((n == 5 && !strncmp(s, "crc32", 5))) return CK_ALGO_CRC32;
  if ((n == 4 && !strncmp(s, "sum8", 4))) return CK_ALGO_SUM8;
  if ((n == 5 && !strncmp(s, "sum16", 5))) return CK_ALGO_SUM16;
  if ((n == 5 && !strncmp(s, "sum32", 5))) return CK_ALGO_SUM32;
  if ((n == 4 && !strncmp(s, "xor8", 4))) return CK_ALGO_XOR8;
  if ((n == 5 && !strncmp(s, "xor16", 5))) return CK_ALGO_XOR16;
  if ((n == 5 && !strncmp(s, "xor32", 5))) return CK_ALGO_XOR32;
  if ((n == 3 && !strncmp(s, "len", 3))) return CK_ALGO_LEN;
  return CK_ALGO_NONE;

}

/* Default CRC parameters per width, the common industry variants. */
static void ck_crc_defaults(ck_region_t *r) {

  switch (r->algo) {

    case CK_ALGO_CRC8:
      r->poly = 0x07;
      r->init = 0x00;
      r->xorout = 0x00;
      r->refin = 0;
      r->refout = 0;
      break;
    case CK_ALGO_CRC16:
      r->poly = 0x1021;                         /* CCITT-FALSE */
      r->init = 0xffff;
      r->xorout = 0x0000;
      r->refin = 0;
      r->refout = 0;
      break;
    case CK_ALGO_CRC32:
      r->poly = 0x04c11db7;
      r->init = 0xffffffff;
      r->xorout = 0xffffffff;
      r->refin = 1;
      r->refout = 1;
      break;

  }

}

/* Parse one token of the form key=value or key:value into an unsigned.
   Returns 1 on success. */
static u8 ck_tok_u32(const char **p, u32 *out) {

  const char *s = *p;
  if (*s != ':' && *s != '=' && *s != ',') return 0;
  ++s;
  char *end;
  unsigned long v = strtoul(s, &end, 0);
  if (end == s) return 0;
  *out = (u32)v;
  *p = end;
  return 1;

}

u32 ck_parse_config(ck_state_t *ck, const char *spec) {

  if (!ck || !spec) return 0;

  u32 added = 0;
  const char *p = spec;

  while (*p) {

    while (*p == ';' || *p == ',' || *p == ' ') ++p;
    if (!*p) break;
    if (ck->region_cnt >= ck->region_cap) {

      WARNF("AFL_CHECKSUM: region cap %u reached, ignoring remaining spec",
            ck->region_cap);
      break;

    }

    const char *name = p;
    while (*p && *p != ':' && *p != '=' && *p != ';') ++p;
    u32 namelen = (u32)(p - name);
    u8  algo = ck_algo_from_name(name, namelen);
    if (algo == CK_ALGO_NONE) {

      WARNF("AFL_CHECKSUM: unknown algorithm '%.*s', skipping entry",
            namelen, name);
      while (*p && *p != ';') ++p;
      continue;

    }

    ck_region_t r;
    memset(&r, 0, sizeof(r));
    r.algo = algo;
    r.conf = CK_CAND_CONFIRMED;
    r.enabled = 1;
    r.endian = CK_END_LE;
    r.field_width = (algo == CK_ALGO_CRC8 || algo == CK_ALGO_SUM8 ||
                     algo == CK_ALGO_XOR8)
                        ? 1
                    : (algo == CK_ALGO_CRC16 || algo == CK_ALGO_SUM16 ||
                       algo == CK_ALGO_XOR16)
                        ? 2
                        : 4;
    r.region_end = 0;                          /* default: whole input */
    if (algo != CK_ALGO_LEN) ck_crc_defaults(&r);
    r.len_kind = CK_LEN_TOTAL;

    u32 v;
    if (!ck_tok_u32(&p, &v)) goto bad_entry;
    r.field_off = v;

    /* Optional fields, order documented in docs/checksum.md. */
    if (*p == ':' || *p == '=') {

      if (!ck_tok_u32(&p, &v)) goto bad_entry;
      if (v != 1 && v != 2 && v != 4) {

        WARNF("AFL_CHECKSUM: field width must be 1, 2 or 4");
        goto bad_entry;

      }

      r.field_width = (u8)v;

    }

    if (*p == ':' || *p == '=') {

      if (!ck_tok_u32(&p, &v)) goto bad_entry;
      r.endian = v ? CK_END_BE : CK_END_LE;

    }

    if (*p == ':' || *p == '=') {

      if (!ck_tok_u32(&p, &v)) goto bad_entry;
      r.region_off = v;

    }

    if (*p == ':' || *p == '=') {

      if (!ck_tok_u32(&p, &v)) goto bad_entry;
      r.region_end = v;

    }

    /* Length-specific: len kind and anchor. */
    if (algo == CK_ALGO_LEN) {

      if (*p == ':' || *p == '=') {

        if (!ck_tok_u32(&p, &v)) goto bad_entry;
        if (v > CK_LEN_SPAN) {

          WARNF("AFL_CHECKSUM: invalid len kind");
          goto bad_entry;

        }

        r.len_kind = (u8)v;

      }

      if (*p == ':' || *p == '=') {

        if (!ck_tok_u32(&p, &v)) goto bad_entry;
        r.anchor_off = v;

      }

      if (*p == ':' || *p == '=') {

        if (!ck_tok_u32(&p, &v)) goto bad_entry;
        r.anchor_end = v;

      }

    } else {

      /* Optional CRC polynomial override. */
      if (*p == ':' || *p == '=') {

        if (!ck_tok_u32(&p, &v)) goto bad_entry;
        r.poly = v;

      }

    }

    /* Sanity: width/algo consistency for sum/xor families. */
    if ((algo == CK_ALGO_SUM8 || algo == CK_ALGO_XOR8) &&
        r.field_width != 1) {

      WARNF("AFL_CHECKSUM: width 1 required for sum8/xor8");
      goto bad_entry;

    }

    if ((algo == CK_ALGO_SUM16 || algo == CK_ALGO_XOR16) &&
        r.field_width != 2) {

      WARNF("AFL_CHECKSUM: width 2 required for sum16/xor16");
      goto bad_entry;

    }

    if ((algo == CK_ALGO_SUM32 || algo == CK_ALGO_XOR32 ||
         algo == CK_ALGO_CRC32) &&
        r.field_width != 4) {

      WARNF("AFL_CHECKSUM: width 4 required for 32-bit algorithms");
      goto bad_entry;

    }

    ck->regions[ck->region_cnt++] = r;
    ++added;
    ck->enabled = 1;
    continue;

  bad_entry:
    WARNF("AFL_CHECKSUM: malformed entry near '%.16s', skipping", p);
    while (*p && *p != ';') ++p;

  }

  return added;

}

/* ----------------------------------------------------------------------- */
/* Static inference                                                        */
/* ----------------------------------------------------------------------- */

/* Candidate set for one field slot is deliberately small: the common
   algorithms plus both endiannesses, so misinference stays bounded. */
typedef struct {

  u8 algo;
  u8 endian;
  u8 width;

} ck_cand_key_t;

static const ck_cand_key_t cand_keys[] = {

    {CK_ALGO_CRC32, CK_END_LE, 4}, {CK_ALGO_CRC32, CK_END_BE, 4},
    {CK_ALGO_CRC16, CK_END_LE, 2}, {CK_ALGO_CRC16, CK_END_BE, 2},
    {CK_ALGO_CRC8, CK_END_LE, 1},  {CK_ALGO_SUM32, CK_END_LE, 4},
    {CK_ALGO_SUM32, CK_END_BE, 4}, {CK_ALGO_SUM16, CK_END_LE, 2},
    {CK_ALGO_SUM16, CK_END_BE, 2}, {CK_ALGO_SUM8, CK_END_LE, 1},
    {CK_ALGO_XOR32, CK_END_LE, 4}, {CK_ALGO_XOR32, CK_END_BE, 4},
    {CK_ALGO_XOR16, CK_END_LE, 2}, {CK_ALGO_XOR16, CK_END_BE, 2},
    {CK_ALGO_XOR8, CK_END_LE, 1},

};

#define CK_CAND_KEYS_CNT (sizeof(cand_keys) / sizeof(cand_keys[0]))

static void ck_make_region(const ck_cand_key_t *k, u32 field_off,
                           ck_region_t *r) {

  memset(r, 0, sizeof(*r));
  r->field_off = field_off;
  r->field_width = k->width;
  r->algo = k->algo;
  r->endian = k->endian;
  r->region_off = 0;
  r->region_end = 0;                          /* whole input convention */
  r->conf = CK_CAND_UNCONFIRMED;
  r->enabled = 1;
  if (k->algo != CK_ALGO_LEN) ck_crc_defaults(r);

}

static u8 ck_duplicate(const ck_state_t *ck, const ck_region_t *r) {

  for (u32 i = 0; i < ck->region_cnt; ++i) {

    const ck_region_t *e = &ck->regions[i];
    if (e->algo == r->algo && e->field_off == r->field_off &&
        e->field_width == r->field_width && e->endian == r->endian &&
        e->region_off == r->region_off && e->region_end == r->region_end)
      return 1;

  }

  return 0;

}

static void ck_add_candidate(ck_state_t *ck, const ck_region_t *r) {

  if (ck->region_cnt >= ck->region_cap) return;
  if (ck_duplicate(ck, r)) return;
  ck->regions[ck->region_cnt++] = *r;
  ck->enabled = 1;

}

/* Length field inference: look at slots near the head of the input and
   check whether the stored value matches a length relationship with the
   actual seed length. */
static void ck_infer_lengths(ck_state_t *ck, const u8 *buf, u32 len) {

  /* Only probe a bounded prefix: length prefixes live in headers. */
  u32 probe = MIN(len, (u32)32);
  static const u8 widths[3] = {4, 2, 1};

  for (u32 off = 0; off + 2 <= probe; ++off) {

    for (u8 end = 0; end < 2; ++end) {

      /* Widest width first. A wider field that already explains the value
         makes narrower matches redundant (they would also overflow sooner as
         the input grows), so keep only the first matching width. */
      for (u8 wi = 0; wi < 3; ++wi) {

        u8 width = widths[wi];
        if (off + width > probe) continue;
        /* Endianness is meaningless for a single byte; LE already covered
           the value, skip the duplicate BE probe. */
        if (width == 1 && end == CK_END_BE) continue;

        u64 v = ck_read_field(buf, off, width, end);
        if (v > 0xffffffffu || v == 0) continue;
        u32 val = (u32)v;

        u8 len_kind;
        if (val == len) {

          len_kind = CK_LEN_TOTAL;

        } else if (val == len - (off + width)) {

          len_kind = CK_LEN_AFTER;

        } else if (val == off) {

          len_kind = CK_LEN_BEFORE;

        } else {

          continue;

        }

        ck_region_t r;
        memset(&r, 0, sizeof(r));
        r.algo = CK_ALGO_LEN;
        r.field_off = off;
        r.field_width = width;
        r.endian = end;
        r.len_kind = len_kind;
        r.conf = CK_CAND_UNCONFIRMED;
        r.enabled = 1;
        ck_add_candidate(ck, &r);
        break;                          /* widest match wins for this end */

      }

    }

  }

}

void ck_observe_seed(afl_state_t *afl, const u8 *buf, u32 len) {

  ck_state_t *ck = afl->ck;
  if (!ck || ck->infer_mode != 1 || !buf || len < 4) return;
  if (ck->region_cnt >= ck->region_cap) return;
  if (ck->infer_seed_cnt >= AFL_CHECKSUM_MAX_OBSERVED_SEEDS) return;
  if (len > AFL_CHECKSUM_INFER_SCAN_MAX) return;

  ++ck->infer_seed_cnt;
  ck_init_tables();

  /* Length relationships are cheap and high-precision: try them first. */
  ck_infer_lengths(ck, buf, len);

  /* Checksum slots: scan every plausible offset.  Cost is bounded by
     AFL_CHECKSUM_INFER_SCAN_MAX and the small candidate table. */
  for (u32 off = 0; off < len; ++off) {

    if (ck->region_cnt >= ck->region_cap) break;

    for (u32 ki = 0; ki < CK_CAND_KEYS_CNT; ++ki) {

      const ck_cand_key_t *k = &cand_keys[ki];
      if ((u64)off + k->width > len) continue;

      ck_region_t r;
      ck_make_region(k, off, &r);
      u64 stored = ck_read_field(buf, off, k->width, k->endian);
      u64 actual = ck_compute(&r, buf, len);

      if (stored == actual) ck_add_candidate(ck, &r);

    }

  }

}

/* ----------------------------------------------------------------------- */
/* Repair                                                                  */
/* ----------------------------------------------------------------------- */

u8 *ck_repair(afl_state_t *afl, u8 *buf, u32 len) {

  ck_state_t *ck = afl->ck;
  if (!ck || !ck->enabled || !ck->region_cnt) return buf;

  ++ck->repair_calls;

  u8 any_applies = 0;
  for (u32 i = 0; i < ck->region_cnt; ++i) {

    if (ck_region_applies(&ck->regions[i], len)) { any_applies = 1; break; }

  }

  if (!any_applies) {

    ++ck->repair_fallback;
    return buf;

  }

  /* One reusable scratch allocation; only grows with input length, never
     per round. */
  if (ck->scratch_size < len) {

    u8 *p = ck->scratch ? realloc(ck->scratch, len) : malloc(len);
    if (!p) {

      ++ck->repair_fallback;
      return buf;                         /* keep original mutation */

    }

    ck->scratch = p;
    ck->scratch_size = len;

  }

  memcpy(ck->scratch, buf, len);

  /* use_cnt doubles as a per-round participation flag for feedback: clear it
     here, set it on every region actually recomputed below, so ck_report()
     only judges regions that took part in this repair. */
  for (u32 i = 0; i < ck->region_cnt; ++i) ck->regions[i].use_cnt = 0;

  /* Length fields are repaired first and only once: their value depends on
     layout, not on other fields, so they never need re-evaluation. */
  for (u32 i = 0; i < ck->region_cnt; ++i) {

    ck_region_t *r = &ck->regions[i];
    if (!ck_region_applies(r, len) || r->algo != CK_ALGO_LEN) continue;

    u64 expected = ck_compute(r, ck->scratch, len);
    u64 mask = (1ULL << (8 * r->field_width)) - 1;

    /* A value that does not fit its field width means the layout cannot be
       represented - treat as non-repairable and keep the original input. */
    if (expected > mask) {

      ++ck->repair_fallback;
      return buf;

    }

    ck_write_field(ck->scratch, r->field_off, r->field_width, r->endian,
                   expected);
    ++r->use_cnt;

  }

  /* Checksum fields may cover one another's slots, so a single left-to-right
     sweep can leave a field stale.  Iterate to a fixed point: each full
     sweep either converges (no field changes) or changes at least one of the
     finite-width fields, so convergence takes at most region_cnt+1 sweeps.
     The bound keeps work independent of input size and guarantees we never
     loop forever on a pathological layout. */
  u32 applicable = 0;
  for (u32 i = 0; i < ck->region_cnt; ++i)
    if (ck_region_applies(&ck->regions[i], len) &&
        ck->regions[i].algo != CK_ALGO_LEN)
      ++applicable;

  u32 max_sweeps = applicable + 1;
  u8  converged = 0;
  for (u32 sweep = 0; sweep < max_sweeps; ++sweep) {

    u8 changed = 0;
    for (u32 i = 0; i < ck->region_cnt; ++i) {

      ck_region_t *r = &ck->regions[i];
      if (!ck_region_applies(r, len) || r->algo == CK_ALGO_LEN) continue;

      u64 expected = ck_compute(r, ck->scratch, len);
      u64 mask = (1ULL << (8 * r->field_width)) - 1;
      expected &= mask;
      u64 current = ck_read_field(ck->scratch, r->field_off, r->field_width,
                                  r->endian);

      if (current != expected) {

        ck_write_field(ck->scratch, r->field_off, r->field_width, r->endian,
                       expected);
        changed = 1;

      }

      ++r->use_cnt;

    }

    if (!changed) { converged = 1; break; }

  }

  /* No fixed point within the bounded sweep count means mutually dependent
     fields that cannot be made simultaneously consistent (e.g. checksums
     covering each other's live slots). Never ship a partially repaired
     input - fall back to the untouched original mutation. */
  if (!converged) {

    ++ck->repair_fallback;
    return buf;

  }

  ++ck->repair_ok;
  return ck->scratch;

}

void ck_report(afl_state_t *afl, u8 accepted) {

  ck_state_t *ck = afl->ck;
  if (!ck) return;

  for (u32 i = 0; i < ck->region_cnt; ++i) {

    ck_region_t *r = &ck->regions[i];
    if (r->conf == CK_CAND_CONFIRMED || !r->use_cnt) continue;

    if (accepted) {

      /* A successful repaired execution confirms every unconfirmed region
         that participated. */
      r->conf = CK_CAND_CONFIRMED;
      r->fail_cnt = 0;

    } else {

      ++r->fail_cnt;
      if (r->fail_cnt >= AFL_CHECKSUM_RETIRE_FAILS) {

        r->conf = CK_CAND_DEAD;
        r->enabled = 0;
        ++ck->retired;

      }

    }

  }

}

u32 ck_active_count(afl_state_t *afl) {

  ck_state_t *ck = afl->ck;
  if (!ck) return 0;
  u32 n = 0;
  for (u32 i = 0; i < ck->region_cnt; ++i)
    if (ck->regions[i].enabled && ck->regions[i].conf != CK_CAND_DEAD) ++n;
  return n;

}

/* ----------------------------------------------------------------------- */
/* Lifecycle                                                               */
/* ----------------------------------------------------------------------- */

void ck_init(afl_state_t *afl) {

  const char *cfg = getenv("AFL_CHECKSUM");
  const char *infer = getenv("AFL_CHECKSUM_INFER");
  const char *maxenv = getenv("AFL_CHECKSUM_MAX");

  if (!cfg && !(infer && infer[0] != '0')) return;

  u32 cap = AFL_CHECKSUM_DEFAULT_MAX;
  if (maxenv && *maxenv) {

    int c = atoi(maxenv);
    if (c <= 0) {

      WARNF("AFL_CHECKSUM_MAX must be positive, using %u", cap);

    } else {

      cap = (u32)c;
      if (cap > AFL_CHECKSUM_HARD_MAX) {

        WARNF("AFL_CHECKSUM_MAX clamped to hard limit %d",
              AFL_CHECKSUM_HARD_MAX);
        cap = AFL_CHECKSUM_HARD_MAX;

      }

    }

  }

  ck_state_t *ck = calloc(1, sizeof(ck_state_t));
  if (!ck) { PFATAL("checksum state alloc"); }
  ck->regions = calloc(cap, sizeof(ck_region_t));
  if (!ck->regions) { PFATAL("checksum region table alloc"); }
  ck->region_cap = cap;
  afl->ck = ck;

  ck_init_tables();

  if (infer && infer[0] != '0') {

    ck->infer_mode = 1;
    OKF("Checksum-aware mutation: auto inference enabled (cap=%u)", cap);

  } else {

    ck->infer_mode = 2;
    OKF("Checksum-aware mutation: configured regions only (cap=%u)", cap);

  }

  if (cfg && *cfg) {

    u32 n = ck_parse_config(ck, cfg);
    OKF("Checksum-aware mutation: %u region(s) loaded from AFL_CHECKSUM", n);

  }

}

void ck_deinit(afl_state_t *afl) {

  ck_state_t *ck = afl->ck;
  if (!ck) return;
  free(ck->scratch);
  free(ck->regions);
  free(ck);
  afl->ck = NULL;

}
