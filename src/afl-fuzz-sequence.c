/*
   american fuzzy lop++ - part of the AFL++ project
   ------------------------------------------------

   Copyright 2019-2026 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0

   SPDX-License-Identifier: Apache-2.0

 */

/* Stateful / sequence fuzzing (AFL_SEQUENCE_FUZZING).

   Classic AFL++ mutation is byte-centric: multi-step handshakes, transactions
   and state migrations in protocol-like targets are only reachable by luck.
   This optional stage splits an input into a message sequence (delimiter
   based), learns a bounded state model from the corpus — a state is the chain
   of message types consumed so far — and then mutates along the observed
   model: splicing a message that is a known legal successor of the state at
   the splice point, replaying messages, reordering adjacent messages and
   dropping messages. Mutations that would create a transition never observed
   in the corpus ("illegal") are downweighted: they are skipped most of the
   time but still allowed occasionally so the model can grow.

   Design properties required by the feature:

   - Opt-in only. Without AFL_SEQUENCE_FUZZING nothing changes; inputs that
     do not parse as a sequence (no delimiter) skip the stage and fall back
     to the plain byte-level havoc pipeline unchanged.
   - Bounded memory. The state, type and transition tables are fixed-capacity
     open-addressing hash tables allocated once; when full, inserts become
     no-ops (the model stops growing) instead of growing without bound. The
     number of messages parsed per input is capped (AFL_SEQ_MAX_MSGS) and a
     single mutation never copies more than one message from a donor plus the
     current input, and candidates stay below max_length like any other
     mutation.
   - State reset is inherent: every execution is a fresh forkserver child, so
     the target's protocol state resets per run; the input itself is the full
     self-contained transcript. If a target needs an explicit reset message,
     include it as the first message of the seeds.
   - Nondeterministic responses cannot corrupt the model: states are inferred
     purely from the (deterministic) input side — either the built-in
     token/prefix message typing or the optional afl_custom_seq_state custom
     mutator callback, which lets the user encode response features into the
     type id.
   - Timeouts are handled by the normal AFL++ machinery (common_fuzz_stuff /
     subseq_tmouts); the stage abandons the entry when the consecutive
     timeout limit is hit, exactly like the havoc stage.
   - Coexists with CmpLog/LAF: the stage runs after the deterministic and
     CmpLog stages and only emits candidates through common_fuzz_stuff, it
     does not touch the cmplog forkserver or its state. */

#include "afl-fuzz.h"

#define SEQ_INIT_HASH 0xCBF29CE484222325ULL   /* FNV offset basis         */
#define SEQ_FNV_PRIME 0x100000001B3ULL        /* FNV prime                */
#define SEQ_HASH_SEED 0x5EED5EED5EED5EEDULL
#define SEQ_TYPE_RETRY 6        /* attempts to find a legal donor type    */
#define SEQ_ILLEGAL_PROB 10     /* 1/10 chance to still do an illegal op  */

/* Small self-contained FNV-1a so this file also links standalone (unit
   tests do not pull in afl-performance.o). */

static inline u64 seq_hash_bytes(const u8 *data, u32 len, u64 seed) {

  u64 h = SEQ_INIT_HASH ^ seed;
  for (u32 i = 0; i < len; ++i) {

    h ^= data[i];
    h *= SEQ_FNV_PRIME;

  }

  return h ? h : 1;                     /* 0 marks an empty table slot    */

}

/* Unescape a user-provided delimiter string (\n, \r, \t, \0, \\).
   Returns the length written into out (out must hold strlen(in)+1). */

static u32 seq_unescape(const u8 *in, u8 *out) {

  u32 n = 0;
  while (*in) {

    if (*in == '\\' && in[1]) {

      ++in;
      switch (*in) {

        case 'n': out[n++] = '\n'; break;
        case 'r': out[n++] = '\r'; break;
        case 't': out[n++] = '\t'; break;
        case '0': out[n++] = '\0'; break;
        case '\\': out[n++] = '\\'; break;
        default: out[n++] = *in; break;

      }

      ++in;

    } else {

      out[n++] = *in++;

    }

  }

  return n;

}

static inline u32 seq_next_pow2(u32 x) {

  --x;
  x |= x >> 1;
  x |= x >> 2;
  x |= x >> 4;
  x |= x >> 8;
  x |= x >> 16;
  return x + 1;

}

/* One-time lazy init of the bounded tables. On failure the feature disables
   itself so the fuzzer continues in plain stateless mode. */

void afl_seq_init(afl_state_t *afl) {

  if (afl->seq_enabled) { return; }

  /* Delimiter */

  u8 *d = afl->afl_env.afl_seq_delim;
  if (d && *d) {

    afl->seq_delim = (u8 *)ck_alloc(strlen((char *)d) + 1);
    afl->seq_delim_len = seq_unescape(d, afl->seq_delim);

  } else {

    afl->seq_delim = (u8 *)ck_alloc(2);
    afl->seq_delim[0] = '\n';
    afl->seq_delim_len = 1;

  }

  if (unlikely(!afl->seq_delim_len)) {

    WARNF("AFL_SEQ_DELIM is empty after unescaping - sequence fuzzing off");
    afl->afl_env.afl_sequence_fuzzing = 0;
    ck_free(afl->seq_delim);
    afl->seq_delim = NULL;
    return;

  }

  /* Bounds */

  u32 max_msgs = afl->afl_env.afl_seq_max_msgs;
  if (max_msgs < 4) { max_msgs = 4; }
  if (max_msgs > SEQ_MAX_MSGS_CAP) { max_msgs = SEQ_MAX_MSGS_CAP; }
  afl->seq_max_msgs = max_msgs;

  u32 states = afl->afl_env.afl_seq_max_states;
  if (states < 64) { states = 64; }
  if (states > SEQ_MAX_STATES_CAP) { states = SEQ_MAX_STATES_CAP; }
  afl->seq_states_cap = seq_next_pow2(states);
  afl->seq_types_cap = afl->seq_states_cap;
  u64 trans_cap = (u64)afl->seq_states_cap * 4;
  if (trans_cap > (SEQ_MAX_STATES_CAP * 4)) { trans_cap = SEQ_MAX_STATES_CAP * 4; }
  afl->seq_trans_cap = (u32)trans_cap;

  afl->seq_states = (seq_state_t *)ck_alloc(sizeof(seq_state_t) *
                                            afl->seq_states_cap);
  afl->seq_types =
      (seq_type_t *)ck_alloc(sizeof(seq_type_t) * afl->seq_types_cap);
  afl->seq_trans =
      (seq_trans_t *)ck_alloc(sizeof(seq_trans_t) * afl->seq_trans_cap);

  afl->seq_msgs = (seq_msg_t *)ck_alloc(sizeof(seq_msg_t) * afl->seq_max_msgs);
  afl->seq_msg_types = (u32 *)ck_alloc(sizeof(u32) * (afl->seq_max_msgs + 1));
  afl->seq_msg_states = (u32 *)ck_alloc(sizeof(u32) * (afl->seq_max_msgs + 1));

  /* Insert the initial (empty sequence) state. */

  u32 slot = (u32)(SEQ_INIT_HASH & (afl->seq_states_cap - 1));
  afl->seq_states[slot].hash = SEQ_INIT_HASH;
  afl->seq_states[slot].id = slot;
  afl->seq_states[slot].depth = 0;
  afl->seq_states_cnt = 1;

  afl->seq_enabled = 1;

  if (!afl->seq_announced) {

    afl->seq_announced = 1;
    u8 dbuf[64];
    u32 pos = 0;
    for (u32 i = 0; i < afl->seq_delim_len && pos < sizeof(dbuf) - 5; ++i) {

      pos += snprintf((char *)dbuf + pos, sizeof(dbuf) - pos, "\\x%02x",
                      afl->seq_delim[i]);

    }

    OKF("Stateful sequence fuzzing enabled (delim=%s, max_msgs=%u, "
        "max_states=%u).",
        dbuf, afl->seq_max_msgs, afl->seq_states_cap);

  }

}

void afl_seq_deinit(afl_state_t *afl) {

  if (afl->seq_delim) { ck_free(afl->seq_delim); }
  if (afl->seq_states) { ck_free(afl->seq_states); }
  if (afl->seq_types) { ck_free(afl->seq_types); }
  if (afl->seq_trans) { ck_free(afl->seq_trans); }
  if (afl->seq_msgs) { ck_free(afl->seq_msgs); }
  if (afl->seq_msg_types) { ck_free(afl->seq_msg_types); }
  if (afl->seq_msg_states) { ck_free(afl->seq_msg_states); }
  if (afl->seq_buf) { afl_free(afl->seq_buf); }
  afl->seq_delim = NULL;
  afl->seq_states = NULL;
  afl->seq_types = NULL;
  afl->seq_trans = NULL;
  afl->seq_msgs = NULL;
  afl->seq_msg_types = NULL;
  afl->seq_msg_states = NULL;
  afl->seq_buf = NULL;
  afl->seq_enabled = 0;

}

/* Split buf into messages on the delimiter. At most max_msgs messages are
   returned; if the input contains more, the remainder is merged into the
   last message (keeps the parse bounded). Empty messages between adjacent
   delimiters are kept. Returns the message count (1 = not a sequence). */

u32 afl_seq_parse(afl_state_t *afl, const u8 *buf, u32 len, seq_msg_t *msgs,
                  u32 max_msgs) {

  if (!len) { return 0; }

  const u32 dlen = afl->seq_delim_len;
  u32        n = 0, start = 0;

  while (n + 1 < max_msgs && start + dlen <= len) {

    u32 p = start;
    while (p + dlen <= len &&
           memcmp(buf + p, afl->seq_delim, dlen) != 0) {

      ++p;

    }

    if (p + dlen > len) { break; }      /* no more delimiters */

    msgs[n].off = start;
    msgs[n].len = p - start;
    ++n;
    start = p + dlen;

  }

  if (start < len) {                    /* tail after the last delimiter */

    msgs[n].off = start;
    msgs[n].len = len - start;
    ++n;

  }

  return n;

}

/* Compute the type key hash of one message. A user-provided custom mutator
   callback (afl_custom_seq_state) takes precedence over the built-in
   token/prefix inference. */

static u64 seq_type_hash(afl_state_t *afl, const u8 *msg, u32 mlen) {

  if (unlikely(afl->custom_mutators_count)) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (el->afl_custom_seq_state) {

        u32 v = el->afl_custom_seq_state(el->data, msg, mlen);
        u64 h = SEQ_INIT_HASH ^ ((u64)v * SEQ_FNV_PRIME);
        return h ? h : 1;

      }

    });

  }

  u32 klen;

  if (afl->afl_env.afl_seq_type_len) {

    /* fixed prefix mode: the first N bytes are the message type */
    klen = MIN(mlen, afl->afl_env.afl_seq_type_len);

  } else {

    /* token mode: the first whitespace-delimited token (capped) */
    klen = 0;
    while (klen < mlen && klen < SEQ_TOKEN_MAX && msg[klen] != ' ' &&
           msg[klen] != '\t' && msg[klen] != '\r') {

      ++klen;

    }

  }

  return seq_hash_bytes(msg, klen, SEQ_HASH_SEED);

}

/* Look up (or, with create=1, insert) a message type. Returns the type id
   (== table slot) or SEQ_ID_NONE when unknown / the table is full. */

u32 afl_seq_type_id(afl_state_t *afl, const u8 *msg, u32 mlen, u8 create) {

  u64 h = seq_type_hash(afl, msg, mlen);
  u32 mask = afl->seq_types_cap - 1;
  u32 idx = (u32)(h & mask);

  while (afl->seq_types[idx].hash) {

    if (afl->seq_types[idx].hash == h) { return idx; }
    idx = (idx + 1) & mask;

  }

  if (!create) { return SEQ_ID_NONE; }

  /* keep the load factor <= 3/4 so probing stays short */
  if (unlikely(afl->seq_types_cnt >= (afl->seq_types_cap >> 1) +
                                       (afl->seq_types_cap >> 2))) {

    afl->seq_tables_full = 1;
    return SEQ_ID_NONE;

  }

  afl->seq_types[idx].hash = h;
  afl->seq_types[idx].id = idx;
  ++afl->seq_types_cnt;
  return idx;

}

/* The id of the initial (empty sequence) state. */

static inline u32 seq_initial_state(afl_state_t *afl) {

  return (u32)(SEQ_INIT_HASH & (afl->seq_states_cap - 1));

}

/* Look up (or insert) the state reached by consuming a message of type
   `type` in state `from`. Returns the state id or SEQ_ID_NONE. */

u32 afl_seq_state_step(afl_state_t *afl, u32 from, u32 type, u8 create) {

  if (from == SEQ_ID_NONE || type == SEQ_ID_NONE) { return SEQ_ID_NONE; }

  u64 h = afl->seq_states[from].hash * SEQ_FNV_PRIME ^
          afl->seq_types[type].hash;
  if (!h) { h = 1; }

  u32 mask = afl->seq_states_cap - 1;
  u32 idx = (u32)(h & mask);

  while (afl->seq_states[idx].hash) {

    if (afl->seq_states[idx].hash == h) {

      if (afl->seq_states[idx].hits < UINT32_MAX) {

        ++afl->seq_states[idx].hits;

      }

      return idx;

    }

    idx = (idx + 1) & mask;

  }

  if (!create) { return SEQ_ID_NONE; }

  if (unlikely(afl->seq_states_cnt >= (afl->seq_states_cap >> 1) +
                                          (afl->seq_states_cap >> 2))) {

    afl->seq_tables_full = 1;
    return SEQ_ID_NONE;

  }

  afl->seq_states[idx].hash = h;
  afl->seq_states[idx].id = idx;
  afl->seq_states[idx].depth = afl->seq_states[from].depth + 1;
  afl->seq_states[idx].hits = 1;
  ++afl->seq_states_cnt;
  return idx;

}

/* Record (or find) the transition (from, type) -> to. */

static void seq_trans_record(afl_state_t *afl, u32 from, u32 type, u32 to) {

  u64 key = ((u64)from << 32) | (u64)type;
  u32 mask = afl->seq_trans_cap - 1;
  u32 idx = (u32)((key * SEQ_FNV_PRIME) & mask);

  while (afl->seq_trans[idx].key) {

    if (afl->seq_trans[idx].key == key + 1) {

      if (afl->seq_trans[idx].count < UINT32_MAX) {

        ++afl->seq_trans[idx].count;

      }

      return;

    }

    idx = (idx + 1) & mask;

  }

  if (unlikely(afl->seq_trans_cnt >= (afl->seq_trans_cap >> 1) +
                                         (afl->seq_trans_cap >> 2))) {

    afl->seq_tables_full = 1;
    return;

  }

  afl->seq_trans[idx].key = key + 1;
  afl->seq_trans[idx].to_state = to;
  afl->seq_trans[idx].count = 1;
  ++afl->seq_trans_cnt;

}

/* Find the target state of an observed transition, SEQ_ID_NONE if the
   transition was never observed (illegal under the current model). */

u32 afl_seq_trans_find(afl_state_t *afl, u32 from, u32 type) {

  if (from == SEQ_ID_NONE || type == SEQ_ID_NONE) { return SEQ_ID_NONE; }

  u64 key = ((u64)from << 32) | (u64)type;
  u32 mask = afl->seq_trans_cap - 1;
  u32 idx = (u32)((key * SEQ_FNV_PRIME) & mask);

  while (afl->seq_trans[idx].key) {

    if (afl->seq_trans[idx].key == key + 1) {

      return afl->seq_trans[idx].to_state;

    }

    idx = (idx + 1) & mask;

  }

  return SEQ_ID_NONE;

}

/* Learn the message types, states, transitions and donor exemplars of one
   corpus input. All tables are bounded; when a table is full, learning for
   the rest of the input silently stops. */

void afl_seq_learn(afl_state_t *afl, const u8 *buf, u32 len, u32 queue_id) {

  u32 n = afl_seq_parse(afl, buf, len, afl->seq_msgs, afl->seq_max_msgs);
  if (n < 2) { return; }

  u32 state = seq_initial_state(afl);

  for (u32 i = 0; i < n; ++i) {

    const u8 *msg = buf + afl->seq_msgs[i].off;
    u32       mlen = afl->seq_msgs[i].len;

    u32 t = afl_seq_type_id(afl, msg, mlen, 1);
    if (t == SEQ_ID_NONE) { return; }   /* type table full */

    seq_type_t *ty = &afl->seq_types[t];
    if (ty->count < UINT32_MAX) { ++ty->count; }

    /* bounded reservoir of donor exemplars for this message type */
    ++ty->ex_seen;
    if (ty->ex_count < SEQ_MAX_EXEMPLARS) {

      ty->ex[ty->ex_count].queue_id = queue_id;
      ty->ex[ty->ex_count].offset = afl->seq_msgs[i].off;
      ty->ex[ty->ex_count].len = mlen;
      ++ty->ex_count;

    } else {

      u32 j = rand_below(afl, ty->ex_seen);
      if (j < SEQ_MAX_EXEMPLARS) {

        ty->ex[j].queue_id = queue_id;
        ty->ex[j].offset = afl->seq_msgs[i].off;
        ty->ex[j].len = mlen;

      }

    }

    u32 next = afl_seq_state_step(afl, state, t, 1);
    if (next == SEQ_ID_NONE) { return; } /* state table full */

    seq_trans_record(afl, state, t, next);
    state = next;

  }

}

/* Pick a random known message type that is a legal successor of state
   `from`. Returns SEQ_ID_NONE after SEQ_TYPE_RETRY failed attempts. */

static u32 seq_pick_legal_type(afl_state_t *afl, u32 from) {

  if (from == SEQ_ID_NONE || !afl->seq_types_cnt) { return SEQ_ID_NONE; }

  u32 mask = afl->seq_types_cap - 1;

  for (u32 tries = 0; tries < SEQ_TYPE_RETRY; ++tries) {

    u32 idx = rand_below(afl, afl->seq_types_cap);
    /* probe forward to the next occupied slot */
    for (u32 k = 0; k < 8 && !afl->seq_types[idx].hash; ++k) {

      idx = (idx + 1) & mask;

    }

    if (!afl->seq_types[idx].hash) { continue; }

    if (afl_seq_trans_find(afl, from, idx) != SEQ_ID_NONE) { return idx; }

  }

  return SEQ_ID_NONE;

}

/* Pick any known message type (used, downweighted, when no legal successor
   is known so the model can still be extended). */

static u32 seq_pick_any_type(afl_state_t *afl) {

  if (!afl->seq_types_cnt) { return SEQ_ID_NONE; }

  u32 mask = afl->seq_types_cap - 1;
  u32 idx = rand_below(afl, afl->seq_types_cap);
  for (u32 k = 0; k < 16 && !afl->seq_types[idx].hash; ++k) {

    idx = (idx + 1) & mask;

  }

  return afl->seq_types[idx].hash ? idx : SEQ_ID_NONE;

}

/* Fetch a donor message for type t. Validates the exemplar against the
   (possibly trimmed) donor queue entry. Returns 1 on success. */

static u8 seq_get_donor(afl_state_t *afl, u32 t, const u8 **msg, u32 *mlen) {

  seq_type_t *ty = &afl->seq_types[t];
  if (!ty->ex_count) { return 0; }

  seq_exemplar_t *ex = &ty->ex[rand_below(afl, ty->ex_count)];

  if (ex->queue_id >= afl->queued_items) { return 0; }

  struct queue_entry *q = afl->queue_buf[ex->queue_id];
  if (!q || ex->offset > q->len || ex->len > q->len - ex->offset) {

    return 0;                            /* donor was trimmed/modified */

  }

  u8 *buf = queue_testcase_get(afl, q);
  if (!buf) { return 0; }

  *msg = buf + ex->offset;
  *mlen = ex->len;
  return 1;

}

/* The sequence mutation stage. Returns 1 if the entry must be abandoned
   (stop_soon / too many consecutive timeouts), 0 otherwise. */

u8 sequence_stage(afl_state_t *afl, u8 *in_buf, u32 len, u32 perf_score) {

  if (unlikely(!afl->seq_enabled)) {

    afl_seq_init(afl);
    if (!afl->seq_enabled) { return 0; } /* init failed: stateless mode */

  }

  /* Learn from the current input (bounded, idempotent). */
  afl_seq_learn(afl, in_buf, len, afl->current_entry);

  u32 n = afl_seq_parse(afl, in_buf, len, afl->seq_msgs, afl->seq_max_msgs);
  if (n < 2) {

    /* Not a message sequence: fall back to plain byte-level fuzzing. */
    ++afl->seq_skipped;
    return 0;

  }

  /* Message types and prefix states for this input. */
  u32 state = seq_initial_state(afl);
  for (u32 i = 0; i < n; ++i) {

    afl->seq_msg_states[i] = state;
    u32 t = afl_seq_type_id(afl, in_buf + afl->seq_msgs[i].off,
                            afl->seq_msgs[i].len, 0);
    afl->seq_msg_types[i] = t;
    state = afl_seq_state_step(afl, state, t, 0);

  }

  afl->seq_msg_states[n] = state;

  const u32 dlen = afl->seq_delim_len;
  const u8  trailing =
      (len >= dlen && memcmp(in_buf + len - dlen, afl->seq_delim, dlen) == 0);

  afl->stage_name = "sequence";
  afl->stage_short = "seq";
  afl->stage_val_type = STAGE_VAL_NONE;
  afl->stage_max = (HAVOC_CYCLES * perf_score / afl->havoc_div) >> 9;
  if (afl->stage_max < HAVOC_MIN) { afl->stage_max = HAVOC_MIN; }

  u64 orig_hit_cnt = afl->queued_items + afl->saved_crashes;

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    u32 new_len = 0;
    u32 r = rand_below(afl, 16);

    if (r < 6) {

      /***** SPLICE: insert a donor message that is a legal successor *****/

      if (n >= afl->seq_max_msgs) { continue; }   /* bounded growth */

      u32 pos = rand_below(afl, n + 1);

      u32 from = afl->seq_msg_states[pos];
      u32 t = seq_pick_legal_type(afl, from);

      if (t == SEQ_ID_NONE) {

        /* no known legal successor: downweight the illegal transition */
        ++afl->seq_downgraded;
        if (rand_below(afl, SEQ_ILLEGAL_PROB)) { continue; }
        t = seq_pick_any_type(afl);
        if (t == SEQ_ID_NONE) { continue; }

      }

      const u8 *donor;
      u32       dlen2;
      if (!seq_get_donor(afl, t, &donor, &dlen2)) { continue; }

      u64 need = (u64)len + dlen2 + dlen;
      if (need > afl->max_length || need > MAX_FILE) { continue; }

      u8 *out = (u8 *)afl_realloc(AFL_BUF_PARAM(seq), (size_t)need);
      if (unlikely(!out)) { PFATAL("alloc"); }

      if (pos < n) {

        /* insert "donor + delim" right before message pos */
        u32 off = afl->seq_msgs[pos].off;
        memcpy(out, in_buf, off);
        memcpy(out + off, donor, dlen2);
        memcpy(out + off + dlen2, afl->seq_delim, dlen);
        memcpy(out + off + dlen2 + dlen, in_buf + off, len - off);
        new_len = off + dlen2 + dlen + (len - off);

      } else {

        /* append at the end, preserving the trailing-delimiter style */
        memcpy(out, in_buf, len);
        u32 o = len;
        if (!trailing) {

          memcpy(out + o, afl->seq_delim, dlen);
          o += dlen;

        }

        memcpy(out + o, donor, dlen2);
        o += dlen2;
        if (trailing) {

          memcpy(out + o, afl->seq_delim, dlen);
          o += dlen;

        }

        new_len = o;

      }

    } else if (r < 10) {

      /***** REPLACE: swap one message for a legal donor of its state *****/

      u32 i = rand_below(afl, n);
      u32 from = afl->seq_msg_states[i];
      u32 t = seq_pick_legal_type(afl, from);

      if (t == SEQ_ID_NONE) {

        ++afl->seq_downgraded;
        if (rand_below(afl, SEQ_ILLEGAL_PROB)) { continue; }
        t = seq_pick_any_type(afl);
        if (t == SEQ_ID_NONE) { continue; }

      }

      const u8 *donor;
      u32       dlen2;
      if (!seq_get_donor(afl, t, &donor, &dlen2)) { continue; }

      u32 off = afl->seq_msgs[i].off;
      u32 mlen = afl->seq_msgs[i].len;
      u64 need = (u64)len - mlen + dlen2;
      if (!need || need > afl->max_length || need > MAX_FILE) { continue; }

      u8 *out = (u8 *)afl_realloc(AFL_BUF_PARAM(seq), (size_t)need);
      if (unlikely(!out)) { PFATAL("alloc"); }

      memcpy(out, in_buf, off);
      memcpy(out + off, donor, dlen2);
      memcpy(out + off + dlen2, in_buf + off + mlen, len - off - mlen);
      new_len = off + dlen2 + (len - off - mlen);

    } else if (r < 13) {

      /***** REPLAY: duplicate one message (bounded: a single copy) *****/

      if (n >= afl->seq_max_msgs) { continue; }

      u32 i = rand_below(afl, n);
      u32 off = afl->seq_msgs[i].off;
      u32 mlen = afl->seq_msgs[i].len;

      u64 need = (u64)len + mlen + dlen;
      if (need > afl->max_length || need > MAX_FILE) { continue; }

      u8 *out = (u8 *)afl_realloc(AFL_BUF_PARAM(seq), (size_t)need);
      if (unlikely(!out)) { PFATAL("alloc"); }

      if (i + 1 == n && !trailing) {

        /* last message without trailing delim: append "delim + msg" */
        memcpy(out, in_buf, len);
        memcpy(out + len, afl->seq_delim, dlen);
        memcpy(out + len + dlen, in_buf + off, mlen);
        new_len = len + dlen + mlen;

      } else {

        /* insert "msg + delim" right before its original */
        memcpy(out, in_buf, off);
        memcpy(out + off, in_buf + off, mlen);
        memcpy(out + off + mlen, afl->seq_delim, dlen);
        memcpy(out + off + mlen + dlen, in_buf + off, len - off);
        new_len = off + mlen + dlen + (len - off);

      }

    } else if (r < 14) {

      /***** REORDER: swap two adjacent messages if transitions stay legal
               (illegal reorders are downweighted, not forbidden) *****/

      if (n < 3) { continue; }

      u32 i = rand_below(afl, n - 1);
      u32 ta = afl->seq_msg_types[i];
      u32 tb = afl->seq_msg_types[i + 1];
      u32 s = afl->seq_msg_states[i];

      u32 s1 = afl_seq_trans_find(afl, s, tb);
      u32 s2 = (s1 != SEQ_ID_NONE) ? afl_seq_trans_find(afl, s1, ta)
                                   : SEQ_ID_NONE;

      if (s2 == SEQ_ID_NONE) {

        ++afl->seq_downgraded;
        if (rand_below(afl, SEQ_ILLEGAL_PROB)) { continue; }

      }

      u32 off_a = afl->seq_msgs[i].off;
      u32 len_a = afl->seq_msgs[i].len;
      u32 off_b = afl->seq_msgs[i + 1].off;
      u32 len_b = afl->seq_msgs[i + 1].len;

      u8 *out = (u8 *)afl_realloc(AFL_BUF_PARAM(seq), len);
      if (unlikely(!out)) { PFATAL("alloc"); }

      /* ... A <delim> B ...  ->  ... B <delim> A ... */
      memcpy(out, in_buf, off_a);
      memcpy(out + off_a, in_buf + off_b, len_b);
      memcpy(out + off_a + len_b, afl->seq_delim, dlen);
      memcpy(out + off_a + len_b + dlen, in_buf + off_a, len_a);
      u32 tail = off_b + len_b;
      memcpy(out + off_a + len_b + dlen + len_a, in_buf + tail, len - tail);
      new_len = len;

    } else {

      /***** DROP: remove a message if the bypass transition is legal *****/

      if (n <= 2) { continue; }

      u32 i = rand_below(afl, n);

      if (i + 1 < n) {

        /* removing message i joins state[i] directly with type[i+1] */
        if (afl_seq_trans_find(afl, afl->seq_msg_states[i],
                               afl->seq_msg_types[i + 1]) == SEQ_ID_NONE) {

          ++afl->seq_downgraded;
          if (rand_below(afl, SEQ_ILLEGAL_PROB)) { continue; }

        }

      } /* dropping the tail message is always legal */

      u32 off = afl->seq_msgs[i].off;
      u32 mlen = afl->seq_msgs[i].len;

      u8 *out = (u8 *)afl_realloc(AFL_BUF_PARAM(seq), len);
      if (unlikely(!out)) { PFATAL("alloc"); }

      if (i + 1 == n && !trailing) {

        /* last message, no trailing delim: also drop the preceding delim */
        if (off < dlen) { continue; }
        memcpy(out, in_buf, off - dlen);
        new_len = off - dlen;

      } else if (i + 1 == n) {

        /* last message with trailing delim: cut it off entirely */
        memcpy(out, in_buf, off);
        new_len = off;

      } else {

        /* remove "msg + delim" */
        memcpy(out, in_buf, off);
        memcpy(out + off, in_buf + off + mlen + dlen, len - off - mlen - dlen);
        new_len = len - mlen - dlen;

      }

      if (!new_len) { continue; }

    }

    if (!new_len) { continue; }

    ++afl->seq_cycles;

    if (common_fuzz_stuff(afl, afl->seq_buf, new_len)) {

      /* stop_soon or too many consecutive timeouts: abandon the entry */
      afl->stage_finds[STAGE_SEQUENCE] +=
          (afl->queued_items + afl->saved_crashes) - orig_hit_cnt;
      afl->stage_cycles[STAGE_SEQUENCE] += afl->stage_cur;
      return 1;

    }

  }

  u64 new_hit_cnt = afl->queued_items + afl->saved_crashes;
  afl->stage_finds[STAGE_SEQUENCE] += new_hit_cnt - orig_hit_cnt;
  afl->stage_cycles[STAGE_SEQUENCE] += afl->stage_cur;
  afl->seq_finds += new_hit_cnt - orig_hit_cnt;

  return 0;

}
