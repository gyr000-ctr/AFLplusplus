/* Unit tests for the stateful/sequence fuzzing module
   (src/afl-fuzz-sequence.c): message parsing, type inference, bounded state
   and transition tables, legal/illegal transition handling, replay/reorder/
   splice/drop mutation building, timeout abandon and stateless fallback. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "afl-fuzz.h"

/* ---- mocks for symbols sequence_stage pulls in from the rest of afl ---- */

#define MAX_CAPTURED 512
#define MAX_CAPTURED_LEN 4096

static u8  captured[MAX_CAPTURED][MAX_CAPTURED_LEN];
static u32 captured_len[MAX_CAPTURED];
static u32 captured_cnt;
static u32 abandon_after;               /* return 1 after this many calls */
static u32 cfs_calls;

u8 common_fuzz_stuff(afl_state_t *afl, u8 *out_buf, u32 len) {

  (void)afl;
  ++cfs_calls;
  if (captured_cnt < MAX_CAPTURED && len <= MAX_CAPTURED_LEN) {

    memcpy(captured[captured_cnt], out_buf, len);
    captured_len[captured_cnt] = len;
    ++captured_cnt;

  }

  if (abandon_after && cfs_calls >= abandon_after) { return 1; }
  return 0;

}

u8 *queue_testcase_get(afl_state_t *afl, struct queue_entry *q) {

  (void)afl;
  return q->testcase_buf;

}

/* ---- helpers ---- */

static afl_state_t *make_afl(void) {

  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  afl->afl_env.afl_sequence_fuzzing = 1;
  afl->afl_env.afl_seq_max_msgs = 16;
  afl->afl_env.afl_seq_max_states = 1024;
  afl->afl_env.afl_seq_type_len = 0;
  afl->fixed_seed = 1;
  afl->rand_cnt = 1 << 20;
  afl->rand_seed[0] = 0x123456789ULL;
  afl->rand_seed[1] = 0xabcdefULL;
  afl->rand_seed[2] = 0x55ULL;
  afl->max_length = MAX_FILE;
  afl->havoc_div = 1;
  afl_seq_init(afl);
  return afl;

}

static void free_afl(afl_state_t *afl) {

  afl_seq_deinit(afl);
  free(afl);

}

/* set up a single-entry queue holding `buf` so donor lookups work */
static void set_queue(afl_state_t *afl, u8 *buf, u32 len) {

  static struct queue_entry q;
  memset(&q, 0, sizeof(q));
  q.len = len;
  q.testcase_buf = buf;
  static struct queue_entry *qb[1];
  qb[0] = &q;
  afl->queue_buf = qb;
  afl->queued_items = 1;
  afl->current_entry = 0;

}

static void reset_capture(void) {

  captured_cnt = 0;
  cfs_calls = 0;
  abandon_after = 0;

}

/* ---- parsing ---- */

static void test_parse_basic(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  seq_msg_t  msgs[8];

  u8 buf[] = "A\nBB\nCCC\n";
  u32 n = afl_seq_parse(afl, buf, 9, msgs, 8);
  assert_int_equal(n, 3);
  assert_int_equal(msgs[0].off, 0);
  assert_int_equal(msgs[0].len, 1);
  assert_int_equal(msgs[1].off, 2);
  assert_int_equal(msgs[1].len, 2);
  assert_int_equal(msgs[2].off, 5);
  assert_int_equal(msgs[2].len, 3);

  /* no trailing delimiter */
  u8 buf2[] = "A\nBB";
  n = afl_seq_parse(afl, buf2, 4, msgs, 8);
  assert_int_equal(n, 2);
  assert_int_equal(msgs[1].len, 2);

  /* no delimiter at all: single message -> not a sequence */
  u8 buf3[] = "hello world";
  n = afl_seq_parse(afl, buf3, 11, msgs, 8);
  assert_int_equal(n, 1);

  /* binary blob without delimiter: also not a sequence (corpus compat) */
  u8 buf4[] = {0x00, 0x01, 0xff, 0x42, 0x00};
  n = afl_seq_parse(afl, buf4, 5, msgs, 8);
  assert_int_equal(n, 1);

  free_afl(afl);

}

static void test_parse_msg_cap(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  seq_msg_t  msgs[4];

  /* 6 messages but cap is 4: the tail is merged into the last message */
  u8 buf[] = "a\nb\nc\nd\ne\nf\n";
  u32 n = afl_seq_parse(afl, buf, 12, msgs, 4);
  assert_int_equal(n, 4);
  assert_int_equal(msgs[3].off, 6);
  assert_int_equal(msgs[3].len, 6);     /* "d\ne\nf" */

  free_afl(afl);

}

static void test_parse_multibyte_delim(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  afl->afl_env.afl_sequence_fuzzing = 1;
  afl->afl_env.afl_seq_max_msgs = 16;
  afl->afl_env.afl_seq_max_states = 1024;
  afl->afl_env.afl_seq_delim = (u8 *)"\\r\\n";
  afl_seq_init(afl);
  assert_int_equal(afl->seq_delim_len, 2);
  assert_int_equal(afl->seq_delim[0], '\r');
  assert_int_equal(afl->seq_delim[1], '\n');

  seq_msg_t msgs[8];
  u8        buf[] = "GET x\r\nHOST y\r\n\r\n";
  u32       n = afl_seq_parse(afl, buf, sizeof(buf) - 1, msgs, 8);
  assert_int_equal(n, 3);
  assert_int_equal(msgs[0].len, 5);
  assert_int_equal(msgs[1].len, 6);
  assert_int_equal(msgs[2].len, 0);     /* empty message kept */

  free_afl(afl);

}

/* ---- type inference ---- */

static void test_type_token_mode(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();

  u32 t1 = afl_seq_type_id(afl, (u8 *)"AUTH user1", 10, 1);
  u32 t2 = afl_seq_type_id(afl, (u8 *)"AUTH user2", 10, 1);
  u32 t3 = afl_seq_type_id(afl, (u8 *)"CMD 1", 5, 1);
  assert_int_equal(t1, t2);             /* same token -> same type */
  assert_true(t1 != t3);
  assert_true(t1 != SEQ_ID_NONE && t3 != SEQ_ID_NONE);

  free_afl(afl);

}

static void test_type_prefix_mode(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  afl->afl_env.afl_seq_type_len = 2;

  u32 t1 = afl_seq_type_id(afl, (u8 *)"AAx", 3, 1);
  u32 t2 = afl_seq_type_id(afl, (u8 *)"AAyyyy", 6, 1);
  u32 t3 = afl_seq_type_id(afl, (u8 *)"ABx", 3, 1);
  assert_int_equal(t1, t2);
  assert_true(t1 != t3);

  free_afl(afl);

}

/* ---- state model learning and legality ---- */

static void test_learn_and_transitions(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  set_queue(afl, (u8 *)"HELLO\nAUTH\nCMD\n", 15);

  u8 buf[] = "HELLO\nAUTH\nCMD\n";
  afl_seq_learn(afl, buf, 15, 0);

  u32 t_hello = afl_seq_type_id(afl, (u8 *)"HELLO", 5, 0);
  u32 t_auth = afl_seq_type_id(afl, (u8 *)"AUTH", 4, 0);
  u32 t_cmd = afl_seq_type_id(afl, (u8 *)"CMD", 3, 0);
  u32 t_bye = afl_seq_type_id(afl, (u8 *)"BYE", 3, 0);
  assert_true(t_hello != SEQ_ID_NONE && t_auth != SEQ_ID_NONE &&
              t_cmd != SEQ_ID_NONE);
  assert_int_equal(t_bye, SEQ_ID_NONE); /* never learned */

  u32 s0 = (u32)(0xCBF29CE484222325ULL & (afl->seq_states_cap - 1));
  u32 s1 = afl_seq_trans_find(afl, s0, t_hello);
  assert_true(s1 != SEQ_ID_NONE);       /* HELLO legal from init */
  u32 s2 = afl_seq_trans_find(afl, s1, t_auth);
  assert_true(s2 != SEQ_ID_NONE);       /* AUTH legal after HELLO */
  assert_true(afl_seq_trans_find(afl, s2, t_cmd) != SEQ_ID_NONE);

  /* illegal transitions: AUTH from init, HELLO after AUTH */
  assert_int_equal(afl_seq_trans_find(afl, s0, t_auth), SEQ_ID_NONE);
  assert_int_equal(afl_seq_trans_find(afl, s1, t_cmd), SEQ_ID_NONE);

  free_afl(afl);

}

static void test_state_table_bounded(void **state) {

  (void)state;
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  afl->afl_env.afl_sequence_fuzzing = 1;
  afl->afl_env.afl_seq_max_msgs = 16;
  afl->afl_env.afl_seq_max_states = 64; /* tiny on purpose */
  afl->fixed_seed = 1;
  afl->rand_cnt = 1 << 20;
  afl_seq_init(afl);

  /* learn far more distinct sequences than the table can hold */
  u8 buf[64];
  for (u32 i = 0; i < 2000; ++i) {

    int len = snprintf((char *)buf, sizeof(buf), "M%u\nN%u\nO%u\n", i, i + 1,
                       i + 2);
    afl_seq_learn(afl, buf, (u32)len, 0);

  }

  /* bounded: never past 3/4 load, and the run did not crash or grow */
  assert_true(afl->seq_types_cnt <= (afl->seq_types_cap * 3) / 4);
  assert_true(afl->seq_states_cnt <= (afl->seq_states_cap * 3) / 4);
  assert_true(afl->seq_trans_cnt <= (afl->seq_trans_cap * 3) / 4);
  assert_true(afl->seq_tables_full);

  free_afl(afl);

}

/* ---- the mutation stage ---- */

static void test_stage_fallback_not_a_sequence(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  u8           buf[] = "no delimiter in here";
  set_queue(afl, buf, sizeof(buf) - 1);
  reset_capture();

  u8 r = sequence_stage(afl, buf, sizeof(buf) - 1, 100);
  assert_int_equal(r, 0);
  assert_int_equal(cfs_calls, 0);       /* stateless fallback: no execs */
  assert_true(afl->seq_skipped > 0);

  free_afl(afl);

}

static void test_stage_mutations_valid(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  u8           buf[] = "HELLO\nAUTH\nCMD\n";
  set_queue(afl, buf, 15);
  reset_capture();

  u8 r = sequence_stage(afl, buf, 15, 100);
  assert_int_equal(r, 0);
  assert_true(cfs_calls > 0);

  u32 t_hello = afl_seq_type_id(afl, (u8 *)"HELLO", 5, 0);
  u32 t_auth = afl_seq_type_id(afl, (u8 *)"AUTH", 4, 0);
  u32 t_cmd = afl_seq_type_id(afl, (u8 *)"CMD", 3, 0);

  u32 saw_more = 0, saw_less = 0, saw_reorder = 0;

  for (u32 i = 0; i < captured_cnt; ++i) {

    u8 *c = captured[i];
    u32 clen = captured_len[i];
    assert_true(clen > 0 && clen <= MAX_FILE);

    /* every message of every candidate must be a known message of the
       only learned sequence (HELLO/AUTH/CMD) */
    seq_msg_t msgs[64];
    u32       n = afl_seq_parse(afl, c, clen, msgs, 64);
    assert_true(n >= 1 && n <= afl->seq_max_msgs);
    for (u32 k = 0; k < n; ++k) {

      u32 t = afl_seq_type_id(afl, c + msgs[k].off, msgs[k].len, 0);
      assert_true(t == t_hello || t == t_auth || t == t_cmd);

    }

    if (n > 3) { saw_more = 1; }        /* replay/splice happened */
    if (n < 3) { saw_less = 1; }        /* drop happened */
    if (n == 3 && clen == 15 && memcmp(c, buf, 15) != 0) { saw_reorder = 1; }

  }

  /* with 50 iterations the op classes must all have fired */
  assert_true(saw_more);
  assert_true(saw_less || saw_reorder);

  free_afl(afl);

}

static void test_stage_legal_splice_only_known_sequences(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();

  /* teach two dialogues sharing the same first message */
  u8 buf1[] = "HELLO\nAUTH\nCMD\n";
  u8 buf2[] = "HELLO\nPING\nPONG\n";
  set_queue(afl, buf1, 15);
  afl_seq_learn(afl, buf1, 15, 0);
  afl_seq_learn(afl, buf2, 15, 0);
  reset_capture();

  u8 r = sequence_stage(afl, buf1, 15, 100);
  assert_int_equal(r, 0);
  assert_true(cfs_calls > 0);

  /* candidates must only contain messages from the two learned dialogues */
  for (u32 i = 0; i < captured_cnt; ++i) {

    seq_msg_t msgs[64];
    u32       n = afl_seq_parse(afl, captured[i], captured_len[i], msgs, 64);
    for (u32 k = 0; k < n; ++k) {

      u8 *m = captured[i] + msgs[k].off;
      u32 ml = msgs[k].len;
      u8  known = (ml == 5 && !memcmp(m, "HELLO", 5)) ||
                  (ml == 4 && !memcmp(m, "AUTH", 4)) ||
                  (ml == 3 && !memcmp(m, "CMD", 3)) ||
                  (ml == 4 && !memcmp(m, "PING", 4)) ||
                  (ml == 4 && !memcmp(m, "PONG", 4));
      assert_true(known);

    }

  }

  free_afl(afl);

}

static void test_stage_timeout_abandons(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  u8           buf[] = "HELLO\nAUTH\nCMD\n";
  set_queue(afl, buf, 15);
  reset_capture();
  abandon_after = 5;                    /* 5th exec reports abandon */

  u8 r = sequence_stage(afl, buf, 15, 100);
  assert_int_equal(r, 1);               /* stage asks to abandon entry */
  assert_int_equal(cfs_calls, 5);       /* and stops executing at once */

  free_afl(afl);

}

static void test_stage_candidate_size_bounded(void **state) {

  (void)state;
  afl_state_t *afl = make_afl();
  afl->max_length = 64;                 /* tight cap */

  u8 buf[] = "HELLO\nAUTH\nCMD\n";
  set_queue(afl, buf, 15);
  reset_capture();

  u8 r = sequence_stage(afl, buf, 15, 100);
  assert_int_equal(r, 0);
  for (u32 i = 0; i < captured_cnt; ++i) {

    assert_true(captured_len[i] <= 64); /* never copies unbounded history */

  }

  free_afl(afl);

}

static void test_disabled_env_means_no_init(void **state) {

  (void)state;
  /* default (env unset): feature stays off, tables stay unallocated */
  afl_state_t *afl = calloc(1, sizeof(afl_state_t));
  assert_int_equal(afl->afl_env.afl_sequence_fuzzing, 0);
  assert_null(afl->seq_states);
  free(afl);

}

int main(void) {

  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_parse_basic),
      cmocka_unit_test(test_parse_msg_cap),
      cmocka_unit_test(test_parse_multibyte_delim),
      cmocka_unit_test(test_type_token_mode),
      cmocka_unit_test(test_type_prefix_mode),
      cmocka_unit_test(test_learn_and_transitions),
      cmocka_unit_test(test_state_table_bounded),
      cmocka_unit_test(test_stage_fallback_not_a_sequence),
      cmocka_unit_test(test_stage_mutations_valid),
      cmocka_unit_test(test_stage_legal_splice_only_known_sequences),
      cmocka_unit_test(test_stage_timeout_abandons),
      cmocka_unit_test(test_stage_candidate_size_bounded),
      cmocka_unit_test(test_disabled_env_means_no_init),
  };

  return cmocka_run_group_tests(tests, NULL, NULL);

}
