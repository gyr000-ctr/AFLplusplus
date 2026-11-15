/*
   Stateful protocol target for the sequence-fuzzing integration test
   (test-sequence.sh). The input is a newline-delimited message sequence:

     INIT  --HELLO-->  GREETED  --AUTH-->  AUTHD  --CMD-->  EXECD --BYE--> DONE

   Reaching DONE (a complete, in-order handshake) triggers the simulated
   deep bug (abort). Illegal messages divert to an error state with its own
   coverage. SLOW takes a slow path to exercise timeout handling. PING is
   legal in any state. All of this is invisible to byte-level mutation: the
   crash needs four exact messages in the exact order.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {

  ST_INIT,
  ST_GREETED,
  ST_AUTHD,
  ST_EXECD,
  ST_DONE,
  ST_ERR

};

static int state = ST_INIT;

static void handle(const char *msg, size_t len) {

  /* per-state coverage so the fuzzer can tell states apart */
  switch (state) {

    case ST_INIT: puts("s:init"); break;
    case ST_GREETED: puts("s:greeted"); break;
    case ST_AUTHD: puts("s:authd"); break;
    case ST_EXECD: puts("s:execd"); break;
    case ST_DONE: puts("s:done"); break;
    default: puts("s:err"); break;

  }

  if (len == 5 && !memcmp(msg, "HELLO", 5)) {

    state = (state == ST_INIT) ? ST_GREETED : ST_ERR;

  } else if (len >= 4 && !memcmp(msg, "AUTH", 4)) {

    state = (state == ST_GREETED) ? ST_AUTHD : ST_ERR;

  } else if (len >= 3 && !memcmp(msg, "CMD", 3)) {

    state = (state == ST_AUTHD) ? ST_EXECD : ST_ERR;

  } else if (len == 3 && !memcmp(msg, "BYE", 3)) {

    state = (state == ST_EXECD) ? ST_DONE : ST_ERR;

  } else if (len == 4 && !memcmp(msg, "PING", 4)) {

    puts("pong");                         /* legal in every state */

  } else if (len == 4 && !memcmp(msg, "SLOW", 4)) {

    usleep(300000);                       /* slow path: timeout tests */

  } else {

    state = ST_ERR;

  }

}

int main(void) {

  static char buf[1 << 16];
  size_t      len = fread(buf, 1, sizeof(buf) - 1, stdin);
  buf[len] = 0;

  size_t start = 0;
  for (size_t i = 0; i <= len; ++i) {

    if (i == len || buf[i] == '\n') {

      if (i > start) { handle(buf + start, i - start); }
      start = i + 1;

    }

  }

  if (state == ST_DONE) {

    /* deep bug: only reachable via the full in-order handshake */
    abort();

  }

  puts("bye");
  return 0;

}
