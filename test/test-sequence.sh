#!/bin/bash
# test/test-sequence.sh -- integration tests for the optional stateful /
# sequence fuzzing stage (AFL_SEQUENCE_FUZZING):
#   1. state machine target: deep crash behind a 4-step handshake is found
#   2. transitions/replay: the sequence stage produces queue entries (op:seq)
#   3. default regression: without the env var, behavior is unchanged
#   4. corpus compatibility: non-sequence (binary) inputs fall back cleanly
#   5. timeout handling: timeout-inducing inputs do not stall the fuzzer
#   6. CmpLog coexistence: sequence stage works together with -c cmplog

. ./test-pre.sh

# pick an available instrumenting compiler
AFL_COMPILER=
for c in afl-gcc-fast afl-clang-fast; do
  test -x ../$c && AFL_COMPILER=$c && break
done

if test -z "$AFL_COMPILER" -o ! -x ../afl-fuzz; then
  $ECHO "$YELLOW[-] afl-gcc-fast/afl-clang-fast or afl-fuzz not built, skipping sequence fuzzing tests"
  INCOMPLETE=1
  . ./test-post.sh
  exit 0
fi

$ECHO "$BLUE[*] Testing: stateful sequence fuzzing (AFL_SEQUENCE_FUZZING) with $AFL_COMPILER"

rm -rf in out out_def out_to out_cmp sm sm.cmplog errors

# --- build the state machine target -------------------------------------

AFL_QUIET=1 ../$AFL_COMPILER -O0 -o sm ../test/test-state-machine.c > /dev/null 2>&1
test -x sm || {
  $ECHO "$RED[!] $AFL_COMPILER failed to compile the state machine target"
  CODE=1
  . ./test-post.sh
  exit 1
}
$ECHO "$GREEN[+] state machine target compiled with $AFL_COMPILER"

# sanity: the full handshake crashes, a partial one does not
printf 'HELLO\nAUTH\nCMD\nBYE\n' | ./sm > /dev/null 2>&1
test $? -ge 128 && {
  $ECHO "$GREEN[+] target crashes on the full handshake as designed"
} || {
  $ECHO "$RED[!] target does not crash on the full handshake - target broken"
  CODE=1
}
printf 'HELLO\nAUTH\n' | ./sm > /dev/null 2>&1
test $? -eq 0 || {
  $ECHO "$RED[!] target crashes on a partial handshake - target broken"
  CODE=1
}

# --- seeds: fragments of the dialogue plus a binary (non-sequence) input --

mkdir -p in
printf 'HELLO\nAUTH\nCMD\n' > in/1
printf 'CMD\nBYE\n' > in/2
printf 'PING\nHELLO\n' > in/3
printf '\x00\x01\x02\x03\x04' > in/4

# --- 1+2+4: sequence mode finds the deep crash ---------------------------

unset AFL_SEQUENCE_FUZZING
$ECHO "$GREY[*] running afl-fuzz with AFL_SEQUENCE_FUZZING=1, this takes ~25 seconds"
AFL_SEQUENCE_FUZZING=1 AFL_NO_UI=1 ../afl-fuzz -V 25 -m ${MEM_LIMIT} -i in -o out -- ./sm >> errors 2>&1

test -n "$(ls out/default/crashes/id:* 2>/dev/null)" && {
  $ECHO "$GREEN[+] sequence fuzzing found the deep state-machine crash"
} || {
  echo CUT------------------------------------------------------------------CUT
  cat errors
  echo CUT------------------------------------------------------------------CUT
  $ECHO "$RED[!] sequence fuzzing did not find the state-machine crash"
  CODE=1
}

# the sequence stage must have produced queue entries itself (op:seq)
test -n "$(ls out/default/queue/*op:seq* 2>/dev/null)" && {
  $ECHO "$GREEN[+] sequence stage produced queue entries (splice/replay/reorder)"
} || {
  $ECHO "$RED[!] no queue entries from the sequence stage (op:seq) found"
  CODE=1
}

# the binary seed must not have broken anything (corpus compatibility):
# the fuzzer completed its run and executed inputs
test "$(grep -a '^execs_done' out/default/fuzzer_stats 2>/dev/null | awk '{print $3}')" -gt 0 2>/dev/null && {
  $ECHO "$GREEN[+] non-sequence inputs in the corpus fall back to stateless mode cleanly"
} || {
  $ECHO "$RED[!] fuzzer did not execute anything with a mixed corpus"
  CODE=1
}

# --- 3: default regression: no env var -> classic behavior ---------------

$ECHO "$GREY[*] running afl-fuzz without AFL_SEQUENCE_FUZZING (default regression), ~10 seconds"
unset AFL_SEQUENCE_FUZZING
AFL_NO_UI=1 ../afl-fuzz -V 10 -m ${MEM_LIMIT} -i in -o out_def -- ./sm >> errors 2>&1

test -n "$(ls out_def/default/queue/id:000001* 2>/dev/null)" && {
  $ECHO "$GREEN[+] default fuzzing without the sequence stage works unchanged"
} || {
  echo CUT------------------------------------------------------------------CUT
  cat errors
  echo CUT------------------------------------------------------------------CUT
  $ECHO "$RED[!] default fuzzing run regressed"
  CODE=1
}
# and of course no sequence-stage entries without the env var
test -z "$(ls out_def/default/queue/*op:seq* 2>/dev/null)" && {
  $ECHO "$GREEN[+] no sequence stage activity without AFL_SEQUENCE_FUZZING"
} || {
  $ECHO "$RED[!] sequence stage ran even though AFL_SEQUENCE_FUZZING was unset"
  CODE=1
}

# --- 5: timeout handling --------------------------------------------------

mkdir -p in_to
printf 'SLOW\nHELLO\n' > in_to/1
printf 'HELLO\nAUTH\n' > in_to/2
$ECHO "$GREY[*] running afl-fuzz with timeout-inducing inputs, ~10 seconds"
AFL_SEQUENCE_FUZZING=1 AFL_NO_UI=1 AFL_NO_STARTUP_CALIBRATION=1 AFL_CAL_FAST=1 \
  ../afl-fuzz -V 10 -t 200 -m ${MEM_LIMIT} -i in_to -o out_to -- ./sm >> errors 2>&1

test "$(grep -a '^execs_done' out_to/default/fuzzer_stats 2>/dev/null | awk '{print $3}')" -gt 0 2>/dev/null && {
  $ECHO "$GREEN[+] fuzzer keeps going with timeout-inducing sequences"
} || {
  echo CUT------------------------------------------------------------------CUT
  cat errors
  echo CUT------------------------------------------------------------------CUT
  $ECHO "$RED[!] fuzzer stalled on timeout-inducing inputs"
  CODE=1
}

# --- 6: CmpLog coexistence ------------------------------------------------

AFL_QUIET=1 AFL_GCC_CMPLOG=1 AFL_LLVM_CMPLOG=1 ../$AFL_COMPILER -O0 -o sm.cmplog ../test/test-state-machine.c > /dev/null 2>&1
if test -x sm.cmplog; then
  $ECHO "$GREY[*] running afl-fuzz with CmpLog + sequence fuzzing, ~8 seconds"
  AFL_SEQUENCE_FUZZING=1 AFL_NO_UI=1 ../afl-fuzz -V 8 -m ${MEM_LIMIT} -i in -o out_cmp -c ./sm.cmplog -- ./sm >> errors 2>&1
  test "$(grep -a '^execs_done' out_cmp/default/fuzzer_stats 2>/dev/null | awk '{print $3}')" -gt 0 2>/dev/null && {
    $ECHO "$GREEN[+] sequence fuzzing coexists with CmpLog"
  } || {
    echo CUT------------------------------------------------------------------CUT
    cat errors
    echo CUT------------------------------------------------------------------CUT
    $ECHO "$RED[!] fuzzer with CmpLog + sequence fuzzing did not run"
    CODE=1
  }
else
  $ECHO "$YELLOW[-] cmplog build of the target failed, skipping coexistence test"
  INCOMPLETE=1
fi

rm -rf in in_to out out_def out_to out_cmp sm sm.cmplog

. ./test-post.sh
