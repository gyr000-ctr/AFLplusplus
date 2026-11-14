#!/bin/sh

# End-to-end tests for checksum-aware mutation.
#
# The test image has no instrumentation compiler (no clang / gcc plugin),
# so targets are built with the plain compiler and driven through
# `afl-fuzz -n` (dumb mode). Dumb mode still detects crashes via signals and
# writes a flat output tree (out/crashes rather than out/default/crashes).
#
# Scenarios:
#   1. default regression: with no AFL_CHECKSUM* the feature is inert and the
#      checksum-protected target never reaches its crash.
#   2. CRC + nested length: an explicit AFL_CHECKSUM spec repairs the length
#      fields and the CRC and the guarded crash is reached.
#   3. multiple checksums: three disjoint regions (sum16/xor16/crc32) are all
#      repaired and the crash is reached.
#   4. misinference / auto mode: AFL_CHECKSUM_INFER initializes a bounded
#      candidate table and runs without corrupting inputs or crashing itself.

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: checksum-aware mutation"

CODE_LOCAL=0
SEED_GEN="$(pwd)/checksum_seeds/gen_seeds.py"

cc -O2 -o test-checksum-target test-checksum-target.c 2>errors || {
  $ECHO "$RED[!] cannot compile test-checksum-target"
  cat errors
  CODE=1
  . ./test-post.sh
  exit 1
}
cc -O2 -o test-checksum-multi-target test-checksum-multi-target.c 2>>errors || {
  $ECHO "$RED[!] cannot compile test-checksum-multi-target"
  cat errors
  CODE=1
  . ./test-post.sh
  exit 1
}
cc -O2 -fPIC -shared -I../include -o libckmutator.so \
  checksum_seeds/custom_checksum_mutator.c 2>>errors || {
  $ECHO "$RED[!] cannot compile custom checksum mutator"
  cat errors
  CODE=1
  . ./test-post.sh
  exit 1
}

# ---------------------------------------------------------------------------
# Scenario 1 + 2: CRC + nested length target
# ---------------------------------------------------------------------------
mkdir -p in-ck
python3 -I "$SEED_GEN" single in-ck

# sanity: the seed validates and does not crash
if ./test-checksum-target < in-ck/seed; then
  $ECHO "$GREEN[+] valid seed accepted without crashing"
else
  $ECHO "$RED[!] valid seed rejected or crashed unexpectedly"
  CODE_LOCAL=1
fi

# --- 1. default path: feature off. The target rejects every broken checksum,
# so no crash must appear and no checksum log line must be emitted.
$ECHO "$GREY[*] default (feature disabled) run, approx 8s"
env -u AFL_CHECKSUM -u AFL_CHECKSUM_INFER -u AFL_CHECKSUM_MAX \
  AFL_TRY_AFFINITY=1 AFL_QUIET=1 \
  ../afl-fuzz -n -V8 -m none -i in-ck -o out-off -- \
  ./test-checksum-target >>errors 2>&1
test -z "$(ls out-off/crashes/id:000000* 2>/dev/null)" && {
  $ECHO "$GREEN[+] default mutation path leaves checksums intact (no false crash)"
} || {
  $ECHO "$RED[!] unexpected crash with checksum feature disabled"
  CODE_LOCAL=1
}
if grep -q "Checksum-aware" errors; then
  $ECHO "$RED[!] checksum subsystem logged activity while disabled"
  CODE_LOCAL=1
fi
rm -rf out-off

# --- 2. enabled with an explicit region spec:
#   len:0:2:0:0:0:0           total length, u16 LE, len-kind TOTAL(0)
#   len:2:2:0:0:0:1           length AFTER field, u16 LE
#   crc32:<n-4>:4:0:0:0       crc32 LE over whole input (slot zeroed)
SEED_LEN=$(wc -c < in-ck/seed)
CRC_OFF=$((SEED_LEN - 4))
CK_SPEC="len:0:2:0:0:0:0;len:2:2:0:0:0:1;crc32:${CRC_OFF}:4:0:0:0"

$ECHO "$GREY[*] checksum-aware run (explicit spec), approx 12s"
AFL_CHECKSUM="$CK_SPEC" AFL_TRY_AFFINITY=1 AFL_QUIET=1 \
  ../afl-fuzz -n -V12 -m none -i in-ck -o out-ck -- \
  ./test-checksum-target >>errors 2>&1
CRASH=$(ls out-ck/crashes/id:000000* 2>/dev/null | head -1)
test -n "$CRASH" && {
  # prove the crashing input really passed validation (signal 6 = SIGABRT)
  if ./test-checksum-target < "$CRASH" 2>/dev/null; then :; else rc=$?; fi
  test "${rc:-0}" = "134" && {
    $ECHO "$GREEN[+] checksum repair reached the guarded crash (CRC + lengths)"
  } || {
    $ECHO "$RED[!] crash input did not pass target validation (rc=${rc:-0})"
    CODE_LOCAL=1
  }
} || {
  $ECHO "$RED[!] checksum-aware fuzzing failed to reach the crash"
  cat errors
  CODE_LOCAL=1
}
rm -rf out-ck

# --- 2b. custom mutator compatibility: the mutator only changes payload
# bytes, so without repair every output fails the target's checksum; with
# repair the guarded crash must be reachable.
$ECHO "$GREY[*] custom-mutator + checksum repair run, approx 12s"
AFL_CUSTOM_MUTATOR_LIBRARY="$(pwd)/libckmutator.so" AFL_CHECKSUM="$CK_SPEC" \
  AFL_TRY_AFFINITY=1 AFL_QUIET=1 \
  ../afl-fuzz -n -V12 -m none -i in-ck -o out-cm -- \
  ./test-checksum-target >>errors 2>&1
CMCRASH=$(ls out-cm/crashes/id:000000* 2>/dev/null | head -1)
test -n "$CMCRASH" && {
  if ./test-checksum-target < "$CMCRASH" 2>/dev/null; then :; else cmrc=$?; fi
  test "${cmrc:-0}" = "134" && {
    $ECHO "$GREEN[+] checksum repair wraps custom mutator output, crash reached"
  } || {
    $ECHO "$RED[!] custom-mutator crash input failed validation (rc=${cmrc:-0})"
    CODE_LOCAL=1
  }
} || {
  $ECHO "$RED[!] custom-mutator + repair failed to reach the crash"
  cat errors
  CODE_LOCAL=1
}
rm -rf out-cm

# ---------------------------------------------------------------------------
# Scenario 3: multiple disjoint checksums
# ---------------------------------------------------------------------------
mkdir -p in-multi
python3 -I "$SEED_GEN" multi in-multi
if ./test-checksum-multi-target < in-multi/seed; then
  $ECHO "$GREEN[+] multi-checksum seed accepted"
else
  $ECHO "$RED[!] multi-checksum seed rejected"
  CODE_LOCAL=1
fi

# sum16 at 8 (span 0..8); xor16 at 18 (span 10..18); crc32 at 20 (span 0..20)
MULTI_SPEC="sum16:8:2:0:0:8;xor16:18:2:0:10:18;crc32:20:4:0:0:20"
$ECHO "$GREY[*] multi-checksum run, approx 15s"
AFL_CHECKSUM="$MULTI_SPEC" AFL_TRY_AFFINITY=1 AFL_QUIET=1 \
  ../afl-fuzz -n -V15 -m none -i in-multi -o out-multi -- \
  ./test-checksum-multi-target >>errors 2>&1
MCRASH=$(ls out-multi/crashes/id:000000* 2>/dev/null | head -1)
test -n "$MCRASH" && {
  if ./test-checksum-multi-target < "$MCRASH" 2>/dev/null; then :; else mrc=$?; fi
  test "${mrc:-0}" = "134" && {
    $ECHO "$GREEN[+] all three checksum regions repaired, crash reached"
  } || {
    $ECHO "$RED[!] multi crash input failed validation (rc=${mrc:-0})"
    CODE_LOCAL=1
  }
} || {
  $ECHO "$RED[!] multi-checksum fuzzing failed to reach the crash"
  cat errors
  CODE_LOCAL=1
}
rm -rf out-multi

# ---------------------------------------------------------------------------
# Scenario 4: auto inference must initialize a bounded table and stay healthy
# ---------------------------------------------------------------------------
$ECHO "$GREY[*] auto-inference run, approx 10s"
AFL_CHECKSUM_INFER=1 AFL_CHECKSUM_MAX=8 AFL_TRY_AFFINITY=1 AFL_QUIET=1 \
  ../afl-fuzz -n -V10 -m none -i in-ck -o out-infer -- \
  ./test-checksum-target >>errors 2>&1
grep -q "auto inference enabled (cap=8)" errors && {
  $ECHO "$GREEN[+] auto inference initialized with the bounded candidate table"
} || {
  $ECHO "$RED[!] auto inference did not initialize at the requested cap"
  cat errors
  CODE_LOCAL=1
}
test -d out-infer/queue && test -n "$(ls out-infer/queue/id:000000* 2>/dev/null)" && {
  $ECHO "$GREEN[+] inference run executed the target without self-corruption"
} || {
  $ECHO "$RED[!] inference run produced no queue state"
  CODE_LOCAL=1
}
rm -rf out-infer

rm -f test-checksum-target test-checksum-multi-target libckmutator.so errors
rm -rf in-ck in-multi

if [ "$CODE_LOCAL" -eq 0 ]; then
  $ECHO "$GREEN[+] all checksum end-to-end tests passed"
else
  CODE=1
fi

. ./test-post.sh
