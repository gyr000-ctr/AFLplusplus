/* End-to-end target for checksum-aware fuzzing.

   Input layout (little-endian):
     [0..1]    total length (u16)
     [2..3]    payload length after this field (u16) = len - 4
     [4..len-5] payload (magic "PASS" unlocks the bug)
     [len-4..]  CRC-32 (zlib) over the whole record, checksum slot zeroed

   The target rejects anything with a bad length or CRC before reaching the
   buggy payload logic, so plain mutations never get past validation.  A
   checksum-aware fuzzer repairs both length fields and the CRC after each
   mutation, letting the payload be explored and the crash reached.

   Built with a plain compiler and run under afl-fuzz -n (dumb mode), which
   still detects the crash via the signal. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t crc32_zlib(const uint8_t *p, size_t n, size_t zero_off,
                           size_t zero_w) {

  uint32_t c = 0xffffffffu;
  for (size_t i = 0; i < n; ++i) {

    uint8_t b = (i >= zero_off && i < zero_off + zero_w) ? 0 : p[i];
    c ^= b;
    for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & -(c & 1));

  }

  return ~c;

}

int main(void) {

  uint8_t buf[1024];
  ssize_t n = read(0, buf, sizeof(buf));
  if (n < 8) return 1;

  uint16_t total = (uint16_t)(buf[0] | (buf[1] << 8));
  uint16_t pay = (uint16_t)(buf[2] | (buf[3] << 8));

  if (total != (uint16_t)n) return 2;
  if (pay != (uint16_t)(n - 4)) return 3;

  uint32_t stored = (uint32_t)buf[n - 4] | ((uint32_t)buf[n - 3] << 8) |
                    ((uint32_t)buf[n - 2] << 16) |
                    ((uint32_t)buf[n - 1] << 24);
  if (stored != crc32_zlib(buf, (size_t)n, (size_t)n - 4, 4)) return 4;

  /* valid record: a single mutated payload byte reaching value 0x7f unlocks
     the bug - reachable by one havoc byte mutation once checksums are
     repaired. */
  for (ssize_t i = 4; i < n - 4; ++i)
    if (buf[i] == 0x7f) abort();

  return 0;

}
