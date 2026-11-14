/* End-to-end target exercising MULTIPLE, independent checksum regions.

   Input layout (little-endian):
     [0..7]    header (free-form payload region A)
     [8..9]    SUM16 over bytes [0,8)
     [10..17]  payload region B
     [18..19]  XOR16-equivalent (two byte xor folded, stored LE u16) over
               bytes [10,18)
     [20..23]  CRC-32 (zlib) over bytes [0,20), slot zeroed

   All three must validate before the "PASS" magic (anywhere in region A or
   B) triggers abort().  Disjoint spans mean no checksum covers another's
   slot. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static uint32_t crc32_zlib(const uint8_t *p, size_t n) {

  uint32_t c = 0xffffffffu;
  for (size_t i = 0; i < n; ++i) {

    c ^= p[i];
    for (int k = 0; k < 8; ++k) c = (c >> 1) ^ (0xedb88320u & -(c & 1));

  }

  return ~c;

}

int main(void) {

  uint8_t buf[1024];
  ssize_t n = read(0, buf, sizeof(buf));
  if (n < 24) return 1;

  uint16_t sum = 0;
  for (int i = 0; i < 8; ++i) sum = (uint16_t)(sum + buf[i]);
  uint16_t sum_stored = (uint16_t)(buf[8] | (buf[9] << 8));
  if (sum != sum_stored) return 2;

  uint16_t x = 0;
  /* byte-wise XOR fold, matching AFL CK_ALGO_XOR16 (u16 accumulation) */
  for (int i = 10; i < 18; ++i) x = (uint16_t)(x ^ buf[i]);
  uint16_t x_stored = (uint16_t)(buf[18] | (buf[19] << 8));
  if (x != x_stored) return 3;

  /* crc over [0,20), its own slot at [20,24) excluded from the span */
  uint32_t c = crc32_zlib(buf, 20);
  uint32_t c_stored = (uint32_t)buf[20] | ((uint32_t)buf[21] << 8) |
                      ((uint32_t)buf[22] << 16) | ((uint32_t)buf[23] << 24);
  if (c != c_stored) return 4;

  /* single-byte trigger inside either payload region */
  for (int i = 0; i < 8; ++i)
    if (buf[i] == 0x7f) abort();
  for (int i = 10; i < 18; ++i)
    if (buf[i] == 0x7f) abort();
  return 0;

}
