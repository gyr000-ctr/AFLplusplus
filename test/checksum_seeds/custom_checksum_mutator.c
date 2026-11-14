/* Custom mutator for the checksum end-to-end test.

   It performs a single deterministic byte mutation inside the payload region
   (never touching the length header at [0,4) or the trailing CRC), which
   deliberately invalidates the target's checksum. The checksum-aware repair
   layer in afl-fuzz must then recompute the integrity fields for the mutated
   buffer to be accepted. This proves repair also wraps custom mutator output,
   not just the built-in havoc pipeline. */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "afl-fuzz.h"

typedef struct ck_mut {

  uint8_t *out;
  size_t   cap;
  uint32_t step;

} ck_mut_t;

void *afl_custom_init(afl_state_t *afl, unsigned int seed) {

  (void)afl;
  (void)seed;
  ck_mut_t *m = calloc(1, sizeof(ck_mut_t));
  m->cap = 4096;
  m->out = malloc(m->cap);
  return m;

}

size_t afl_custom_fuzz(void *data, uint8_t *buf, size_t buf_size,
                       uint8_t **out_buf, uint8_t *add_buf,
                       size_t add_buf_size, size_t max_size) {

  (void)add_buf;
  (void)add_buf_size;
  (void)max_size;
  ck_mut_t *m = data;
  if (buf_size < 9 || buf_size > m->cap) { *out_buf = buf; return buf_size; }

  memcpy(m->out, buf, buf_size);

  /* Cycle a payload byte (offset 4..len-5, i.e. excluding the 4-byte header
     and the 4-byte CRC) through a set of values, one per fuzz call. */
  size_t off = 4 + (m->step % (buf_size - 8));
  m->out[off] = (uint8_t)(0x40 + (m->step & 0x3f));
  ++m->step;

  *out_buf = m->out;
  return buf_size;

}

void afl_custom_deinit(void *data) {

  ck_mut_t *m = data;
  free(m->out);
  free(m);

}
