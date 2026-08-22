/*
 * SPDX-License-Identifier: MIT
 *
 * Own-source helper/scratch probe for G17P.  The fixed output address keeps
 * this focused experiment independent of a compiler-specific argument ABI.
 */
#include "compiler/libcl/libcl.h"

#define G17P_SPILL_OUTPUT_DVA 0x10000108000UL
#define G17P_SPILL_WORDS 256

KERNEL(32)
g17p_mesa_spill_probe(void)
{
   volatile float values[G17P_SPILL_WORDS];
   uint gid = cl_global_id.x;

   for (uint i = 0; i < G17P_SPILL_WORDS; ++i)
      values[i] = convert_float(i + gid);

   /* Every odd step permutes all 256 entries, retaining one exact result. */
   uint step = (gid << 1) | 1;
   float sum = 0.0f;
   for (uint i = 0; i < G17P_SPILL_WORDS; ++i)
      sum += values[(i * step) & (G17P_SPILL_WORDS - 1)];

   global float *output =
      (global float *)(uintptr_t)G17P_SPILL_OUTPUT_DVA;
   output[gid] = sum;
}
