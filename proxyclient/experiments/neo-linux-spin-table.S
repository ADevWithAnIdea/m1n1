/* SPDX-License-Identifier: MIT
 * Test transport only. All five guest secondaries park before Linux starts.
 * x0 = this CPU's LE64 release word; x1 = readiness word on its own cache line.
 * Linux's standard spin-table backend writes secondary_holding_pen and SEVs.
 */
.balign 64
secondary_park:
    mov x4, x0
    mov x5, x1
    mov x6, #1
    str x6, [x5]
    dsb sy
    sevl
1:  wfe
    ldar x6, [x4]
    cbz x6, 1b
    dsb sy
    mov x0, #0
    mov x1, #0
    mov x2, #0
    mov x3, #0
    br x6
