/* SPDX-License-Identifier: MIT */

#ifndef PMU_H
#define PMU_H

/* Clear the PMU's count of unclean boots. Returns 0 if it was cleared. */
int pmu_reset_panic_counter(void);

#endif
