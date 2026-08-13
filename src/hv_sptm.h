/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef HV_SPTM_H
#define HV_SPTM_H

#include "exception.h"
#include "types.h"

u64 hv_sptm_init(u64 guest_adt, u64 cons_ops, u64 page_shift_const, u64 xnu_text);
void hv_sptm_configure(u64 managed_start, u64 managed_end, u64 physmap_base, u64 scratch_pa,
                       u64 kernel_root, u64 cpu_info);
void hv_sptm_configure_frames(u64 frame_table_pa);
void hv_sptm_configure_uat(u64 shared_l2_pa, u64 shared_l2_size, u64 info, u64 global_state,
                           u64 gpu_contexts, u64 shared_l2_va);
void hv_sptm_configure_uat_handoff(u64 handoff_pa, u64 handoff_size);
void hv_sptm_configure_txm(u64 info_va);
void hv_sptm_configure_sart(u64 base, u64 canary, u64 info);
void hv_sptm_configure_nvme(u64 config);
void hv_sptm_configure_dart(u64 info, u64 config, u64 instance0, u64 instance1, u64 instance2,
                            u64 instance3);
bool hv_sptm_handle_hvc(struct exc_info *ctx, u32 immediate);
void sptm_boot_prepare_start(void **entry, u64 regs[4], bool secondary);
bool hv_handle_clpc_hvc(struct exc_info *ctx, u32 immediate);

#endif
