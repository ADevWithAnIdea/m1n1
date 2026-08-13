/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef HV_SPTM_INTERNAL_H
#define HV_SPTM_INTERNAL_H

#include "string.h"

#include "hv.h"
#include "hv_sptm.h"
#include "memory.h"
#include "smp.h"
#include "utils.h"

#define SPTM_PAGE_SHIFT      14
#define SPTM_PAGE_SIZE       BIT(SPTM_PAGE_SHIFT)
#define SPTM_PAGE_MASK       (SPTM_PAGE_SIZE - 1)
#define SPTM_CACHE_LINE_SIZE 64

#define SPTM_DESC_PA_MASK_16K 0x0000ffffffffc000ULL

#define SPTM_STATUS_SUCCESS            0
#define SPTM_STATUS_MAP_VALID          1
#define SPTM_STATUS_MAP_PADDR_CONFLICT 6
#define SPTM_STATUS_TABLE_NOT_PRESENT  7
#define SPTM_STATUS_TABLE_PRESENT      8

#define SPTM_MAX_SCRATCH_ENTRIES (SPTM_PAGE_SIZE / sizeof(u64))
#define SPTM_SERIAL_LINE_SIZE    512
#define SPTM_MAX_DARTS           32
#define SPTM_MAX_DART_INSTANCES  4
#define SPTM_MAX_DART_SIDS       256
#define SPTM_MAX_DART_PAGES      65536
#define SPTM_MAX_DART_DAPF       256
#define SPTM_MAX_DART_CLOCKS     32
#define SPTM_MAX_DART_TUNABLES   256
#define SPTM_MAX_DART_CLOCK_REFS 64
#define SPTM_MAX_SURT_ROOTS      128

#define SPTM_TXM_RECORD_OFFSET 0x3c00
#define SPTM_TXM_RECORD_SIZE   0x58
#define SPTM_TXM_MAX_WORDS     7

#define SPTM_SART_ENTRIES    16
#define SPTM_SART_PAGE_SHIFT 12
#define SPTM_SART_PAGE_SIZE  BIT(SPTM_SART_PAGE_SHIFT)

#define SPTM_NVME_CONFIG_WORDS      17
#define SPTM_NVME_TCB_SIZE          0x80
#define SPTM_NVME_TCB_ALIGNMENT     0x1000
#define SPTM_NVME_PRP_PAGE_SHIFT    12
#define SPTM_NVME_PRP_PAGE_SIZE     BIT(SPTM_NVME_PRP_PAGE_SHIFT)
#define SPTM_NVME_PRP_PAGE_MASK     (SPTM_NVME_PRP_PAGE_SIZE - 1)
#define SPTM_NVME_PRP_SLOT_SIZE     0x800
#define SPTM_NVME_MAX_PRPS          0x101
#define SPTM_NVME_COMMAND_SIZE      32
#define SPTM_NVME_FLAG_PRP_FLUSH_WA BIT(0)
#define SPTM_NVME_FLAG_TL_WA        BIT(1)
#define SPTM_NVME_FLAG_VDMA_WA      BIT(2)
#define SPTM_NVME_FLAG_SHA_PRESENT  BIT(3)

#define NVMMU_QUEUE_COUNT    0x100
#define NVMMU_ADMIN_TCB_BASE 0x108
#define NVMMU_IO_TCB_BASE    0x110
#define NVMMU_TCB_INVALIDATE 0x118
#define NVMMU_TCB_STATUS     0x1120

#define NVME_AQA             0x24
#define NVME_ASQ             0x28
#define NVME_ACQ             0x30
#define NVME_IOSQ            0x1200
#define NVME_IOCQ            0x1208
#define NVME_IOQA            0x1210
#define DART_PARAMS_4        0x004
#define DART_PARAMS_8        0x008
#define DART_PARAMS_C        0x00c
#define DART_TLB_OP          0x080
#define DART_TLB_START_DVA   0x098
#define DART_TLB_END_DVA     0x0a0
#define DART_ERROR           0x100
#define DART_REG_PROTECT     0x200
#define DART_TLIMIT          0x228
#define DART_TEQRESERVE      0x22c
#define DART_SID_EXCEPTIONS  0x4000
#define DART_ENABLE_STREAMS  0xc00
#define DART_DISABLE_STREAMS 0xc20
#define DART_TCR             0x1000
#define DART_TTBR            0x1400
#define DART_UNAVAILABLE     0xabad1dea

#define DART_TLB_BUSY           BIT(31)
#define DART_TLB_HARDWARE_FLUSH BIT(30)
#define DART_TLB_FLUSH_SID      BIT(8)
#define DART_TLB_FLUSH_DVA      BIT(14)
#define DART_TLB_FLUSH_ALL      0
#define DART_TCR_TRANSLATE      BIT(0)
#define DART_TTBR_VALID         BIT(0)
#define DART_ERROR_SECONDARY    BIT(19)

#define FPAG_CLOCK_PROTECTION BIT(4)

#define SPTM_DART_CLOCK_FLAGS 3

#define DART_PTE_VALID       BIT(0)
#define DART_PTE_UNCACHABLE  BIT(1)
#define DART_PTE_WRPROT      BIT(2)
#define DART_PTE_RDPROT      BIT(3)
#define DART_PTE_OFFSET_MASK (BIT(28) - 1)

#define UAT_STATE_ROOT0             0x08
#define UAT_STATE_ROOT1             0x10
#define UAT_STATE_CONTEXT_ID        0x18
#define UAT_STATE_GUARD             0x1a
#define UAT_STATE_CURSOR0           0x20
#define UAT_STATE_CURSOR1           0x28
#define UAT_STATE_CURSOR2           0x30
#define UAT_STATE_CURSOR3           0x38
#define UAT_STATE_OPTIONS           0x40
#define UAT_STATE_FLUSH_LEVEL       0x44
#define UAT_STATE_MAP_SEGMENTS      0x48
#define UAT_STATE_UNMAP_FLUSH_COUNT 0x248
#define UAT_STATE_UNMAP_SEGMENTS    0x250

#define UAT_STATE_SINGLE_ROOT  1
#define UAT_STATE_GLOBAL_MODE0 2
#define UAT_STATE_DUAL_ROOT    4
#define UAT_STATE_GLOBAL_MODE1 8

#define UAT_GUARD_UNINITIALIZED 0
#define UAT_GUARD_BUSY          1
#define UAT_GUARD_IDLE          2
#define UAT_GUARD_MAP           3
#define UAT_GUARD_PREPARE_UNMAP 4
#define UAT_GUARD_UNMAP         5

#define UAT_UNMAP_PHASE_VALIDATE 0
#define UAT_UNMAP_PHASE_CLEAR    1
#define UAT_UNMAP_PHASE_RELEASE  2

#define UAT_DESC_TABLE          3
#define UAT_DESC_VALID          BIT(0)
#define UAT_DESC_FIRMWARE_OWNED BIT(3)
#define UAT_DESC_AP_SHIFT       6
#define UAT_DESC_ATTR_SHIFT     2
#define UAT_DESC_AF             BIT(10)
#define UAT_DESC_NG             BIT(11)
#define UAT_DESC_PXN            BIT(53)
#define UAT_DESC_UXN            BIT(54)
#define UAT_DESC_OS             BIT(55)

#define UAT_MAP_OPTIONS_MASK (0xfULL | (3ULL << 8) | (0xfULL << 16))

#define UAT_HANDOFF_MAGIC       0x4b1d000000000002ULL
#define UAT_HANDOFF_MAGIC_AP    0x000
#define UAT_HANDOFF_MAGIC_FW    0x008
#define UAT_HANDOFF_LOCK_AP     0x010
#define UAT_HANDOFF_LOCK_FW     0x011
#define UAT_HANDOFF_TURN        0x014
#define UAT_HANDOFF_CURRENT_CTX 0x018
#define UAT_HANDOFF_SLOT_BASE   0x020
#define UAT_HANDOFF_SLOT_STRIDE 0x018
#define UAT_HANDOFF_SLOT_STATE  0x000
#define UAT_HANDOFF_SLOT_ADDR   0x008
#define UAT_HANDOFF_SLOT_SIZE   0x010
#define UAT_HANDOFF_SLOT_COUNT  0x041
#define UAT_HANDOFF_SHARED_SLOT 0x040
#define UAT_HANDOFF_UNK3        0x640
#define UAT_HANDOFF_MIN_SIZE    0x648
#define UAT_HANDOFF_UNMAP_TAG   0xdead000000000000ULL
#define UAT_HANDOFF_ADDR_MASK   0x0000ffffffffffffULL

#define SPTM_DART_SID_KNOWN   BIT(0)
#define SPTM_DART_SID_ENABLED BIT(1)
#define SPTM_DART_SID_POLICY  BIT(2)
#define SPTM_DART_SID_EXCLAVE BIT(3)

#define SPTM_DART_FLUSH_BY_DVA     BIT(0)
#define SPTM_DART_AVOID_MAP_TLBI   BIT(1)
#define SPTM_DART_RELAXED_RW       BIT(2)
#define SPTM_DART_RETENTION        BIT(3)
#define SPTM_DART_ALLOW_PTE_REMAP  BIT(4)
#define SPTM_DART_CLAMP_TLIMITS    BIT(5)
#define SPTM_DART_IGNORE_SECONDARY BIT(6)
#define SPTM_DART_UNGANG_SHARED_PS BIT(7)

#define SPTM_FRAME_KERNEL_ROOT             8
#define SPTM_FRAME_PAGE_TABLE              9
#define SPTM_FRAME_USER_ROOT               18
#define SPTM_FRAME_SHARED_ROOT             19
#define SPTM_FRAME_XNU_ROOT                20
#define SPTM_FRAME_SHARED_PT               21
#define SPTM_FRAME_ROZONE_PT               22
#define SPTM_FRAME_COMMPAGE_PT             23
#define SPTM_FRAME_STAGE2_ROOT             33
#define SPTM_FRAME_STAGE2_PT               34
#define SPTM_FRAME_KERNEL_RESTRICTED       35
#define SPTM_FRAME_SUBPAGE                 40
#define SPTM_FRAME_DEFAULT                 11
#define SPTM_FRAME_XNU_IOMMU               24
#define SPTM_FRAME_XNU_IO                  26
#define SPTM_FRAME_PROTECTED_IO            27
#define SPTM_FRAME_COPROCESSOR_RO_IO       28
#define SPTM_FRAME_RESTRICTED_IO           38
#define SPTM_FRAME_RESTRICTED_IO_TELEMETRY 39
#define SPTM_FRAME_SK_IO                   65
#define SPTM_FRAME_TXM_SECURE_CHANNEL      61

struct sptm_cpu {
    u32 phys_id;
    u8 logical_id;
    bool valid;
};

struct sptm_geometry {
    u64 descriptor_mask;
    u16 entries_mask;
    u8 page_shift;
    u8 start_level;
    u8 page_ratio;
};

struct sptm_dart {
    u32 id;
    u16 sid_count;
    u16 sid_words;
    u8 instance_count;
    bool valid;
    u64 sid_states;
    u64 dapf_entries;
    u64 clock_entries;
    u64 tunable_entries;
    u16 dapf_count;
    u8 clock_count;
    u16 tunable_count;
    u32 flags;
    u64 instances[SPTM_MAX_DART_INSTANCES];
    u32 boot_streams[(SPTM_MAX_DART_SIDS + 31) / 32];
    u32 saved_streams[SPTM_MAX_DART_INSTANCES][(SPTM_MAX_DART_SIDS + 31) / 32];
    u32 active_streams[SPTM_MAX_DART_INSTANCES][(SPTM_MAX_DART_SIDS + 31) / 32];
    u32 saved_counters[SPTM_MAX_DART_INSTANCES][9];
    u32 saved_tlimit[SPTM_MAX_DART_INSTANCES];
    u32 saved_teqreserve[SPTM_MAX_DART_INSTANCES];
    u8 version_major;
    u8 version_minor;
    u8 counter_count;
    u16 interrupt_status_offset;
    bool hardware_flush_supported;
    bool saved_valid;
    bool limits_valid;
    bool initialized;
    bool powered;
    bool clock_active;
};

struct sptm_dart_sid {
    u64 root;
    u64 pt_start;
    u64 pt_end;
    u64 dva_base;
    u64 dva_size;
    u32 tcr;
    u8 root_level;
    u8 flags;
    u16 reserved;
};

struct sptm_dart_config {
    u64 sid_states;
    u64 dapf_entries;
    u64 clock_entries;
    u64 tunable_entries;
    u32 dapf_count;
    u32 clock_count;
    u32 tunable_count;
    u32 flags;
};

struct sptm_dart_dapf {
    u64 base;
    u64 start;
    u64 end;
    u32 r4;
    u32 control;
    u32 r20;
    u32 reserved;
};

struct sptm_dart_tunable {
    u64 base;
    u32 offset;
    u32 size;
    u64 mask;
    u64 value;
};

struct sptm_dart_clock_ref {
    u64 address;
    u16 refs;
    bool original;
    bool valid;
};

struct sptm_uat_segment {
    u64 first;
    u64 count;
};

static_assert(sizeof(struct sptm_uat_segment) == 16, "unexpected UAT segment size");

#define SPTM_UAT_BATCH_PAGES 256

static_assert(sizeof(struct sptm_dart_sid) == 48, "unexpected DART SID-state size");
static_assert(sizeof(struct sptm_dart_config) == 48, "unexpected DART configuration size");
static_assert(sizeof(struct sptm_dart_dapf) == 40, "unexpected DART DAPF-entry size");
static_assert(sizeof(struct sptm_dart_tunable) == 32, "unexpected DART tunable-entry size");

struct sptm_surt_root {
    u64 root;
    u16 asid;
    u8 attr_index;
    bool valid;
};

struct sptm_nvme_command {
    u64 prp_aux;
    u64 drained_slots;
    u16 count;
    u8 qid;
    u8 dma_flags;
    u8 state;
    u8 reserved[3];
    u64 first;
};

static_assert(sizeof(struct sptm_nvme_command) == SPTM_NVME_COMMAND_SIZE,
              "unexpected NVMe command-state size");
static_assert((SPTM_NVME_MAX_PRPS - 1) * sizeof(u64) <= SPTM_NVME_PRP_SLOT_SIZE,
              "NVMe PRP list exceeds its per-CID slot");

struct sptm_nvme {
    bool configured;
    bool coastguard_enabled;
    bool prp_flush_wa;
    bool tl_wa;
    bool vdma_wa;
    bool sha_present;
    u8 protocol;
    u8 tl_slots;
    u32 queue_entries;
    u64 queue_bar;
    u64 nvmmu;
    u64 trusted_start;
    u64 trusted_end;
    u64 xnu_managed_start;
    u64 xnu_managed_end;
    u64 admin_tcbs;
    u64 io_tcbs;
    u64 prp_scratch;
    u64 command_state;
    u64 tl_mask;
    u64 tl_control;
    u64 tl_status;
    u64 vdma_status;
    u64 sha_base;
    bool admin_queues_valid;
    bool io_sizes_valid;
    bool io_sq_valid;
    bool io_cq_valid;
    bool sha_valid;
    u64 admin_queues[4];
    u64 io_sizes[2];
    u64 io_sq;
    u64 io_cq;
    u64 sha[3];
};

struct sptm_state {
    bool enabled;
    size_t host_rt_restore_count;
    u64 host_rt_restore_pages[SPTM_MAX_SCRATCH_ENTRIES];
    u64 managed_start;
    u64 managed_end;
    u64 physmap_base;
    u64 physmap_end;
    u64 scratch_pa;
    u64 kernel_root;
    u64 frame_table_pa;
    u64 external_ref_table_pa;
    u64 uat_global_state;
    u64 uat_gpu_contexts;
    u64 uat_shared_l2_pa;
    size_t uat_shared_l2_size;
    u64 uat_shared_l2_va;
    u64 uat_handoff_pa;
    bool uat_handoff_pending[UAT_HANDOFF_SLOT_COUNT];
    u64 uat_handoff_owner[UAT_HANDOFF_SLOT_COUNT];
    u32 uat_segment_limit;
    u32 uat_mapping_limit;
    u32 uat_state_size;
    u8 uat_va_width;
    u8 uat_mode;
    bool uat_tlbi_at_retype;
    bool uat_configured;
    u64 txm_info_va;
    u64 sart_base;
    u64 sart_canary;
    u16 sart_protected_mask;
    u16 sart_guarded_mask;
    u16 sart_guard_count;
    bool sart_exclusive_bounds;
    bool sart_configured;
    spinlock_t service_lock;
    spinlock_t frame_lock;
    struct sptm_cpu cpus[MAX_CPUS];
    u32 hv_phys_ids[MAX_CPUS];
    u8 cpu_count;
    u64 sprr_perm[2];
    u32 sprr_umprr;
    u8 max_cpus;
    struct sptm_dart darts[SPTM_MAX_DARTS];
    size_t dart_count;
    struct sptm_dart_clock_ref dart_clock_refs[SPTM_MAX_DART_CLOCK_REFS];
    struct sptm_surt_root surt_roots[SPTM_MAX_SURT_ROOTS];
    struct sptm_nvme nvme;
};

extern struct sptm_state sptm;

/* Core */
bool sptm_valid_pa(u64 pa, size_t size);
bool sptm_valid_platform_pa(u64 pa, size_t size);
u64 sptm_pointer_pa(u64 pointer, size_t size);
u64 sptm_iommu_table_va(u64 pa);
struct sptm_cpu *sptm_find_cpu(u32 phys_id);
struct sptm_cpu *sptm_register_cpu(u32 phys_id);
u64 sptm_scratch_pa(struct exc_info *ctx);

/* DART */
struct sptm_dart *sptm_find_dart(u32 id);
bool sptm_dart_flush_all(struct sptm_dart *dart);
struct sptm_dart_sid *sptm_dart_sid(const struct sptm_dart *dart, u32 sid);
bool sptm_dart_valid_table(const struct sptm_dart_sid *state, u64 pa, size_t size);
void sptm_init_platform(u64 guest_adt, u64 aux_start, u64 aux_end);
u64 sptm_boot_init(u64 guest_adt, u64 cons_ops, u64 page_shift_const, u64 xnu_text);
bool sptm_dart_power(struct exc_info *ctx, bool power_up);
bool sptm_dart_init(struct exc_info *ctx);
bool sptm_dart_error_endpoint(struct exc_info *ctx);
u64 sptm_dart_clock_address(u64 entry);
bool sptm_handle_dart(struct exc_info *ctx, u32 endpoint);

/* Frame ownership */
bool sptm_is_table_type(u8 type);
bool sptm_is_root_type(u8 type);
u8 *sptm_frame_entry(u64 pa);
u32 *sptm_external_ref_entry(u64 pa);
bool sptm_adjust_data_ref(u64 pa, bool writable, int delta);
bool sptm_data_range_can_release(u64 pa, u64 size, bool writable);
bool sptm_adjust_data_range(u64 pa, u64 size, bool writable, int delta);
bool sptm_adjust_iommu_use(u64 pa, int delta);
bool sptm_adjust_table_valid(u64 slot, int delta);
bool sptm_adjust_parent_links(u64 child, int delta);
bool sptm_adjust_mapping_ref(u64 pte, u64 descriptor_mask, int delta);

/* UAT */
void sptm_uat_tlbi_all(void);
bool sptm_handle_uat(struct exc_info *ctx, u32 endpoint);

/* Stage-1 pmap */
struct sptm_surt_root *sptm_find_surt_root(u64 root);
u64 sptm_walk(u64 root, u64 va, unsigned int target_level, struct sptm_geometry *geometry_out);
void sptm_publish_stage1(void);
bool sptm_retype_frame(struct exc_info *ctx);
bool sptm_configure_shared_region(struct exc_info *ctx);
bool sptm_map_page(struct exc_info *ctx);
bool sptm_map_table(struct exc_info *ctx);
bool sptm_unmap_table(struct exc_info *ctx);
bool sptm_update_region(struct exc_info *ctx);
bool sptm_update_disjoint(struct exc_info *ctx);
bool sptm_update_disjoint_multipage(struct exc_info *ctx);
bool sptm_unmap_region(struct exc_info *ctx);
bool sptm_unmap_disjoint(struct exc_info *ctx);
bool sptm_nest_region(struct exc_info *ctx, bool nest);
bool sptm_surt_update(struct exc_info *ctx, bool allocate);
bool sptm_condemn_leaf_table(struct exc_info *ctx, bool condemn);

/* Service dispatch */
bool sptm_handle_xnu_bootstrap(struct exc_info *ctx, u32 endpoint);
bool sptm_handle_txm(struct exc_info *ctx, u32 endpoint);
bool sptm_handle_sart(struct exc_info *ctx, u32 endpoint);
bool sptm_handle_nvme(struct exc_info *ctx, u32 endpoint);

#endif
