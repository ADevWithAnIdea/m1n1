/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

#include "mcc.h"

struct sptm_state sptm;

bool sptm_valid_pa(u64 pa, size_t size)
{
    return pa >= sptm.managed_start && pa < sptm.managed_end && size <= sptm.managed_end - pa;
}

bool sptm_valid_platform_pa(u64 pa, size_t size)
{
    if (!size || pa < ram_base || pa >= ram_base + mem_size_actual ||
        size > ram_base + mem_size_actual - pa)
        return false;

    u64 end = pa + size;
    for (size_t index = 0; index < mcc_carveout_count; index++) {
        u64 carveout_start = mcc_carveouts[index].base;
        u64 carveout_end = carveout_start + mcc_carveouts[index].size;
        if (pa < carveout_end && carveout_start < end)
            return false;
    }

    return true;
}

u64 sptm_pointer_pa(u64 pointer, size_t size)
{
    u64 pa;

    if (pointer >= sptm.managed_start && pointer < sptm.managed_end) {
        pa = pointer;
    } else if (pointer >= sptm.physmap_base && pointer < sptm.physmap_end) {
        pa = sptm.managed_start + pointer - sptm.physmap_base;
    } else {
        return 0;
    }

    return sptm_valid_pa(pa, size) ? pa : 0;
}

u64 sptm_iommu_table_va(u64 pa)
{
    return pa | REGION_NORMAL_NC;
}

struct sptm_cpu *sptm_find_cpu(u32 phys_id)
{
    for (size_t index = 0; index < ARRAY_SIZE(sptm.cpus); index++) {
        struct sptm_cpu *cpu = &sptm.cpus[index];
        if (cpu->valid && cpu->phys_id == phys_id)
            return cpu;
    }

    return NULL;
}

struct sptm_cpu *sptm_register_cpu(u32 phys_id)
{
    struct sptm_cpu *cpu = sptm_find_cpu(phys_id);
    if (cpu)
        return cpu;

    if (sptm.cpu_count >= sptm.max_cpus)
        return NULL;

    cpu = &sptm.cpus[sptm.cpu_count];
    cpu->phys_id = phys_id;
    cpu->logical_id = sptm.cpu_count;
    cpu->valid = true;
    sptm.cpu_count++;
    return cpu;
}

u64 sptm_scratch_pa(struct exc_info *ctx)
{
    struct sptm_cpu *cpu = sptm_find_cpu(sptm.hv_phys_ids[ctx->cpu_id]);
    return cpu ? sptm.scratch_pa + cpu->logical_id * SPTM_PAGE_SIZE : 0;
}

void hv_sptm_configure(u64 managed_start, u64 managed_end, u64 physmap_base, u64 scratch_pa,
                       u64 kernel_root, u64 cpu_info)
{
    u32 cpu_count;

    memset(&sptm, 0, sizeof(sptm));
    spin_init(&sptm.service_lock);
    spin_init(&sptm.frame_lock);

    if ((managed_start & SPTM_PAGE_MASK) || managed_end <= managed_start ||
        (managed_end & SPTM_PAGE_MASK) || (scratch_pa & SPTM_PAGE_MASK) ||
        kernel_root < managed_start || kernel_root >= managed_end ||
        SPTM_PAGE_SIZE > managed_end - kernel_root || (cpu_info & 3) || cpu_info < managed_start ||
        cpu_info >= managed_end || sizeof(u32) > managed_end - cpu_info ||
        scratch_pa < managed_start || scratch_pa >= managed_end) {
        printf("HV: refusing invalid SPTM fast-path configuration\n");
        return;
    }

    cpu_count = read32(cpu_info);
    if (!cpu_count || cpu_count > MAX_CPUS ||
        (cpu_count + 1) * sizeof(u32) > managed_end - cpu_info ||
        cpu_count * SPTM_PAGE_SIZE > managed_end - scratch_pa) {
        printf("HV: refusing invalid SPTM CPU-map configuration\n");
        return;
    }

    sptm.managed_start = managed_start;
    sptm.managed_end = managed_end;
    sptm.physmap_base = physmap_base;
    sptm.physmap_end = physmap_base + managed_end - managed_start;
    sptm.scratch_pa = scratch_pa;
    sptm.kernel_root = kernel_root;
    sptm.sprr_perm[0] = 0x2010002030100000;
    sptm.sprr_perm[1] = 0x2020a506f020f0e0;
    sptm.max_cpus = cpu_count;
    for (size_t index = 0; index < cpu_count; index++)
        sptm.hv_phys_ids[index] = read32(cpu_info + (index + 1) * sizeof(u32));
    sptm.enabled = true;
}
