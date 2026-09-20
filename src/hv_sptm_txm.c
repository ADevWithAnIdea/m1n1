/* SPDX-License-Identifier: GPL-2.0-only */

#include "hv_sptm_internal.h"

bool sptm_handle_txm(struct exc_info *ctx, u32 endpoint)
{
    const u64 success = 0;
    const u64 generic = 1;
    const u64 not_found = 8;
    const u64 not_permitted = 38;
    const u64 not_supported = 41;
    u64 code = success;
    u64 words[SPTM_TXM_MAX_WORDS] = {0};
    size_t word_count = 0;

    switch (endpoint) {
        case 0:
            code = generic;
            break;
        case 1:
            word_count = 3;
            break;
        case 2:
            if (!sptm.txm_info_va)
                return false;
            words[0] = sptm.txm_info_va;
            words[1] = sptm.txm_info_va + 0x318;
            words[5] = sptm.txm_info_va;
            word_count = 6;
            break;
        case 3:
            word_count = 4;
            break;
        case 4:
        case 15:
        case 27:
        case 32:
        case 43:
            word_count = 1;
            break;
        case 7:
        case 11:
        case 17:
        case 22:
        case 24:
        case 34:
        case 38:
        case 41:
            code = not_supported;
            break;
        case 12:
        case 35:
            words[0] = 1;
            word_count = 1;
            break;
        case 14:
        case 16:
        case 30:
        case 44:
            code = not_found;
            break;
        case 19:
        case 23:
        case 25:
            word_count = 2;
            break;
        case 5:
        case 6:
        case 8:
        case 9:
        case 10:
        case 13:
        case 18:
        case 20:
        case 21:
        case 26:
        case 28:
        case 29:
        case 31:
        case 33:
        case 36:
        case 37:
        case 39:
        case 40:
        case 42:
        case 45:
            break;
        case 46:
        case 47:
        case 48:
        case 49:
        case 50:
        case 51:
            code = not_permitted;
            break;
        default:
            code = not_supported;
            break;
    }

    if (ctx->regs[0] > UINT64_MAX - SPTM_TXM_RECORD_OFFSET)
        return false;
    u64 record = sptm_pointer_pa(ctx->regs[0] + SPTM_TXM_RECORD_OFFSET, SPTM_TXM_RECORD_SIZE);
    if (!record)
        return false;

    memset((void *)record, 0, SPTM_TXM_RECORD_SIZE);
    write64(record + 0x08, code);
    write64(record + 0x18, word_count);
    for (size_t index = 0; index < word_count; index++)
        write64(record + 0x20 + index * sizeof(u64), words[index]);
    dc_civac_range((void *)record, SPTM_TXM_RECORD_SIZE);
    sysop("dsb sy");
    ctx->regs[0] = SPTM_STATUS_SUCCESS;
    return true;
}

void hv_sptm_configure_txm(u64 info_va)
{
    if (!sptm.enabled || !sptm_pointer_pa(info_va, SPTM_PAGE_SIZE)) {
        printf("HV: refusing invalid SPTM TXM configuration 0x%lx\n", info_va);
        return;
    }

    sptm.txm_info_va = info_va;
}
