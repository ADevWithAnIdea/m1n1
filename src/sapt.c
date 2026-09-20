/* SPDX-License-Identifier: GPL-2.0-only */

#include "sapt.h"
#include "adt.h"
#include "string.h"
#include "types.h"
#include "utils.h"

#define SAPT_PAGES_PER_BYTE 4

void sapt_disable(void)
{
    if (!cpu_features->sapt)
        return;

    int node = adt_path_offset(adt, "/arm-io/sapt");
    u64 table_address;
    u64 entries;

    if (node < 0 ||
        ADT_GETPROP(adt, node, "table-address", &table_address) != sizeof(table_address) ||
        ADT_GETPROP(adt, node, "n-entries", &entries) != sizeof(entries)) {
        printf("SAPT: Configuration not found\n");
        return;
    }

    u64 expected_entries = mem_size_actual / SZ_16K;
    if (entries != expected_entries) {
        printf("SAPT: Invalid entry count 0x%lx (expected 0x%lx)\n", entries, expected_entries);
        return;
    }

    size_t table_size = (entries + SAPT_PAGES_PER_BYTE - 1) / SAPT_PAGES_PER_BYTE;
    printf("SAPT: Disabling protection at 0x%lx (0x%zx bytes)\n", table_address, table_size);
    memset((void *)table_address, 0, table_size);
    sysop("dsb sy");
}
