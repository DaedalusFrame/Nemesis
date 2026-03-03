#pragma once
#include "../includes/structs.hpp"
#include "../includes/includes.h"
#include "../includes/func_defs.hpp"

typedef struct {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} cpuidsplit_t;


typedef struct {
    void* table;
    bool large_page;
} slot_t;

typedef struct {
    va_64_t remapped_va;

    // Pml4 slot not needed as we only have 1 anyways
    slot_t pdpt_table;
    slot_t pd_table;
    void* pt_table;

    bool used;
} remapped_entry_t;

typedef enum {
    pdpt_table_valid, // Means that the pml4 at the correct index already points to a remapped pdpt table
    pde_table_valid,  // Means that the pdpt at the correct index already points to a remapped pde table
    pte_table_valid,  // Means that the pde at the correct index already points to a remapped pte table
    non_valid,        // Means that the pml4 indexes didn't match
} usable_until_t;

#define PAGE_TABLE_ENTRY_COUNT 512
typedef struct {
    alignas(0x1000) pml4e_64 pml4_table[PAGE_TABLE_ENTRY_COUNT]; // Basically only is a windows copy; We replace one entry and point it to our paging structure
    alignas(0x1000) pdpte_64 pdpt_table[PAGE_TABLE_ENTRY_COUNT];
    alignas(0x1000) pde_2mb_64 pd_2mb_table[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT];
} page_tables_t;

#define REMAPPING_TABLE_COUNT 100
#define MAX_REMAPPINGS 250 
typedef struct {
    union {
        pdpte_64* pdpt_table[REMAPPING_TABLE_COUNT];
        pdpte_1gb_64* pdpt_1gb_table[REMAPPING_TABLE_COUNT];
    };
    union {
        pde_64* pd_table[REMAPPING_TABLE_COUNT];
        pde_2mb_64* pd_2mb_table[REMAPPING_TABLE_COUNT];
    };

    pte_64* pt_table[REMAPPING_TABLE_COUNT];

    bool is_pdpt_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pd_table_occupied[REMAPPING_TABLE_COUNT];
    bool is_pt_table_occupied[REMAPPING_TABLE_COUNT];

    remapped_entry_t remapping_list[MAX_REMAPPINGS];
} remapping_tables_t;

typedef struct {
    // These page tables make up our cr3
    page_tables_t* page_tables;

    // These page tables are sole entries we use to
    // remap addresses in our cr3
    remapping_tables_t remapping_tables;

    cr3 kernel_cr3;

    cr3 constructed_cr3;
    uint64_t mapped_physical_mem_base; // Is the base where we mapped the first 512 gb of physical memory 

    bool initialized;
} physmem_t;