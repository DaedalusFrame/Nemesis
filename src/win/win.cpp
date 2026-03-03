#include "../includes/includes.h"
#include "../includes/func_defs.hpp"

namespace win {
    uint64_t win_get_virtual_address(uint64_t physical_address) {
        PHYSICAL_ADDRESS phys_addr = { 0 };
        phys_addr.QuadPart = physical_address;

        return (uint64_t)(MmGetVirtualForPhysical(phys_addr));
    }

    uint64_t win_get_physical_address(void* virtual_address) {
        return MmGetPhysicalAddress(virtual_address).QuadPart;
    }
};