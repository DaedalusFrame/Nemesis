#include "includes.h"
#include "func_defs.hpp"
#include "physmem/physmem.hpp"

namespace idt {
    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> SIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing (TO DO!)
        detection_6 -> Non canonical address passed as memory operand
        detection_7 -> Non canonical address passed as memory operand in SS segment -> #SS
    */
    namespace storing {
        bool detection_1(void) {
            bool hypervisor_detected = false;

            // Lock prefix should cause an exception
            segment_descriptor_register_64 idtr;
            __try {
                __lock_sidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_2(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #PF and not #GP as 0xdead is canonical (;
                __sidt((void*)0xdead); // If there actually is a va 0xdead then you honestly deserve that dub
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_3(void) {
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;
            void* allocated_page = MmAllocateContiguousMemory(0x1000, max_addr);
            if (!allocated_page)
                return false;

            memset(allocated_page, 0, 0x1000);

            volatile segment_descriptor_register_64* idtr_in_tlb = (volatile segment_descriptor_register_64*)allocated_page;
            // Put the part of the memory page we will use into the tlb
            // so that the cpu will be able to access it when executing sidt
            for (uint32_t i = 0; i < sizeof(segment_descriptor_register_64); i++) {
                volatile uint8_t dummy = *(uint8_t*)((uint64_t)allocated_page + i);
                UNREFERENCED_PARAMETER(dummy);
            }

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_page, stored_flags)) {
                return false;
            }

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_page)) {
                return false;
            }

            // The instruction should go through as the idtr page is still in the tlb (but not mapped in cr3!)
            bool hypervisor_detected = false;
            __try {
                __sidt((void*)idtr_in_tlb);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true; // Should not happen on bare metal
            }

            if (!physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_page, stored_flags)) {
                return hypervisor_detected;
            }

            return hypervisor_detected;
        }

        bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __sidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;

                // Account for hypervisors over adjusting the tsc
                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        bool detection_5(void) {
            // Compatibility mode IDTR storing (TO DO)

            return false;
        }

        bool detection_6(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #GP as we pass a non canonical address
                __gp_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_7(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause an exception
            __try {
                // This will cause #SS as we pass a non canonical address and we do so in rsp (-> stack segment)
                __ss_fault_sidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }
            if (hypervisor_detected) {
                return true;
            }

            return false;
        }

        bool detection_8(void) {
            cr4 curr_cr4;
            cr4 new_cr4;

            curr_cr4.flags = __readcr4();
            new_cr4.flags = curr_cr4.flags;

            new_cr4.smap_enable = 0;
            new_cr4.smep_enable = 0;
            __writecr4(new_cr4.flags);

            if (!safety_net::cpl::switch_to_cpl_3()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            if (!safety_net::cpl::switch_to_cpl_0()) {
                __writecr4(curr_cr4.flags);
                return false;
            }

            __writecr4(curr_cr4.flags);

            return false;
        }

        bool execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return false;

            if (detection_1()) {
                log_error_indent(2, "Failed detection 1");
            }
            else {
                log_success_indent(2, "Passed detection 1");
            }


            if (detection_2()) {
                log_error_indent(2, "Failed detection 2");
            }
            else {
                log_success_indent(2, "Passed detection 2");
            }


            if (detection_3()) {
                log_error_indent(2, "Failed detection 3");
            }
            else {
                log_success_indent(2, "Passed detection 3");
            }


            if (detection_4()) {
                log_error_indent(2, "Failed detection 4");
            }
            else {
                log_success_indent(2, "Passed detection 4");
            }


            if (detection_5()) {
                log_error_indent(2, "Failed detection 5");
            }
            else {
                log_success_indent(2, "Passed detection 5");
            }


            if (detection_6()) {
                log_error_indent(2, "Failed detection 6");
            }
            else {
                log_success_indent(2, "Passed detection 6");
            }


            if (detection_7()) {
                log_error_indent(2, "Failed detection 7");
            }
            else {
                log_success_indent(2, "Passed detection 7");
            }


            if (detection_8()) {
                log_error_indent(2, "Failed detection 8");
            }
            else {
                log_success_indent(2, "Passed detection 8");
            }

            safety_net::stop_safety_net(storage);

            return false;
        }
    };

    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> LIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing (TO DO!)
        detection_6 -> Non canonical address passed as memory operand
        detection_7 -> Non canonical address passed as memory operand in SS segment -> #SS
    */
    namespace loading {

        bool detection_1(void) {
            bool hypervisor_detected = false;

            // Lock prefix should cause an exception
            segment_descriptor_register_64 idtr;
            __try {
                __lock_lidt(&idtr);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != invalid_opcode)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_2(void) {
            bool hypervisor_detected = false;

            // Invalid operand should cause a page fault
            __try {
                // This should cause #PF since 0xdead is canonical but not mapped
                __lidt((void*)0xdead);
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != page_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_3(void) {
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;
            void* allocated_page = MmAllocateContiguousMemory(0x1000, max_addr);
            if (!allocated_page)
                return false;

            memset(allocated_page, 0, 0x1000);

            segment_descriptor_register_64 idtr;
            __sidt(&idtr);

            // This memcpy also maps the va into the tlb
            memcpy(allocated_page, &idtr, sizeof(idtr));

            uint64_t stored_flags;
            if (!physmem::paging_manipulation::win_destroy_memory_page_mapping(allocated_page, stored_flags)) {
                return false;
            }

            if (physmem::paging_manipulation::is_memory_page_mapped(allocated_page)) {
                return false;
            }

            // The instruction should go through as the idtr page is still in the tlb (but not mapped in cr3!)
            bool hypervisor_detected = false;
            __try {
                __lidt(allocated_page);
            }

            __except (EXCEPTION_EXECUTE_HANDLER) {
                hypervisor_detected = true;  // Should not happen on bare metal
            }

            physmem::paging_manipulation::win_restore_memory_page_mapping(allocated_page, stored_flags);
            return hypervisor_detected;
        }

        bool detection_4(void) {
            uint64_t lowest_tsc = MAXULONG64;
            segment_descriptor_register_64 idtr;

            // Copy the current idtr into idtr to ensure we load valid idtrs via lidt during timing
            __sidt(&idtr);

            for (int i = 0; i < 10; i++) {

                _mm_lfence();
                uint64_t start = __rdtsc();
                _mm_lfence();

                __lidt(&idtr);

                _mm_lfence();
                uint64_t end = __rdtsc();
                _mm_lfence();

                uint64_t delta = (end - start);
                if (delta < lowest_tsc)
                    lowest_tsc = delta;

                if (delta & (1ull << 63)) {
                    return true;
                }
            }

            return lowest_tsc > MAX_ACCEPTABLE_TSC;
        }

        bool detection_5(void) {
            // Compatibility mode IDTR storing (TO DO)
            return false;
        }

        bool detection_6(void) {
            bool hypervisor_detected = false;

            // Non-canonical address should cause a general protection fault
            __try {
                __gp_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != general_protection)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool detection_7(void) {
            bool hypervisor_detected = false;

            // Non-canonical address in SS segment should cause a stack segment fault
            __try {
                __ss_fault_lidt();
                hypervisor_detected = true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                if (safety_net::idt::get_core_last_interrupt_record()->exception_vector != stack_segment_fault)
                    hypervisor_detected = true;
            }

            return hypervisor_detected;
        }

        bool execute_detections(void) {
            safety_net_t storage;
            if (!safety_net::start_safety_net(storage))
                return false;

            if (detection_1()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 1");
                return true;
            }
            log_success_indent(2, "Passed detection 1");

            if (detection_2()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 2");
                return true;
            }
            log_success_indent(2, "Passed detection 2");

            if (detection_3()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 3");
                return true;
            }
            log_success_indent(2, "Passed detection 3");

            if (detection_4()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 4");
                return true;
            }
            log_success_indent(2, "Passed detection 4");

            if (detection_5()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 5");
                return true;
            }
            log_success_indent(2, "Passed detection 5");

            if (detection_6()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 6");
                return true;
            }
            log_success_indent(2, "Passed detection 6");

            if (detection_7()) {
                safety_net::stop_safety_net(storage);
                log_error_indent(2, "Failed detection 7");
                return true;
            }
            log_success_indent(2, "Passed detection 7");
            safety_net::stop_safety_net(storage);

            return false;
        }
    };

    void execute_idt_detections(void) {
        //log_new_line();
        //log_info_indent(1, "SIDT");
        //storing::execute_detections();
        //log_new_line();

        log_info_indent(1, "LIDT");
        loading::execute_detections();
        log_new_line();
    }
};