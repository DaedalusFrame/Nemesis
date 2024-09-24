#include "includes.h"
#include "func_defs.hpp"
#include "structs.hpp"
#include "physmem/physmem.hpp"

#include <ntimage.h>

namespace safety_net {
	bool inited = false;

	uint64_t g_image_base;
	uint64_t g_image_size;

	namespace gdt {
		// Compile time variables
		constexpr segment_selector zero_descriptor_selector = { 0, 0, 0 };

		constexpr segment_selector constructed_cpl0_cs = { 0, 0, 1 };
		constexpr segment_selector constructed_cpl0_ss = { 0, 0, 2 };
		
		constexpr segment_selector constructed_cpl3_ss = { 3, 0, 3 };
		constexpr segment_selector constructed_cpl3_cs = { 3, 0, 4 };

		constexpr segment_selector constructed_tr = { 0, 0, 5 }; // Takes up 2 slots

		constexpr uint16_t constructed_gdt_size = 7;

		// Runtime data
		bool gdt_inited = false;

		void* universal_stack = 0;
		void* interrupt_stack = 0;
		task_state_segment_64* my_tss = 0;
		segment_descriptor_32* my_gdt = 0;
		segment_descriptor_register_64 my_gdtr = { 0 };

		/*
			Utility / Exposed API's
		*/

		segment_descriptor_register_64 get_constructed_gdtr(void) {
			return my_gdtr;
		}

		void log_segment_descriptor_64(segment_descriptor_64* descriptor, const char* segment_name) {
			// Calculate the full base address
			uint64_t base_address = ((uint64_t)descriptor->base_address_upper << 32) |
				(descriptor->base_address_high << 24) |
				(descriptor->base_address_middle << 16) |
				descriptor->base_address_low;

			// Calculate the full segment limit
			uint32_t segment_limit = (descriptor->segment_limit_high << 16) |
				descriptor->segment_limit_low;

			// Check granularity flag to determine the effective segment limit
			if (descriptor->granularity) {
				segment_limit = (segment_limit << 12) | 0xFFF; // Granularity set, multiply by 4 KB
			}

			// Log information about the segment descriptor
			log_info("Segment Descriptor (%s):", segment_name);
			log_info("  Base Address: 0x%016llX", base_address);
			log_info("  Segment Limit: 0x%X", segment_limit);
			log_info("  Type: 0x%X", descriptor->type);
			log_info("  Descriptor Type (S flag): 0x%X", descriptor->descriptor_type);
			log_info("  DPL (Descriptor Privilege Level): 0x%X", descriptor->descriptor_privilege_level);
			log_info("  Present (P flag): 0x%X", descriptor->present);
			log_info("  Granularity (G flag): 0x%X", descriptor->granularity);
			log_info("  Default/Big (D flag): 0x%X", descriptor->default_big);
			log_info("  Long Mode (L flag): 0x%X", descriptor->long_mode);
			log_info("  System: 0x%X", descriptor->system);
			log_info("  System: 0x%X", descriptor->descriptor_type == 0 ? 1 : 0); // System flag is derived from the S flag
		}

		void log_segment_descriptor_32(segment_descriptor_32* descriptor, const char* segment_name) {
			// Calculate full base address
			uint32_t base_address = (descriptor->base_address_high << 24) |
				(descriptor->base_address_middle << 16) |
				descriptor->base_address_low;

			// Calculate full segment limit
			uint32_t segment_limit = (descriptor->segment_limit_high << 16) |
				descriptor->segment_limit_low;

			// Check granularity flag to determine the effective segment limit
			if (descriptor->granularity) {
				segment_limit = (segment_limit << 12) | 0xFFF; // Granularity set, multiply by 4 KB
			}

			log_info("Segment Descriptor (%s):", segment_name);
			log_info("  Base Address: 0x%08X", base_address);
			log_info("  Segment Limit: 0x%X", segment_limit);
			log_info("  Type: 0x%X", descriptor->type);
			log_info("  Descriptor Type (S flag): 0x%X", descriptor->descriptor_type);
			log_info("  DPL (Descriptor Privilege Level): 0x%X", descriptor->descriptor_privilege_level);
			log_info("  Present (P flag): 0x%X", descriptor->present);
			log_info("  Granularity (G flag): 0x%X", descriptor->granularity);
			log_info("  Default/Big (D/B flag): 0x%X", descriptor->default_big);
			log_info("  Long Mode (L flag): 0x%X", descriptor->long_mode);
			log_info("  System: 0x%X", descriptor->system);
		}

		void log_segment_selector(segment_selector* selector, const char* selector_name) {
			// Extract values from the segment selector fields
			uint16_t rpl = selector->request_privilege_level; // Requested Privilege Level (RPL)
			uint16_t table = selector->table;                 // Table Indicator (0 = GDT, 1 = LDT)
			uint16_t index = selector->index;                 // Descriptor index

			// Determine if the selector points to the GDT or LDT
			const char* table_name = (table == 0) ? "GDT" : "LDT";

			// Print out the segment selector details
			log_info("[%s] Segment Selector Details:", selector_name);
			log_info("  Request Privilege Level (RPL): %u", rpl);
			log_info("  Table Indicator (TI): %s (%u)", table_name, table);
			log_info("  Index: %u", index);
			log_info("  Raw Flags: 0x%04X", selector->flags); // Optional: print the raw flags for debugging
		}

		void log_constructed_gdt_descriptors(void) {
			log_info("CONSTRUCTED");

			// Log Kernel Mode Code Segment (KM CS)
			log_segment_descriptor_32(&my_gdt[constructed_cpl0_cs.index], "Kernel Mode Code Segment (KM CS)");

			// Log Kernel Mode Stack Segment (KM SS)
			log_segment_descriptor_32(&my_gdt[constructed_cpl0_ss.index], "Kernel Mode Stack Segment (KM SS)");

			// Log User Mode Code Segment (UM CS)
			log_segment_descriptor_32(&my_gdt[constructed_cpl3_cs.index], "User Mode Code Segment (UM CS)");

			// Log User Mode Stack Segment (UM SS)
			log_segment_descriptor_32(&my_gdt[constructed_cpl3_ss.index], "User Mode Stack Segment (UM SS)");

			// Log Task Register (TR)
			segment_descriptor_64* tss_descriptor = (segment_descriptor_64*)&my_gdt[constructed_tr.index];
			log_segment_descriptor_64(tss_descriptor, "Task Register (TR)");


			log_info("WINDOWS");

			segment_descriptor_register_64 win_gdtr;
			_sgdt(&win_gdtr);
			segment_descriptor_32* win_gdt = (segment_descriptor_32*)win_gdtr.base_address;
			uint64_t win_star = __readmsr(IA32_STAR);
			segment_selector win_um_cs;
			segment_selector win_um_ss;
			win_um_cs.flags = (uint16_t)(((win_star >> 48) + 16) | 3);
			win_um_ss.flags = (uint16_t)(((win_star >> 48) + 8) | 3);

			// Log User Mode Code Segment (UM CS)
			log_segment_descriptor_32(&win_gdt[win_um_cs.index], "User Mode Code Segment (UM CS)");

			// Log User Mode Stack Segment (UM SS)
			log_segment_descriptor_32(&win_gdt[win_um_ss.index], "User Mode Stack Segment (UM SS)");
			
		}

		/*
			Note: We only need 1 gdt as we lock execution
				  to one core via disabling of interrupts and no others execute whilst it is
		*/
		bool init_gdt(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			my_gdt = (segment_descriptor_32*)MmAllocateContiguousMemory(max(sizeof(segment_descriptor_32) * constructed_gdt_size, 0x1000), max_addr);
			if (!my_gdt)
				return false;
			memset(my_gdt, 0, max(sizeof(segment_descriptor_32) * constructed_gdt_size, 0x1000));

			my_tss = (task_state_segment_64*)MmAllocateContiguousMemory(0x1000, max_addr);
			if (!my_tss)
				return false;
			memset(my_tss, 0, 0x1000);

			universal_stack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
			if (!universal_stack)
				return false;
			memset(universal_stack, 0, KERNEL_STACK_SIZE);

			interrupt_stack = MmAllocateContiguousMemory(KERNEL_STACK_SIZE, max_addr);
			if (!interrupt_stack)
				return false;
			memset(interrupt_stack, 0, KERNEL_STACK_SIZE);

			my_tss->rsp0 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->rsp1 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->rsp2 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;

			my_tss->ist1 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist2 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist3 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist4 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist5 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist6 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;
			my_tss->ist7 = (uint64_t)universal_stack + KERNEL_STACK_SIZE;

			uint64_t tss_base = reinterpret_cast<uint64_t>(my_tss);

			// Null descriptor
			segment_descriptor_32* zero_descriptor = &my_gdt[zero_descriptor_selector.index];
			memset(zero_descriptor, 0, sizeof(segment_descriptor_32));

			// Kernel Code Segment
			segment_descriptor_32* cpl_0_cs_descriptor = &my_gdt[constructed_cpl0_cs.index];
			memset(cpl_0_cs_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_0_cs_descriptor->present = 1;
			cpl_0_cs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
			cpl_0_cs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_0_cs_descriptor->descriptor_privilege_level = 0;
			cpl_0_cs_descriptor->long_mode = 1;


			// Kernel Data Segment
			segment_descriptor_32* cpl_0_ss_descriptor = &my_gdt[constructed_cpl0_ss.index];
			memset(cpl_0_ss_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_0_ss_descriptor->present = 1;
			cpl_0_ss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			cpl_0_ss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_0_ss_descriptor->descriptor_privilege_level = 0;
			cpl_0_ss_descriptor->default_big = 1;


			// User Code Segment
			segment_descriptor_32* cpl_3_cs_descriptor = &my_gdt[constructed_cpl3_cs.index];
			memset(cpl_3_cs_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_3_cs_descriptor->present = 1;
			cpl_3_cs_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_CODE_EXECUTE_READ_ACCESSED;
			cpl_3_cs_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_3_cs_descriptor->descriptor_privilege_level = 3;
			cpl_3_cs_descriptor->long_mode = 1;

			// User Data Segment
			segment_descriptor_32* cpl_3_ss_descriptor = &my_gdt[constructed_cpl3_ss.index];
			memset(cpl_3_ss_descriptor, 0, sizeof(segment_descriptor_32));
			cpl_3_ss_descriptor->present = 1;
			cpl_3_ss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_DATA_READ_WRITE_ACCESSED;
			cpl_3_ss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_CODE_OR_DATA;
			cpl_3_ss_descriptor->descriptor_privilege_level = 3;
			cpl_3_ss_descriptor->granularity = 1;
			cpl_3_ss_descriptor->default_big = 1;
			cpl_3_ss_descriptor->segment_limit_low = 0xFFFF; // Lower 16 bits of the segment limit.
			cpl_3_ss_descriptor->segment_limit_high = 0xF;   // Upper 4 bits of the segment limit.

			// Task State Segment
			segment_descriptor_64* tss_descriptor = reinterpret_cast<segment_descriptor_64*>(&my_gdt[constructed_tr.index]);
			memset(tss_descriptor, 0, sizeof(segment_descriptor_64));

			tss_descriptor->present = 1;
			tss_descriptor->type = SEGMENT_DESCRIPTOR_TYPE_TSS_BUSY;
			tss_descriptor->descriptor_type = SEGMENT_DESCRIPTOR_TYPE_SYSTEM;
			tss_descriptor->descriptor_privilege_level = 0;
			tss_descriptor->segment_limit_low = sizeof(task_state_segment_64) - 1;
			tss_descriptor->base_address_low = (tss_base >> 00) & 0xFFFF;
			tss_descriptor->base_address_middle = (tss_base >> 16) & 0xFF;
			tss_descriptor->base_address_high = (tss_base >> 24) & 0xFF;
			tss_descriptor->base_address_upper = (tss_base >> 32) & 0xFFFFFFFF;

			my_gdtr.base_address = (uint64_t)my_gdt;
			my_gdtr.limit = (constructed_gdt_size * sizeof(segment_descriptor_32));

			gdt_inited = true;

			return true;
		}
	};

	namespace idt {
		bool idt_inited = false;
		segment_descriptor_interrupt_gate_64* my_idt = 0;
		segment_descriptor_register_64 my_idtr = { 0 };

		uint64_t total_interrupts = 0;
		idt_regs_ecode_t* context_storage = 0;

		/*
			Utility / Exposed API's
		*/
		segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler) {
			segment_descriptor_interrupt_gate_64 gate = { 0 };

			gate.interrupt_stack_table = 0; // Doesn't really matter which one we point it to as all point to the same; Just has to be non 0
			gate.segment_selector = gdt::constructed_cpl0_cs.flags;
			gate.must_be_zero_0 = 0;
			gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE;
			gate.must_be_zero_1 = 0;
			gate.descriptor_privilege_level = 3; // Is the minimum cpl required to use the gate
			gate.present = 1;
			gate.reserved = 0;

			uint64_t offset = (uint64_t)assembly_handler;
			gate.offset_low = (offset >> 0) & 0xFFFF;
			gate.offset_middle = (offset >> 16) & 0xFFFF;
			gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

			return gate;
		}

		segment_descriptor_register_64 get_constructed_idtr(void) {
			return my_idtr;
		}

		void increase_interrupt_counter(void) {
			total_interrupts++;
		}

		uint64_t get_interrupt_count(void) {
			return idt::total_interrupts;
		}

		idt_regs_ecode_t* get_interrupt_record(uint32_t interrupt_idx) {
			if (!idt_inited || interrupt_idx >= 1000)
				return 0;

			return &context_storage[interrupt_idx];
		}

		idt_regs_ecode_t* get_core_last_interrupt_record(void) {
			if (!idt_inited || total_interrupts >= 1000 || !total_interrupts)
				return 0;

			return &context_storage[total_interrupts - 1];
		}

		void safe_interrupt_record(idt_regs_ecode_t* record) {
			if (!idt_inited || total_interrupts >= 1000)
				return;

			memcpy(&context_storage[total_interrupts], record, sizeof(idt_regs_ecode_t));
		}

		void log_all_interrupts() {
			uint64_t interrupt_count = get_interrupt_count();
			if (interrupt_count == 0) {
				log_info("No interrupts have occurred.");
				return;
			}

			log_info("Interrupt count: %p", interrupt_count);

			for (uint32_t i = 0; i < interrupt_count; ++i) {
				idt_regs_ecode_t* record = get_interrupt_record(i);
				if (!record) {
					log_error("Interrupt #%d has no valid record.", i);
					continue;
				}

				log_new_line();

				log_info("Interrupt #%d:", i);
				log_info_indent(1, "RAX: 0x%llx", record->rax);
				log_info_indent(1, "RBX: 0x%llx", record->rbx);
				log_info_indent(1, "RCX: 0x%llx", record->rcx);
				log_info_indent(1, "RDX: 0x%llx", record->rdx);
				log_info_indent(1, "RSI: 0x%llx", record->rsi);
				log_info_indent(1, "RDI: 0x%llx", record->rdi);
				log_info_indent(1, "RBP: 0x%llx", record->rbp);
				log_info_indent(1, "R8:  0x%llx", record->r8);
				log_info_indent(1, "R9:  0x%llx", record->r9);
				log_info_indent(1, "R10: 0x%llx", record->r10);
				log_info_indent(1, "R11: 0x%llx", record->r11);
				log_info_indent(1, "R12: 0x%llx", record->r12);
				log_info_indent(1, "R13: 0x%llx", record->r13);
				log_info_indent(1, "R14: 0x%llx", record->r14);
				log_info_indent(1, "R15: 0x%llx", record->r15);
				log_info_indent(1, "RIP: 0x%llx", record->rip);
				log_info_indent(1, "CS:  0x%llx", record->cs_selector);
				log_info_indent(1, "RFLAGS: 0x%llx", record->rflags.flags);
				log_info_indent(1, "RSP: 0x%llx", record->rsp);
				log_info_indent(1, "SS:  0x%llx", record->ss_selector);
				log_info_indent(1, "Exception Vector: 0x%llx", record->exception_vector);
				log_info_indent(1, "Error Code: 0x%llx", record->error_code);
			}
		}

		/*
			Core
		*/

		// Core exception handler
		extern "C" void exception_handler(idt_regs_ecode_t* record) {

			// Safe data about the interrupt for various purposes
			safe_interrupt_record(record);
			increase_interrupt_counter();

			// Just mock nmis 
			if (record->exception_vector == nmi) {
				return;
			}

			// stack_segment_fault faults require the real rsp in rax (;
			// Look into detect_asm.asm:__ss_fault_sidt for more details
			if (record->exception_vector == stack_segment_fault) {
				record->rsp = record->rax;
			}

			IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)g_image_base;
			IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)(g_image_base + dos_header->e_lfanew);
			IMAGE_DATA_DIRECTORY* exception = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			RUNTIME_FUNCTION* rt_functions = (RUNTIME_FUNCTION*)(g_image_base + exception->VirtualAddress);

			uint64_t rip_rva = record->rip - g_image_base;

			// Try to resolve the exception directly with rip
			for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx) {
				RUNTIME_FUNCTION* function = &rt_functions[idx];
				if (!(rip_rva >= function->BeginAddress && rip_rva < function->EndAddress))
					continue;

				UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
				if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
					continue;

				SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
				for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
					SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
					if (rip_rva >= scope_record->BeginAddress && rip_rva < scope_record->EndAddress) {

						record->rip = g_image_base + scope_record->JumpTarget;

						return;
					}
				}
			}

			// If we reached here this means that the exception couldn't get
			// resolved with rip, so we have to stack trace to find the __except
			// block (Just walk rsp chain by 8 bytes at a time)
			uint64_t* stack_ptr = (uint64_t*)record->rsp;
			while (stack_ptr) {
				uint64_t potential_caller_rip = *stack_ptr;
				uint64_t potential_caller_rva = potential_caller_rip - g_image_base;

				// Check whether the current stack address can even be a function in our driver
				if (potential_caller_rva > g_image_size) {
					stack_ptr++;
					continue;
				}

				// Check whether the potential_caller_rva corresponds to an __except block
				for (ULONG idx = 0; idx < exception->Size / sizeof(RUNTIME_FUNCTION); ++idx) {
					RUNTIME_FUNCTION* function = &rt_functions[idx];
					if (!(potential_caller_rva >= function->BeginAddress && potential_caller_rva < function->EndAddress))
						continue;

					UNWIND_INFO* unwind_info = (UNWIND_INFO*)(g_image_base + function->UnwindData);
					if (!(unwind_info->Flags & UNW_FLAG_EHANDLER))
						continue;

					SCOPE_TABLE* scope_table = (SCOPE_TABLE*)((uint64_t)(&unwind_info->UnwindCode[(unwind_info->CountOfCodes + 1) & ~1]) + sizeof(uint32_t));
					for (uint32_t entry = 0; entry < scope_table->Count; ++entry) {
						SCOPE_RECORD* scope_record = &scope_table->ScopeRecords[entry];
						if (potential_caller_rva >= scope_record->BeginAddress && potential_caller_rva < scope_record->EndAddress) {
							record->rip = g_image_base + scope_record->JumpTarget;
							record->rsp = (uint64_t)(stack_ptr + 1); // Point rsp to below the return address (*mostly* is the state of the stack of the caller function)

							return;
						}
					}
				}

				stack_ptr++;
			}
		}

		/*
			Initialization
		*/

		void create_idt(segment_descriptor_interrupt_gate_64* idt) {
			// Set IDT entries manually for each exception vector.
			idt[divide_error] = idt::create_interrupt_gate(asm_de_handler);
			idt[debug] = idt::create_interrupt_gate(asm_db_handler);
			idt[nmi] = idt::create_interrupt_gate(asm_nmi_handler);
			idt[breakpoint] = idt::create_interrupt_gate(asm_bp_handler);
			idt[overflow] = idt::create_interrupt_gate(asm_of_handler);
			idt[bound_range_exceeded] = idt::create_interrupt_gate(asm_br_handler);
			idt[invalid_opcode] = idt::create_interrupt_gate(asm_ud_handler);
			idt[device_not_available] = idt::create_interrupt_gate(asm_nm_handler);
			idt[double_fault] = idt::create_interrupt_gate(asm_df_handler);
			idt[invalid_tss] = idt::create_interrupt_gate(asm_ts_handler);
			idt[segment_not_present] = idt::create_interrupt_gate(asm_np_handler);
			idt[stack_segment_fault] = idt::create_interrupt_gate(asm_ss_handler);
			idt[general_protection] = idt::create_interrupt_gate(asm_gp_handler);
			idt[page_fault] = idt::create_interrupt_gate(asm_pf_handler);
			idt[x87_floating_point_error] = idt::create_interrupt_gate(asm_mf_handler);
			idt[alignment_check] = idt::create_interrupt_gate(asm_ac_handler);
			idt[machine_check] = idt::create_interrupt_gate(asm_mc_handler);
			idt[simd_floating_point_error] = idt::create_interrupt_gate(asm_xm_handler);
			idt[virtualization_exception] = idt::create_interrupt_gate(asm_ve_handler);
			idt[control_protection] = idt::create_interrupt_gate(asm_cp_handler);

			my_idtr.base_address = (uint64_t)idt;
			my_idtr.limit = MAXUINT16; // Since we allocate up to that size
		}

		bool init_idt(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;
			my_idt = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(MAXUINT16, max_addr);
			if (!my_idt)
				return false;
			memset(my_idt, 0, MAXUINT16);

			create_idt(my_idt);

			context_storage = (idt_regs_ecode_t*)MmAllocateContiguousMemory(1000 * sizeof(idt_regs_ecode_t), max_addr);
			if (!context_storage)
				return false;
			memset(context_storage, 0, 100 * sizeof(idt_regs_ecode_t));

			idt_inited = true;

			return true;
		}
	};

	namespace cpl {
		bool cpl_switching_inited = false;
		bool currently_in_cpl_3 = false;

		// Runtime data
		// IA32_STAR: Contains info about cs and ss for um and km
		// IA32_LSTAR: Contains where rip will be set to after syscall
		// IA32_FMASK: Every bit set in this will be unset in rflags after a syscall
		uint64_t original_star = 0;
		uint64_t original_lstar = 0;
		uint64_t original_fmask = 0;

		uint64_t constructed_star = 0;
		uint64_t constructed_lstar = 0;
		uint64_t constructed_fmask = 0;

		/*
			Done via sysret;
			In here we need to ensure that we write to all necessary MSR's 
			so that we can later restore shit
		*/
		bool switch_to_cpl_3(void) {
			if (!is_safety_net_active())
				return false;

			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();
			if (curr_cr4.smap_enable || curr_cr4.smep_enable)
				return false;

			__writemsr(IA32_STAR, constructed_star);
			__writemsr(IA32_LSTAR, constructed_lstar);
			__writemsr(IA32_FMASK, constructed_fmask);

			__try {
				asm_switch_segments(gdt::constructed_cpl3_cs.flags, gdt::constructed_cpl3_ss.flags); // Note: From now on you can not execute all restricted instructions (e.g. wrmsr)
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// All is left to do here is to pray
				__writemsr(IA32_STAR, original_star);
				__writemsr(IA32_LSTAR, original_lstar);
				__writemsr(IA32_FMASK, original_fmask);
				return false; 
			}

			currently_in_cpl_3 = true;

			return true;
		}

		/*
			Done via syscall;
			In here we need to ensure that we restore all polluted MSR's
		*/
		bool switch_to_cpl_0(void) {

			/*
				We can't do shit here as we do not have access to privileged instrucitons (e.g. wrmsr)
			*/

			if (!currently_in_cpl_3) {	// Here for testing
				__writemsr(IA32_STAR, constructed_star);
				__writemsr(IA32_LSTAR, constructed_lstar);
				__writemsr(IA32_FMASK, constructed_fmask);
			}

			__try {
				asm_switch_to_cpl_0(); // Note: From now on you can execute all privileged instructions (e.g. wrmsr)
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				// All is left to do here is to pray
				currently_in_cpl_3 = false;
				__writemsr(IA32_STAR, original_star);
				__writemsr(IA32_LSTAR, original_lstar);
				__writemsr(IA32_FMASK, original_fmask);
				return false;
			}

			__writemsr(IA32_STAR, original_star);
			__writemsr(IA32_LSTAR, original_lstar);
			__writemsr(IA32_FMASK, original_fmask);

			currently_in_cpl_3 = false;

			return true;
		}

		bool init_cpl_switcher(void) {

			ia32_efer_register efer;
			efer.flags = __readmsr(IA32_EFER);
			if (!efer.syscall_enable || !efer.ia32e_mode_enable)
				return false;

			// Backup orig values
			original_star = __readmsr(IA32_STAR);
			original_lstar = __readmsr(IA32_LSTAR);
			original_fmask = __readmsr(IA32_FMASK);


			ia32_star_register star;
			star.flags = 0;
			star.kernel_cs_selector = gdt::constructed_cpl0_cs.flags;
			star.user_cs_selector = gdt::constructed_cpl3_cs.flags - 16; // Honestly fuck you to whoever wrote that +16 for sysret behaviour
			constructed_star = star.flags;

			constructed_lstar = (uint64_t)asm_syscall_handler;

			constructed_fmask = 0;
			
			cpl_switching_inited = true;

			return true;
		}
	};

	/*
		Exposed API's
	*/

	bool is_safety_net_active() {
		if (!inited) {
			return false;
		}

		// Check GDTR
		segment_descriptor_register_64 current_gdtr;
		_sgdt(&current_gdtr);
		if (current_gdtr.base_address != gdt::my_gdtr.base_address ||
			current_gdtr.limit != gdt::my_gdtr.limit) {
			return false;
		}

		// Check IDTR
		segment_descriptor_register_64 current_idtr;
		__sidt(&current_idtr);
		if (current_idtr.base_address != idt::my_idtr.base_address ||
			current_idtr.limit != idt::my_idtr.limit) {
			return false;
		}

		// Check segment selectors
		uint16_t current_ss = __read_ss().flags;
		uint16_t current_cs = __read_cs().flags;
		uint16_t current_tr = __read_tr().flags;

		if (current_ss != gdt::constructed_cpl0_ss.flags ||
			current_cs != gdt::constructed_cpl0_cs.flags ||
			current_tr != gdt::constructed_tr.flags) {
			return false;
		}

		// Check RFLAGS
		rflags flags;
		flags.flags = __readeflags();
		if (flags.interrupt_enable_flag)
			return false;

		return true;
	}

	bool init_safety_net(uint64_t image_base, uint64_t image_size) {
		if (!image_base || !image_size)
			return false;

		g_image_base = image_base;
		g_image_size = image_size;

		if (!gdt::init_gdt())
			return false;

		if (!idt::init_idt())
			return false;

		if (!cpl::init_cpl_switcher())
			return false;

		inited = true;

		return true;
	}

	void free_safety_net(void) {
		MmFreeContiguousMemory(idt::my_idt);
	}

	/*
		Note: Has to be called from cpl = 0
	*/
	bool start_safety_net(safety_net_t& info_storage) {
		if (!inited)
			return false;

		_cli();

		// Store the old gdtr
		_sgdt(&info_storage.safed_gdtr);

		// Load the new gdtr
		_lgdt(&gdt::my_gdtr);

		// Store the old selectors
		info_storage.safed_ss = __read_ss().flags;
		info_storage.safed_cs = __read_cs().flags;
		info_storage.safed_tr = __read_tr().flags;

		// Load all associated selectors
		__write_ss(gdt::constructed_cpl0_ss.flags);
		__write_cs(gdt::constructed_cpl0_cs.flags);

		// Mark tss as available and switch tr
		gdt::my_gdt[gdt::constructed_tr.index].type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
		__write_tr(gdt::constructed_tr.flags);

		// Store the old idtr
		__sidt(&info_storage.safed_idtr);

		// Load the new idtr
		__lidt(&idt::my_idtr);

		// Store the old cr3
		info_storage.safed_cr3 = __readcr3();

		// Load the new cr3
		__writecr3(physmem::util::get_constructed_cr3().flags);

		cr4 curr_cr4;
		curr_cr4.flags = __readcr4();
		info_storage.safed_cr4 = curr_cr4.flags;

		curr_cr4.smap_enable = 0;
		curr_cr4.smep_enable = 0;
		__writecr4(curr_cr4.flags);

		return true;
	}

	/*
		Note: Has to be called from cpl = 0
	*/
	void stop_safety_net(safety_net_t& info_storage) {
		_lgdt(&info_storage.safed_gdtr);

		__write_ss(info_storage.safed_ss);
		__write_cs(info_storage.safed_cs);

		// Mark tss as available and switch tr
		segment_descriptor_32* gdt = (segment_descriptor_32*)info_storage.safed_gdtr.base_address;
		segment_selector tr_selec;
		tr_selec.flags = info_storage.safed_tr;
		gdt[tr_selec.index].type = SEGMENT_DESCRIPTOR_TYPE_TSS_AVAILABLE;
		__write_tr(info_storage.safed_tr);

		__lidt(&info_storage.safed_idtr);

		__writecr3(info_storage.safed_cr3);

		__writecr4(info_storage.safed_cr4);

		_sti();
	}
}