#pragma once
#include "includes.h"
#include "structs.hpp"

/*
	Assembly
*/

// ------------------------------------------------------------
// General Purpose Register Manipulation
// ------------------------------------------------------------
extern "C" uint64_t __read_rsp(void);
extern "C" uint64_t __read_r15(void);

// ------------------------------------------------------------
// Segment Register Reading/Manipulation
// ------------------------------------------------------------
extern "C" segment_selector __read_tr(void);
extern "C" segment_selector __read_cs(void);
extern "C" segment_selector __read_ss(void);
extern "C" segment_selector __read_ds(void);
extern "C" segment_selector __read_es(void);
extern "C" segment_selector __read_fs(void);
extern "C" segment_selector __read_gs(void);

extern "C" void __write_tr(uint16_t selector);
extern "C" void __write_cs(uint16_t selector);
extern "C" void __write_ss(uint16_t selector);
extern "C" void __write_ds(uint16_t selector);
extern "C" void __write_es(uint16_t selector);
extern "C" void __write_fs(uint16_t selector);
extern "C" void __write_gs(uint16_t selector);

// ------------------------------------------------------------
// CLI/STI Operations
// ------------------------------------------------------------
extern "C" void _cli(void);
extern "C" void _sti(void);

// ------------------------------------------------------------
// GDT Operations (SGDT, LGDT)
// ------------------------------------------------------------
extern "C" void _sgdt(void* gdtr);
extern "C" void _lgdt(void* gdtr);

// ------------------------------------------------------------
// Special Fault Operations
// ------------------------------------------------------------
extern "C" void __cause_ss(void);

// ------------------------------------------------------------
// Utility Functions
// ------------------------------------------------------------
extern "C" uint32_t get_proc_number(void);
extern "C" void asm_switch_cpl(uint64_t new_cpl);

// ------------------------------------------------------------
// SIDT Operations (Fault Handling and Locking)
// ------------------------------------------------------------
extern "C" void __lock_sidt(void* idtr_storage);
extern "C" void __ss_fault_sidt(void);
extern "C" void __gp_fault_sidt(void);

// ------------------------------------------------------------
// LIDT Operations (Fault Handling and Locking)
// ------------------------------------------------------------
extern "C" void __lock_lidt(void* idtr_storage);
extern "C" void __ss_fault_lidt(void);
extern "C" void __gp_fault_lidt(void);


// ------------------------------------------------------------
// IDT HANDLERS
// ------------------------------------------------------------
extern "C" void asm_de_handler();
extern "C" void asm_db_handler();
extern "C" void asm_nmi_handler();
extern "C" void asm_bp_handler();
extern "C" void asm_of_handler();
extern "C" void asm_br_handler();
extern "C" void asm_ud_handler();
extern "C" void asm_nm_handler();
extern "C" void asm_df_handler();
extern "C" void asm_ts_handler();
extern "C" void asm_np_handler();
extern "C" void asm_ss_handler();
extern "C" void asm_gp_handler();
extern "C" void asm_pf_handler();
extern "C" void asm_mf_handler();
extern "C" void asm_ac_handler();
extern "C" void asm_mc_handler();
extern "C" void asm_xm_handler();
extern "C" void asm_ve_handler();
extern "C" void asm_cp_handler();
extern "C" void seh_handler_ecode(idt_regs_ecode_t* regs);

// ------------------------------------------------------------
// CPL CHANGING / EXECUTION MODE CHANGING
// ------------------------------------------------------------
extern "C" void asm_syscall_handler(void);
extern "C" void asm_switch_segments(uint16_t cs, uint16_t ss);
extern "C" void asm_switch_to_cpl_0(void);
extern "C" void asm_execute_compatibility_mode_code(void);

/*
	High level detections
*/

namespace win {
	uint64_t win_get_virtual_address(uint64_t physical_address);

	uint64_t win_get_physical_address(void* virtual_address);
};

namespace idt {
	void execute_idt_detections(void);
};

namespace gdt {
	void execute_gdt_detections(void);
};

namespace tr {
	void execute_tr_detections(void);
};

namespace safety_net {
	bool init_safety_net(uint64_t image_base, uint64_t image_size);
	void free_safety_net(void);

	/*
		Note: Have to be called from cpl = 0
	*/
	void set_safety_net_kpcr(KPCR* kpcr);
	bool is_safety_net_active();
	bool start_safety_net(safety_net_t& info_storage);
	void stop_safety_net(safety_net_t& info_storage);

	namespace gdt {
		void log_constructed_gdt_descriptors(void);
	};

	namespace idt {
		idt_regs_ecode_t* get_core_last_interrupt_record(void);
		idt_regs_ecode_t* get_interrupt_record(uint32_t interrupt_idx);
		uint64_t get_interrupt_count(void);
		void log_all_interrupts();
		void reset_interrupt_count(void);

		segment_descriptor_register_64 get_constructed_idtr(void);
	};

	namespace cpl {
		/*
			Done via sysret;
			In here we need to ensure that we write to all necessary MSR's
			so that we can later restore shit
		*/
		bool switch_to_cpl_3(void);

		/*
			Done via syscall;
			In here we need to ensure that we restore all polluted MSR's
		*/
		bool switch_to_cpl_0(void);
	};

	namespace execution_mode {
		bool handle_mode_switch(idt_regs_ecode_t* record);

		uint32_t get_compatibility_data_page_address(void);
		void* get_compatibility_data_page(void);

		bool execute_32_bit_shellcode(void* shellcode, uint64_t shellcode_size);
	};
};