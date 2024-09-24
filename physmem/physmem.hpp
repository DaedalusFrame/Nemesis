#include "../structs.hpp"
#include "../includes.h"
#include "../func_defs.hpp"

#include "physmem_structs.hpp"
#include "page_table_helpers.hpp"

namespace physmem {
	// Initialization functions
	bool init_physmem(void);
	bool is_initialized(void);

	namespace util {
		cr3 get_constructed_cr3(void);
		cr3 get_system_cr3(void);
	};

	namespace runtime {
		bool translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t* remaining_bytes = 0);

		void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size);
		bool copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3);
		bool copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3);
		bool copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3);
	};

	namespace remapping {
		bool ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64);
		bool overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64);
	};
	
	namespace paging_manipulation {
		bool win_destroy_memory_page_mapping(void* memory, uint64_t& stored_flags);
		bool win_restore_memory_page_mapping(void* memory, uint64_t stored_flags);
		bool win_set_memory_range_supervisor(void* memory, uint64_t size, uint64_t mem_cr3, bool supervisor);
		bool is_memory_page_mapped(void* memory);
		bool prepare_driver_for_supervisor_access(void* driver_base, uint64_t driver_size, uint64_t mem_cr3);
	};

};