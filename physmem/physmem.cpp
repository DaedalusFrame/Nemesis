#include "physmem.hpp"

namespace physmem {
	/*
		Global variables
	*/
	physmem_t physmem;

	namespace support {
		bool is_physmem_supported(void) {
			// Add support checks that determine whether the systems
			// supports all our needs

			// Only AMD or INTEL processors are supported
			char vendor[13] = { 0 };
			cpuidsplit_t vendor_cpuid_data;
			__cpuid((int*)&vendor_cpuid_data, 0);
			((int*)vendor)[0] = vendor_cpuid_data.ebx;
			((int*)vendor)[1] = vendor_cpuid_data.edx;
			((int*)vendor)[2] = vendor_cpuid_data.ecx;
			if ((strncmp(vendor, "GenuineIntel", 12) != 0) &&
				(strncmp(vendor, "AuthenticAMD", 12) != 0)) {
				return false;
			}

			// Abort on 5 level paging
			cr4 curr_cr4;
			curr_cr4.flags = __readcr4();
			if (curr_cr4.linear_addresses_57_bit) {
				return false;
			}

			// Since we map 512 gb of physical memory to 2MB pages they should be supported -.-
			cpuid_eax_01 cpuid_1;
			__cpuid((int*)(&cpuid_1), 1);
			if (!cpuid_1.cpuid_feature_information_edx.physical_address_extension) {
				return false;
			}

			// SSE2 support should be enable as we use mfence etc
			if (!cpuid_1.cpuid_feature_information_edx.sse2_support) {
				return false;
			}

			// We need an apic on chip as we check for the apic id and use that as a cpu index
			if(!cpuid_1.cpuid_feature_information_edx.apic_on_chip) {
				return false;
			}

			return true;
		}
	};

	namespace page_table_initialization {
		void* allocate_zero_table(PHYSICAL_ADDRESS max_addr) {
			void* table = (void*)MmAllocateContiguousMemory(PAGE_SIZE, max_addr);

			if (table)
				memset(table, 0, PAGE_SIZE);

			return table;
		}

		bool allocate_page_tables(void) {
			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			physmem.page_tables = (page_tables_t*)MmAllocateContiguousMemory(sizeof(page_tables_t), max_addr);
			if(!physmem.page_tables) {
				return false;
			}


			memset(physmem.page_tables, 0, sizeof(page_tables_t));

			for (uint64_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
				physmem.remapping_tables.pdpt_table[i] = (pdpte_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pd_table[i] = (pde_64*)allocate_zero_table(max_addr);
				physmem.remapping_tables.pt_table[i] = (pte_64*)allocate_zero_table(max_addr);

				if (!physmem.remapping_tables.pdpt_table[i] || !physmem.remapping_tables.pd_table[i] || !physmem.remapping_tables.pt_table[i]) {
					return false;
				}

			}

			return true;
		}

		uint64_t get_cr3(uint64_t target_pid) {
			PEPROCESS sys_process = PsInitialSystemProcess;
			PEPROCESS curr_entry = sys_process;

			do {
				uint64_t curr_pid;

				memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + 0x440), sizeof(curr_pid));

				// Check whether we found our process
				if (target_pid == curr_pid) {

					uint32_t active_threads;

					memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + 0x5f0), sizeof(active_threads));

					if (active_threads || target_pid == 4) {
						uint64_t cr3;

						memcpy(&cr3, (void*)((uintptr_t)curr_entry + 0x28), sizeof(cr3));

						return cr3;
					}
				}

				PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+0x448);
				curr_entry = (PEPROCESS)((uintptr_t)list->Flink - 0x448);
			} while (curr_entry != sys_process);

			return 0;
		}

		bool copy_kernel_page_tables(void) {
			pml4e_64* kernel_pml4_page_table = 0;

			physmem.kernel_cr3.flags = get_cr3(4);
			if (!physmem.kernel_cr3.flags)
				return false;

			kernel_pml4_page_table = (pml4e_64*)win::win_get_virtual_address(physmem.kernel_cr3.address_of_page_directory << 12);
			if (!kernel_pml4_page_table)
				return false;

			memcpy(physmem.page_tables->pml4_table, kernel_pml4_page_table, sizeof(pml4e_64) * 512);

			physmem.constructed_cr3.flags = physmem.kernel_cr3.flags;
			physmem.constructed_cr3.address_of_page_directory = win::win_get_physical_address(physmem.page_tables->pml4_table) >> 12;
			if (!physmem.constructed_cr3.address_of_page_directory)
				return false;

			return true;
		}

		uint64_t calculate_physical_memory_base(uint64_t pml4e_idx) {
			// Shift the pml4 index right 36 bits to get the virtual address of the first byte of the 512 gb we mapped
			return (pml4e_idx << (9 + 9 + 9 + 12));
		}

		bool map_full_system_physical_memory(uint32_t free_pml4_idx) {
			page_tables_t* page_tables = physmem.page_tables;

			// TO DO:
			// Dynamically determine the range of physical memory this pc has

			// Map the first 512 gb of physical memory; If any user has more than 512 gb of memory just kill yourselfes ig?
			page_tables->pml4_table[free_pml4_idx].present = 1;
			page_tables->pml4_table[free_pml4_idx].write = 1;
			page_tables->pml4_table[free_pml4_idx].page_frame_number = win::win_get_physical_address(&page_tables->pdpt_table) >> 12;
			if (!page_tables->pml4_table[free_pml4_idx].page_frame_number)
				return false;

			for (uint64_t i = 0; i < PAGE_TABLE_ENTRY_COUNT; i++) {
				page_tables->pdpt_table[i].present = 1;
				page_tables->pdpt_table[i].write = 1;
				page_tables->pdpt_table[i].page_frame_number = win::win_get_physical_address(&page_tables->pd_2mb_table[i]) >> 12;
				if (!page_tables->pdpt_table[i].page_frame_number)
					return false;

				for (uint64_t j = 0; j < PAGE_TABLE_ENTRY_COUNT; j++) {
					page_tables->pd_2mb_table[i][j].present = 1;
					page_tables->pd_2mb_table[i][j].write = 1;
					page_tables->pd_2mb_table[i][j].large_page = 1;
					page_tables->pd_2mb_table[i][j].page_frame_number = (i << 9) + j;
				}
			}

			return true;
		}

		bool construct_my_page_tables(void) {
			page_tables_t* page_tables = physmem.page_tables;

			uint32_t free_pml4_idx = pt_helpers::find_free_pml4e_index(page_tables->pml4_table);
			if (!pt_helpers::is_index_valid(free_pml4_idx))
				return false;

			bool status = map_full_system_physical_memory(free_pml4_idx);
			if (status != true)
				return status;

			physmem.mapped_physical_mem_base = calculate_physical_memory_base(free_pml4_idx);
			if (!physmem.mapped_physical_mem_base)
				return false; // Can't happen basically

			return true;
		}

		bool initialize_page_tables(void) {
			bool status = page_table_initialization::allocate_page_tables();
			if (status != true)
				return status;

			status = page_table_initialization::copy_kernel_page_tables();
			if (status != true)
				return status;

			status = page_table_initialization::construct_my_page_tables();
			if (status != true)
				return status;

			return status;
		}
	}

	namespace util {
		cr3 get_constructed_cr3(void) {
			return physmem.constructed_cr3;
		}

		cr3 get_system_cr3(void) {
			return physmem.kernel_cr3;
		}
	};

	/*
		Exposed core runtime API's
	*/
	namespace runtime {
		bool translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t* remaining_bytes) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			cr3 target_cr3 = { 0 };
			va_64_t va = { 0 };

			target_cr3.flags = outside_target_cr3;
			va.flags = (uint64_t)virtual_address;

			bool status = true;
			pml4e_64* mapped_pml4_table = 0;
			pml4e_64* mapped_pml4_entry = 0;

			pdpte_64* mapped_pdpt_table = 0;
			pdpte_64* mapped_pdpt_entry = 0;

			pde_64* mapped_pde_table = 0;
			pde_64* mapped_pde_entry = 0;

			pte_64* mapped_pte_table = 0;
			pte_64* mapped_pte_entry = 0;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (target_cr3.address_of_page_directory << 12));
			mapped_pml4_entry = &mapped_pml4_table[va.pml4e_idx];
			if (!mapped_pml4_entry->present) {
				status = false;
				return status;
			}

			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_entry->page_frame_number << 12));
			mapped_pdpt_entry = &mapped_pdpt_table[va.pdpte_idx];
			if (!mapped_pdpt_entry->present) {
				status = false;
				return status;
			}

			if (mapped_pdpt_entry->large_page) {
				pdpte_1gb_64 mapped_pdpte_1gb_entry;
				mapped_pdpte_1gb_entry.flags = mapped_pdpt_entry->flags;

				physical_address = (mapped_pdpte_1gb_entry.page_frame_number << 30) + va.offset_1gb;
				if(remaining_bytes)
					*remaining_bytes = 0x40000000 - va.offset_1gb;
	
				return status;
			}


			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_entry->page_frame_number << 12));
			mapped_pde_entry = &mapped_pde_table[va.pde_idx];
			if (!mapped_pde_entry->present) {
				status = false;
				return status;
			}

			if (mapped_pde_entry->large_page) {
				pde_2mb_64 mapped_pde_2mb_entry;
				mapped_pde_2mb_entry.flags = mapped_pde_entry->flags;

				physical_address = (mapped_pde_2mb_entry.page_frame_number << 21) + va.offset_2mb;
				if (remaining_bytes)
					*remaining_bytes = 0x200000 - va.offset_2mb;

				return status;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_entry->page_frame_number << 12));
			mapped_pte_entry = &mapped_pte_table[va.pte_idx];
			if (!mapped_pte_entry->present) {
				status = false;
				return status;
			}

			physical_address = (mapped_pte_entry->page_frame_number << 12) + va.offset_4kb;
			if (remaining_bytes)
				*remaining_bytes = 0x1000 - va.offset_4kb;
	
			return status;
		}

		void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return;

			void* virtual_src = 0;
			void* virtual_dst = 0;

			virtual_src = (void*)(src_physical + physmem.mapped_physical_mem_base);
			virtual_dst = (void*)(dst_physical + physmem.mapped_physical_mem_base);

			memcpy(virtual_dst, virtual_src, size);
		}

		bool copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t current_physical_dst = 0;
			uint64_t src_remaining = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate both the src and dst into physical addresses
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != true)
					break;
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != true)
					break;

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);
				copyable_size = min(copyable_size, dst_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}

		bool copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_src = 0;
			uint64_t src_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate the src into a physical address
				status = translate_to_physical_address(src_cr3, (void*)((uint64_t)src + copied_bytes), current_physical_src, &src_remaining);
				if (status != true)
					break;

				current_virtual_src = (void*)(current_physical_src + physmem.mapped_physical_mem_base);
				current_virtual_dst = (void*)((uint64_t)dst + copied_bytes);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, src_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}

		bool copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			bool status = true;

			void* current_virtual_src = 0;
			void* current_virtual_dst = 0;
			uint64_t current_physical_dst = 0;
			uint64_t dst_remaining = 0;
			uint64_t copyable_size = 0;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				// Translate the dst into a physical address
				status = translate_to_physical_address(dst_cr3, (void*)((uint64_t)dst + copied_bytes), current_physical_dst, &dst_remaining);
				if (status != true)
					break;

				current_virtual_src = (void*)((uint64_t)src + copied_bytes);
				current_virtual_dst = (void*)(current_physical_dst + physmem.mapped_physical_mem_base);

				copyable_size = min(PAGE_SIZE, size - copied_bytes);
				copyable_size = min(copyable_size, dst_remaining);

				// Then copy the mem
				memcpy(current_virtual_dst, current_virtual_src, copyable_size);

				copied_bytes += copyable_size;
			}

			return status;
		}
	};

	/*
		The exposed API's in here are designed for initialization
	*/
	namespace remapping {
		bool get_remapping_entry(void* mem, remapped_entry_t*& remapping_entry) {
			va_64_t target_va = { 0 };
			remapped_entry_t dummy = { 0 };
			remapped_entry_t* curr_closest_entry = &dummy;

			target_va.flags = (uint64_t)mem;

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];

				// Sort out all the irrelevant ones
				if (!curr_entry->used)
					continue;

				// Check whether the pml4 index overlaps
				if (curr_entry->remapped_va.pml4e_idx != target_va.pml4e_idx)
					continue;

				// Check whether the pdpt index overlaps
				if (curr_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {

					// The curr closest entry is already as good as the entry at the current index
					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx)
						continue;

					// Set the curr entry as closest entry
					curr_closest_entry = curr_entry;
					continue;
				}

				// If it points to an entry marked as large page
				// we can return it immediately as there won't be
				// a more fitting entry than this one (paging hierachy
				// for that va range ends there
				if (curr_entry->pdpt_table.large_page) {
					curr_closest_entry = curr_entry;
					goto cleanup;
				}

				// Check whether the pde index overlaps
				if (curr_entry->remapped_va.pde_idx != target_va.pde_idx) {

					// The curr closest entry is already as good as the entry at the current index
					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
						curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx)
						continue;

					// Set the curr entry as closest entry
					curr_closest_entry = curr_entry;
					continue;
				}

				if (curr_entry->pd_table.large_page) {
					curr_closest_entry = curr_entry;
					goto cleanup;
				}

				// Check whether the pte index overlaps
				if (curr_entry->remapped_va.pte_idx != target_va.pte_idx) {

					// The curr closest entry is already as good as the entry at the current index
					if (curr_closest_entry->remapped_va.pml4e_idx == target_va.pml4e_idx &&
						curr_closest_entry->remapped_va.pdpte_idx == target_va.pdpte_idx &&
						curr_closest_entry->remapped_va.pde_idx == target_va.pde_idx)
						continue;

					// Set the curr entry as closest entry
					curr_closest_entry = curr_entry;
					continue;
				}

				// Everything overlapped, the address resides in the same pte table
				// as another one we mapped, we can reuse everything
				curr_closest_entry = curr_entry;
				goto cleanup;
			}

		cleanup:

			if (curr_closest_entry == &dummy) {
				return false;
			}
			else {
				remapping_entry = curr_closest_entry;
			}

			return true;
		}

		bool add_remapping_entry(remapped_entry_t new_entry) {

			for (uint32_t i = 0; i < MAX_REMAPPINGS; i++) {
				remapped_entry_t* curr_entry = &physmem.remapping_tables.remapping_list[i];

				// Check whether the current entry is present/occupied
				if (curr_entry->used)
					continue;

				memcpy(curr_entry, &new_entry, sizeof(remapped_entry_t));
				curr_entry->used = true;

				return true;
			}

			return false;
		}

		bool get_max_remapping_level(remapped_entry_t* remapping_entry, uint64_t target_address, usable_until_t& usable_level) {
			va_64_t target_va;
			target_va.flags = target_address;

			if (!remapping_entry || !target_address) {
				usable_level = non_valid;
				return false;
			}

			// Check whether the pml4 index overlaps
			if (remapping_entry->remapped_va.pml4e_idx != target_va.pml4e_idx) {
				usable_level = non_valid;
				return false;
			}

			// Check whether the pdpt index overlaps
			if (remapping_entry->remapped_va.pdpte_idx != target_va.pdpte_idx) {
				usable_level = pdpt_table_valid;
				return true;
			}

			if (remapping_entry->pdpt_table.large_page) {
				usable_level = pdpt_table_valid;
				return true;
			}

			// Check whether the pde index overlaps
			if (remapping_entry->remapped_va.pde_idx != target_va.pde_idx) {
				usable_level = pde_table_valid;
				return true;
			}

			if (remapping_entry->pd_table.large_page) {
				usable_level = pde_table_valid;
				return true;
			}

			usable_level = pte_table_valid;
			return true;
		}


		bool ensure_memory_mapping_without_previous_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64)
				return false;

			va_64_t mem_va = { 0 };
			cr3 mem_cr3 = { 0 };

			mem_va.flags = (uint64_t)mem;
			mem_cr3.flags = mem_cr3_u64;
			bool status = true;

			// Pointers to mapped system tables
			pml4e_64* mapped_pml4_table = 0;
			pdpte_64* mapped_pdpt_table = 0;
			pde_64* mapped_pde_table = 0;
			pte_64* mapped_pte_table = 0;

			// Pointers to my tables
			pml4e_64* my_pml4_table = 0;
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			// Physical addresses of my page tables
			uint64_t pdpt_phys = 0;
			uint64_t pd_phys = 0;
			uint64_t pt_phys = 0;

			// A new entry for remapping
			remapped_entry_t new_entry = { 0 };

			my_pml4_table = physmem.page_tables->pml4_table;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

			if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = false;
					goto cleanup;
				}

				pdpte_1gb_64* my_1gb_pdpt_table = (pdpte_1gb_64*)my_pdpt_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_1gb_pdpt_table, pdpt_phys) != true)
					goto cleanup;

				memcpy(my_1gb_pdpt_table, mapped_pdpt_table, sizeof(pdpte_1gb_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

				// Create a new remapping entry
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = true;
				new_entry.pdpt_table.table = my_pdpt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x40000000 - mem_va.offset_1gb;

				goto cleanup;
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
				if (!my_pdpt_table) {
					status = false;
					goto cleanup;
				}

				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = false;
					goto cleanup;
				}

				pde_2mb_64* my_2mb_pd_table = (pde_2mb_64*)my_pde_table;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys) != true)
					goto cleanup;

				if (runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys) != true)
					goto cleanup;


				memcpy(my_2mb_pd_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
				memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;
				my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

				// Create a new remapping entry
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = my_pdpt_table;

				new_entry.pd_table.large_page = true;
				new_entry.pd_table.table = my_pde_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x200000 - mem_va.offset_2mb;

				goto cleanup;
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			my_pdpt_table = pt_manager::get_free_pdpt_table(&physmem.remapping_tables);
			if (!my_pdpt_table) {
				status = false;
				goto cleanup;
			}

			my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
			if (!my_pde_table) {
				status = false;
				goto cleanup;
			}

			my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
			if (!my_pte_table) {
				status = false;
				goto cleanup;
			}

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pdpt_table, pdpt_phys);
			if (status != true)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
			if (status != true)
				goto cleanup;

			status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
			if (status != true)
				goto cleanup;

			memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
			memcpy(my_pde_table, mapped_pde_table, sizeof(pde_64) * 512);
			memcpy(my_pdpt_table, mapped_pdpt_table, sizeof(pdpte_64) * 512);
			memcpy(&my_pml4_table[mem_va.pml4e_idx], &mapped_pml4_table[mem_va.pml4e_idx], sizeof(pml4e_64));

			my_pde_table[mem_va.pde_idx].present = 1;
			my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;

			my_pdpt_table[mem_va.pdpte_idx].present = 1;
			my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

			my_pml4_table[mem_va.pml4e_idx].present = 1;
			my_pml4_table[mem_va.pml4e_idx].page_frame_number = pdpt_phys >> 12;

			// Create a new remapping entry
			new_entry.used = true;
			new_entry.remapped_va = mem_va;

			new_entry.pdpt_table.large_page = false;
			new_entry.pdpt_table.table = my_pdpt_table;

			new_entry.pd_table.large_page = false;
			new_entry.pd_table.table = my_pde_table;

			new_entry.pt_table = my_pte_table;

			status = add_remapping_entry(new_entry);

			*ensured_size = 0x1000 - mem_va.offset_4kb;

		cleanup:

			__invlpg(mem);

			return status;
		}

		bool ensure_memory_mapping_with_previous_mapping(void* mem, uint64_t mem_cr3_u64, remapped_entry_t* remapping_entry, uint64_t* ensured_size) {
			if (!ensured_size || !mem || !mem_cr3_u64 || !remapping_entry)
				return false;

			bool status = true;
			va_64_t mem_va = { 0 };
			cr3 mem_cr3 = { 0 };

			mem_va.flags = (uint64_t)mem;
			mem_cr3.flags = mem_cr3_u64;

			// Pointers to mapped system tables
			pml4e_64* mapped_pml4_table = 0;
			pdpte_64* mapped_pdpt_table = 0;
			pde_64* mapped_pde_table = 0;
			pte_64* mapped_pte_table = 0;

			// Pointers to our tables
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			usable_until_t max_usable = non_valid;
			status = get_max_remapping_level(remapping_entry, (uint64_t)mem, max_usable);
			if (status != true)
				goto cleanup;

			mapped_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			mapped_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (mapped_pml4_table[mem_va.pml4e_idx].page_frame_number << 12));

			if (mapped_pdpt_table[mem_va.pdpte_idx].large_page) {
				switch (max_usable) {
				case pdpt_table_valid:
				case pde_table_valid:
				case pte_table_valid: {
					my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
					if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
						status = false;
						goto cleanup;
					}


					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(&my_pdpt_table[mem_va.pdpte_idx], &mapped_pdpt_table[mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = true;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x40000000 - mem_va.offset_1gb;

					goto cleanup;
				}
				}
			}

			mapped_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (mapped_pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));

			if (mapped_pde_table[mem_va.pde_idx].large_page) {
				switch (max_usable) {
				case pdpt_table_valid: {
					my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
					if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
						status = false;
						goto cleanup;
					}

					my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
					if (!my_pde_table) {
						status = false;
						goto cleanup;
					}


					uint64_t pd_phys;
					status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
					if (status != true)
						goto cleanup;

					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
					my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = my_pde_table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x200000 - mem_va.offset_2mb;

					goto cleanup;
				}
				case pde_table_valid:
				case pte_table_valid: {
					pde_2mb_64* my_2mb_pde_table = (pde_2mb_64*)remapping_entry->pd_table.table;
					if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
						status = false;
						goto cleanup;
					}

					// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
					memcpy(&my_2mb_pde_table[mem_va.pde_idx], &mapped_pde_table[mem_va.pde_idx], sizeof(pde_2mb_64));

					remapped_entry_t new_entry;
					new_entry.used = true;
					new_entry.remapped_va = mem_va;

					new_entry.pdpt_table.large_page = false;
					new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

					new_entry.pd_table.large_page = true;
					new_entry.pd_table.table = remapping_entry->pd_table.table;

					status = add_remapping_entry(new_entry);

					*ensured_size = 0x200000 - mem_va.offset_2mb;

					goto cleanup;
				}
				}
			}

			mapped_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (mapped_pde_table[mem_va.pde_idx].page_frame_number << 12));

			switch (max_usable) {
			case pdpt_table_valid: {
				my_pdpt_table = (pdpte_64*)remapping_entry->pdpt_table.table;
				if (mem_va.pdpte_idx == remapping_entry->remapped_va.pdpte_idx) {
					status = false;
					goto cleanup;
				}
				my_pde_table = pt_manager::get_free_pd_table(&physmem.remapping_tables);
				if (!my_pde_table) {
					status = false;
					goto cleanup;
				}
				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = false;
					goto cleanup;
				}

				uint64_t pd_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pde_table, pd_phys);
				if (status != true)
					goto cleanup;

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != true)
					goto cleanup;


				// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				memcpy(my_pde_table, mapped_pde_table, sizeof(pde_2mb_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;
				my_pdpt_table[mem_va.pdpte_idx].page_frame_number = pd_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = my_pde_table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pde_table_valid: {
				my_pde_table = (pde_64*)remapping_entry->pd_table.table;
				if (mem_va.pde_idx == remapping_entry->remapped_va.pde_idx) {
					status = false;
					goto cleanup;
				}

				my_pte_table = pt_manager::get_free_pt_table(&physmem.remapping_tables);
				if (!my_pte_table) {
					status = false;
					goto cleanup;
				}

				uint64_t pt_phys = 0;
				status = runtime::translate_to_physical_address(physmem.constructed_cr3.flags, my_pte_table, pt_phys);
				if (status != true)
					goto cleanup;


				// Remember the order to change mappings (pt, pd, pdpt, pml4). If you don't do it in this order you will bsod sometimes
				memcpy(my_pte_table, mapped_pte_table, sizeof(pte_64) * 512);
				my_pde_table[mem_va.pde_idx].page_frame_number = pt_phys >> 12;


				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = my_pte_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			case pte_table_valid: {
				my_pte_table = (pte_64*)remapping_entry->pt_table;
				if (mem_va.pte_idx == remapping_entry->remapped_va.pte_idx) {
					status = false;
					goto cleanup;
				}


				memcpy(&my_pte_table[mem_va.pte_idx], &mapped_pte_table[mem_va.pte_idx], sizeof(pte_64));

				remapped_entry_t new_entry;
				new_entry.used = true;
				new_entry.remapped_va = mem_va;

				new_entry.pdpt_table.large_page = false;
				new_entry.pdpt_table.table = remapping_entry->pdpt_table.table;

				new_entry.pd_table.large_page = false;
				new_entry.pd_table.table = remapping_entry->pd_table.table;

				new_entry.pt_table = remapping_entry->pt_table;

				status = add_remapping_entry(new_entry);

				*ensured_size = 0x1000 - mem_va.offset_4kb;

				goto cleanup;
			}
			}

		cleanup:

			__invlpg(mem);
			return status;
		}

		bool ensure_memory_mapping(void* mem, uint64_t mem_cr3_u64, uint64_t* ensured_size = 0) {
			if (!mem || !mem_cr3_u64)
				return false;

			bool status = true;
			remapped_entry_t* remapping_entry = 0;
			uint64_t dummy_size = 0;

			status = get_remapping_entry(mem, remapping_entry);

			if (!ensured_size)
				ensured_size = &dummy_size;

			if (status == true) {
				status = ensure_memory_mapping_with_previous_mapping(mem, mem_cr3_u64, remapping_entry, ensured_size);
			}
			else {
				status = ensure_memory_mapping_without_previous_mapping(mem, mem_cr3_u64, ensured_size);
			}

			return status;
		}

		/*
			Exposed API's
		*/
		bool ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			bool status = true;
			uint64_t copied_bytes = 0;

			while (copied_bytes < size) {
				void* current_target = (void*)((uint64_t)target_address + copied_bytes);
				uint64_t ensured_size = 0;

				status = ensure_memory_mapping(current_target, mem_cr3_u64, &ensured_size);
				if (status != true) {
					return status;
				}

				copied_bytes += ensured_size;
			}

			return status;
		}

		bool overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			if (PAGE_ALIGN(target_address) != target_address ||
				PAGE_ALIGN(new_memory) != new_memory)
				return false;

			bool status = true;

			cr3 new_mem_cr3 = { 0 };

			va_64_t target_va = { 0 };
			va_64_t new_mem_va = { 0 };

			target_va.flags = (uint64_t)target_address;
			new_mem_va.flags = (uint64_t)new_memory;

			new_mem_cr3.flags = (uint64_t)new_mem_cr3_u64;

			pml4e_64* my_pml4_table = 0;
			pdpte_64* my_pdpt_table = 0;
			pde_64* my_pde_table = 0;
			pte_64* my_pte_table = 0;

			pml4e_64* new_mem_pml4_table = 0;
			pdpte_64* new_mem_pdpt_table = 0;
			pde_64* new_mem_pde_table = 0;
			pte_64* new_mem_pte_table = 0;


			// First ensure the mapping of the my address
			// in our cr3
			status = ensure_memory_mapping(target_address, target_address_cr3_u64);
			if (status != true)
				goto cleanup;


			my_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (physmem.constructed_cr3.address_of_page_directory << 12));
			new_mem_pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (new_mem_cr3.address_of_page_directory << 12));

			my_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (my_pml4_table[target_va.pml4e_idx].page_frame_number << 12));
			new_mem_pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (new_mem_pml4_table[new_mem_va.pml4e_idx].page_frame_number << 12));

			if (my_pdpt_table[target_va.pdpte_idx].large_page || new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
				if (!my_pdpt_table[target_va.pdpte_idx].large_page || !new_mem_pdpt_table[new_mem_va.pdpte_idx].large_page) {
					status = false;
					goto cleanup;
				}

				memcpy(&my_pdpt_table[target_va.pdpte_idx], &new_mem_pdpt_table[new_mem_va.pdpte_idx], sizeof(pdpte_1gb_64));

				goto cleanup;
			}

			my_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (my_pdpt_table[target_va.pdpte_idx].page_frame_number << 12));
			new_mem_pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (new_mem_pdpt_table[new_mem_va.pdpte_idx].page_frame_number << 12));

			if (my_pde_table[target_va.pde_idx].large_page || new_mem_pde_table[new_mem_va.pde_idx].large_page) {
				if (!my_pde_table[target_va.pde_idx].large_page || !new_mem_pde_table[new_mem_va.pde_idx].large_page) {
					status = false;
					goto cleanup;
				}

				memcpy(&my_pde_table[target_va.pde_idx], &new_mem_pde_table[new_mem_va.pde_idx], sizeof(pde_2mb_64));

				goto cleanup;
			}


			my_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (my_pde_table[target_va.pde_idx].page_frame_number << 12));
			new_mem_pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (new_mem_pde_table[new_mem_va.pde_idx].page_frame_number << 12));

			memcpy(&my_pte_table[target_va.pte_idx], &new_mem_pte_table[new_mem_va.pte_idx], sizeof(pte_64));

		cleanup:
			__invlpg(target_address);

			return status;
		}
	};

	namespace paging_manipulation {
		bool win_destroy_memory_page_mapping(void* memory, uint64_t& stored_flags) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;


			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table)
				return false;

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table)
				return false;

			stored_flags = pte_table[mem_va.pte_idx].flags;
			pte_table[mem_va.pte_idx].flags = 0;

			// DO NOT FUCKING FLUSH THE TRANSLATION
			// OR THE IDTR/GDTR STORING DETECTION
			// WILL NOT WORK PROPERLY

			return true;
		}

		bool win_restore_memory_page_mapping(void* memory, uint64_t stored_flags) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table)
				return false;

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table)
				return false;

			pte_table[mem_va.pte_idx].flags = stored_flags;

			return true;
		}

		bool set_single_page_supervisor(void* memory, cr3 mem_cr3, bool supervisor, uint64_t* set_size) {
			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + (mem_cr3.address_of_page_directory << 12));
			if (!pml4_table[mem_va.pml4e_idx].present)
				return pml4_table[mem_va.pml4e_idx].flags;

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table[mem_va.pdpte_idx].present)
				return false;

			if (pdpt_table[mem_va.pdpte_idx].large_page) {
				pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
				pml4_table[mem_va.pml4e_idx].supervisor = supervisor;
				__invlpg(memory);
				if(set_size)
					*set_size = 0x40000000 - mem_va.offset_1gb;

				return true;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table[mem_va.pde_idx].present)
				return false;

			if (pde_table[mem_va.pde_idx].large_page) {
				pde_table[mem_va.pde_idx].supervisor = supervisor;
				pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
				pml4_table[mem_va.pml4e_idx].supervisor = supervisor;
				__invlpg(memory);
				if(set_size)
					*set_size = 0x200000 - mem_va.offset_2mb;

				return true;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table[mem_va.pte_idx].present)
				return false;

			pte_table[mem_va.pte_idx].supervisor = supervisor;
			pde_table[mem_va.pde_idx].supervisor = supervisor;
			pdpt_table[mem_va.pdpte_idx].supervisor = supervisor;
			pml4_table[mem_va.pml4e_idx].supervisor = supervisor;

			if(set_size)
				*set_size = 0x1000 - mem_va.offset_4kb;

			__invlpg(memory);

			return true;
		}

		bool win_set_memory_range_supervisor(void* memory, uint64_t size, uint64_t mem_cr3, bool supervisor) {

			cr3 cr3_mem_cr3;
			cr3_mem_cr3.flags = mem_cr3;

			bool status = true;
			uint64_t set_bytes = 0;

			while (set_bytes < size) {
				void* current_target = (void*)((uint64_t)memory + set_bytes);
				uint64_t remaining_bytes = 0;

				status = set_single_page_supervisor(current_target, cr3_mem_cr3, supervisor, &remaining_bytes);
				if (status != true) {
					return status;
				}

				set_bytes += remaining_bytes;
			}

			return status;
		}

		bool is_memory_page_mapped(void* memory) {
			rflags flags;
			flags.flags = __readeflags();
			if (flags.interrupt_enable_flag || __readcr3() != physmem.constructed_cr3.flags)
				return false;

			PHYSICAL_ADDRESS max_addr = { 0 };
			max_addr.QuadPart = MAXULONG64;

			va_64_t mem_va;
			mem_va.flags = (uint64_t)memory;

			pml4e_64* pml4_table = 0;
			pdpte_64* pdpt_table = 0;
			pde_64* pde_table = 0;
			pte_64* pte_table = 0;

			pml4_table = (pml4e_64*)(physmem.mapped_physical_mem_base + __readcr3());
			if (!pml4_table)
				return false;

			pdpt_table = (pdpte_64*)(physmem.mapped_physical_mem_base + (pml4_table[mem_va.pml4e_idx].page_frame_number << 12));
			if (!pdpt_table) {
				return false;
			}

			pde_table = (pde_64*)(physmem.mapped_physical_mem_base + (pdpt_table[mem_va.pdpte_idx].page_frame_number << 12));
			if (!pde_table) {
				return false;
			}

			pte_table = (pte_64*)(physmem.mapped_physical_mem_base + (pde_table[mem_va.pde_idx].page_frame_number << 12));
			if (!pte_table)
				return false;

			return pte_table[mem_va.pte_idx].present;
		}

		bool prepare_driver_for_supervisor_access(void* driver_base, uint64_t driver_size, uint64_t mem_cr3) {
			/*
				First prepare the driver then the stack
			*/
			if (!physmem::remapping::ensure_memory_mapping_for_range((void*)driver_base, driver_size, mem_cr3))
				return false;

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)driver_base, driver_size, mem_cr3, 1))
				return false;

			/*
				Then prepare the stack
			*/
			KPCR* kpcr = __getpcr();
			void* curr_thread = *(void**)((uint64_t)kpcr->CurrentPrcb + 0x8);
			uint64_t stack_base = *(uint64_t*)((uint64_t)curr_thread + 0x38);
			uint64_t stack_limit = *(uint64_t*)((uint64_t)curr_thread + 0x30);
			uint64_t stack_size = stack_base - stack_limit;

			/*
				Since the stack grows downwards, stack_limit actually is the base of the mem
			*/
			if (!physmem::remapping::ensure_memory_mapping_for_range((void*)stack_limit, stack_size, mem_cr3))
				return false;

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)stack_limit, stack_size, mem_cr3, 1))
				return false;

			/*
				We need to set the interrupt record pages to supervisor to be able to access them from cpl = 3
			*/
			if (!physmem::remapping::ensure_memory_mapping_for_range((void*)safety_net::idt::get_interrupt_record(0), MAX_RECORDABLE_INTERRUPTS * sizeof(idt_regs_ecode_t), mem_cr3))
				return false;

			if (!physmem::paging_manipulation::win_set_memory_range_supervisor((void*)safety_net::idt::get_interrupt_record(0), MAX_RECORDABLE_INTERRUPTS * sizeof(idt_regs_ecode_t), mem_cr3, 1))
				return false;

			return true;
		}
	};

	bool is_initialized(void) {
		return physmem.initialized;
	}

	bool init_physmem(void) {
		if (!support::is_physmem_supported())
			return false;

		if (!page_table_initialization::initialize_page_tables())
			return false;

		physmem.initialized = true;

		return true;
	};
};