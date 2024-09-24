#include "includes.h"
#include "func_defs.hpp"
#include "physmem/physmem.hpp"

void execute_detections(uint64_t driver_base, uint64_t driver_size) {
	if (!physmem::init_physmem())
		return;
	
	log_new_line();
	log_info("Physmem inited");

	if (!safety_net::init_safety_net(driver_base, driver_size))
		return;

	log_info("Safety net inited\n");

	// Setup the driver for supervisor access (yes, some detections switch into cpl = 3...)
	safety_net_t storage;
	if (!safety_net::start_safety_net(storage))
		return;
	if (!physmem::paging_manipulation::prepare_driver_for_supervisor_access((void*)driver_base, driver_size, __readcr3())) {
		safety_net::stop_safety_net(storage);
		log_error("Failed to setup driver for supervisor access");
		return;
	}
	safety_net::stop_safety_net(storage);

	log_info("IDT:");
	idt::execute_idt_detections();
	log_new_line();
}

NTSTATUS driver_entry(uint64_t driver_base, uint64_t driver_size) {

	log_info("Driver loaded at %p with size %p", driver_base, driver_size);

	execute_detections(driver_base, driver_size);

	return STATUS_SUCCESS;
}