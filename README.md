# Hypervisor IDT Detections (SIDT / LIDT)

Small pet project of mine to detect hypervisors by checking for inconsistencies when exiting on sidt or lidt

**Warning:** this can crash your PC. Tested only on my machine (;

## How it works (short)

Before running any detection, the driver sets up a "safety net":

-> Creates its own GDT / IDT / TSS / CS / SS / CR3 and loads those
-> disables interrupts and records all exceptions (safety_net.cpp)
-> allows temporary CPL switches (CPL0 ↔ CPL3) via syscall/sysret to allow to monitor user mode behaviour from the driver even in kernel memory (prepare the memory range for um access first though: physmem.cpp:prepare_driver_for_supervisor_access)
-> allows switching to compatibility mode (32-bit) for certain tests which was the most work out of all of those checks (cancerous to implement in my opinion (; )

Detections are executed inside this environment and everything is restored afterward.


## SIDT

    /*
        List of checks:

        detection_1 -> #GP(0) due to lock Prefix
        detection_2 -> #PF due to invalid memory operand
        detection_3 -> SIDT with operand not mapped in cr3 but in TLB
        detection_4 -> Timing check (500 tsc ticks acceptable)
        detection_5 -> Compatibility mode idtr storing
        detection_6 -> Non canonical address passed as memory operand
        detection_7 -> Non canonical address passed as memory operand in SS segment -> #SS
        detection_8 -> Executing sidt with cpl = 3 but with cr4.umip = 1 -> #GP(0) should be caused
    */

## LIDT

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

## Notes
If you have any other hv detections that you think would fit into this repo make a pull request or sth.
No timing checks please, as I want sorta new ideas to be collected here <3

-> “Failed detection” means behavior did not match bare metal expectations
