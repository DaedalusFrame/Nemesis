#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "ia32.hpp"

#define MAX_RECORDABLE_INTERRUPTS 10

#define MAX_ACCEPTABLE_TSC 500

typedef union {

    struct {
        uint64_t offset_1gb : 30;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_2mb : 21;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    struct {
        uint64_t offset_4kb : 12;
        uint64_t pte_idx : 9;
        uint64_t pde_idx : 9;
        uint64_t pdpte_idx : 9;
        uint64_t pml4e_idx : 9;
        uint64_t reserved : 16;
    };

    uint64_t flags;
} va_64_t;

#define UNW_FLAG_EHANDLER  1

typedef struct
{
	UINT32 BeginAddress;
	UINT32 EndAddress;
	UINT32 HandlerAddress;
	UINT32 JumpTarget;
} SCOPE_RECORD;

typedef struct
{
	UINT32 Count;
	SCOPE_RECORD ScopeRecords[1];
} SCOPE_TABLE;

typedef struct
{
	UINT32 BeginAddress;
	UINT32 EndAddress;
	UINT32 UnwindData;
} RUNTIME_FUNCTION;

#pragma warning(push)
#pragma warning(disable : 4200)
#pragma warning(disable : 4201)
#pragma warning(disable : 4214)
typedef union {
	UINT8 CodeOffset;
	UINT8 UnwindOp : 4;
	UINT8 OpInfo : 4;
	UINT16 FrameOffset;
} UNWIND_CODE;

typedef struct {
	UINT8 Version : 3;
	UINT8 Flags : 5;
	UINT8 SizeOfProlog;
	UINT8 CountOfCodes;
	UINT8 FrameRegister : 4;
	UINT8 FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];

	union {
		UINT32 ExceptionHandler;
		UINT32 FunctionEntry;
	};

	UINT32 ExceptionData[];
} UNWIND_INFO;
#pragma warning(pop)

#pragma pack(push)
typedef struct {
	uint64_t r15;
	uint64_t r14;
	uint64_t r13;
	uint64_t r12;
	uint64_t r11;
	uint64_t r10;
	uint64_t r9;
	uint64_t r8;
	uint64_t rbp;
	uint64_t rdi;
	uint64_t rsi;
	uint64_t rdx;
	uint64_t rcx;
	uint64_t rbx;
	uint64_t rax;

	uint64_t exception_vector;
	uint64_t error_code;

	uint64_t rip;
	uint64_t cs_selector;
	rflags rflags;
	uint64_t rsp;
	uint64_t ss_selector;
} idt_regs_ecode_t;
#pragma push(pop)

typedef struct {
	segment_descriptor_register_64 safed_idtr;
	segment_descriptor_register_64 safed_gdtr;

	uint16_t safed_ss;
	uint16_t safed_cs;
	uint16_t safed_tr;

	uint64_t safed_cr3;
	uint64_t safed_cr4; // Safed and exchanged to disable SMEP and SMAP

	KPCR* safed_kpcr;
}safety_net_t;
