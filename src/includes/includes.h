#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "ia32.hpp"

#define log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " fmt "\n", ##__VA_ARGS__)
#define log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " fmt "\n", ##__VA_ARGS__)
#define log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-!-] " fmt "\n", ##__VA_ARGS__)


#define INDENT_SPACES(count) ((count) == 1 ? " " : \
                             (count) == 2 ? "  " : \
                             (count) == 3 ? "   " : \
                             (count) == 4 ? "    " : \
                             (count) == 5 ? "     " : \
                             (count) == 6 ? "      " : \
                             (count) == 7 ? "       " : \
                             (count) == 8 ? "        " : \
                             (count) == 9 ? "         " : "         ")
#define log_info_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s[*] " fmt "\n", INDENT_SPACES(indent), ##__VA_ARGS__)
#define log_success_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s[+] " fmt "\n", INDENT_SPACES(indent), ##__VA_ARGS__)
#define log_error_indent(indent, fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s[-!-] " fmt "\n", INDENT_SPACES(indent), ##__VA_ARGS__)

#define log_new_line() DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,"\n")
