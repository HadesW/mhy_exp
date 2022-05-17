#pragma once
#include <iostream>
#include <stdint.h>
#pragma warning(disable:4005)
#include <windows.h>
#include <tlhelp32.h>
#include <ntstatus.h>
#include <winternl.h>
#include <algorithm>
#include <cctype>
#include <vector>

#include "ntdll.hpp"

namespace utils
{
	bool enable_debug_privilege();
	uint32_t get_process_id(const char* process_name);
	uint64_t get_process_base(uint32_t pid);
	//uint64_t get_sysmodule_base(const char* module_name);
	std::pair<uint64_t, uint32_t>get_sysmodule_info(const char* module_name);
	uint64_t get_sysmodule_base(const char* module_name);
	uint32_t get_sysmodule_size(const char* module_name);
	std::string get_current_process_name();
	std::vector<uint32_t> get_thread_id(uint32_t pid);
	uint32_t get_first_thread_id(uint32_t pid);
	uint8_t* search(const uint8_t* start, uint32_t size, const char* pattern, uint32_t len = -1, const char skip = '?');
}