#include "utils.hpp"

namespace utils
{

	bool enable_debug_privilege()
	{
		bool ret = false;
		HANDLE handle = nullptr;
		LUID luid;
		TOKEN_PRIVILEGES privilege;

		do
		{
			//
			if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &handle))
			{
				break;
			}

			//
			if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
			{
				break;
			}

			//
			privilege.PrivilegeCount = 1;
			privilege.Privileges[0].Luid = luid;
			privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			if (!AdjustTokenPrivileges(handle, false, &privilege, sizeof(privilege), NULL, NULL))
			{
				break;
			}

			//
			ret = true;
		} while (false);

		//
		if (handle != nullptr)
		{
			CloseHandle(handle);
		}

		return ret;
	}

	uint32_t get_process_id(const char* process_name)
	{
		uint32_t pid = 0;
		HANDLE handle = INVALID_HANDLE_VALUE;

		do
		{
			handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (handle == INVALID_HANDLE_VALUE)
			{
				break;
			}

			PROCESSENTRY32 pe;
			pe.dwSize = sizeof(PROCESSENTRY32);
			if (!Process32First(handle, &pe))
			{
				break;
			}

			do
			{
				//
				if (_stricmp(process_name, pe.szExeFile) == 0)
				{
					pid = pe.th32ProcessID;
					break;
				}
			} while (Process32Next(handle, &pe));

		} while (false);

		if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
		{
			CloseHandle(handle);
		}

		return pid;
	}

	uint64_t get_process_base(uint32_t pid)
	{
		uint64_t base = 0;
		HANDLE handle = INVALID_HANDLE_VALUE;

		do
		{
			handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
			if (handle == INVALID_HANDLE_VALUE)
			{
				break;
			}

			MODULEENTRY32 me;
			me.dwSize = sizeof(MODULEENTRY32);
			if (!Module32First(handle, &me))
			{
				break;
			}

			//
			base = reinterpret_cast<uint64_t>(me.modBaseAddr);

		} while (false);

		if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
		{
			CloseHandle(handle);
		}

		return base;
	}

	//uint64_t get_sysmodule_base(const char* module_name)
	//{
	//	uint64_t base = 0;
	//	PVOID buffer = nullptr;
	//	DWORD buffer_size = 0;

	//	do
	//	{
	//		// 获取大小
	//		NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(ntdll::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	//		if (status != STATUS_INFO_LENGTH_MISMATCH)
	//			break;

	//		// 申请空间
	//		buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	//		if (!buffer)
	//			break;

	//		// 获取buffer
	//		status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(ntdll::SystemModuleInformation), buffer, buffer_size, &buffer_size);
	//		if (!NT_SUCCESS(status))
	//			break;

	//		// 遍历链表
	//		const auto modules = static_cast<ntdll::PRTL_PROCESS_MODULES_T>(buffer);

	//		for (auto i = 0u; i < modules->NumberOfModules; ++i)
	//		{
	//			const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

	//			// 找到了
	//			if (_stricmp(current_module_name.c_str(), module_name) == 0)
	//			{
	//				base = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
	//				break;
	//			}
	//		}

	//	} while (false);

	//	if (buffer)
	//	{
	//		VirtualFree(buffer, 0, MEM_RELEASE);
	//	}

	//	return base;
	//}

	std::pair<uint64_t, uint32_t> get_sysmodule_info(const char* module_name)
	{
		std::pair<uint64_t, uint32_t> ret(0, 0);

		uint64_t base = 0;
		uint32_t size = 0;
		PVOID buffer = nullptr;
		DWORD buffer_size = 0;

		do
		{
			// 获取大小
			NTSTATUS status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(ntdll::SystemModuleInformation), buffer, buffer_size, &buffer_size);
			if (status != STATUS_INFO_LENGTH_MISMATCH)
				break;

			// 申请空间
			buffer = VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (!buffer)
				break;

			// 获取buffer
			status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(ntdll::SystemModuleInformation), buffer, buffer_size, &buffer_size);
			if (!NT_SUCCESS(status))
				break;

			// 遍历链表
			const auto modules = static_cast<ntdll::PRTL_PROCESS_MODULES_T>(buffer);

			for (auto i = 0u; i < modules->NumberOfModules; ++i)
			{
				const std::string current_module_name = std::string(reinterpret_cast<char*>(modules->Modules[i].FullPathName) + modules->Modules[i].OffsetToFileName);

				// 找到了
				if (_stricmp(current_module_name.c_str(), module_name) == 0)
				{
					base = reinterpret_cast<uint64_t>(modules->Modules[i].ImageBase);
					size = static_cast<uint32_t>(modules->Modules[i].ImageSize);
					break;
				}
			}

			ret = std::make_pair(base, size);
		} while (false);

		if (buffer)
		{
			VirtualFree(buffer, 0, MEM_RELEASE);
		}

		return ret;
	}

	uint64_t get_sysmodule_base(const char* module_name)
	{
		return get_sysmodule_info(module_name).first;
	}

	uint32_t get_sysmodule_size(const char* module_name)
	{
		return get_sysmodule_info(module_name).second;
	}

	std::string get_current_process_name()
	{
		std::string name;
		char buffer[MAX_PATH] = {};

		do
		{
			//
			ZeroMemory(buffer, sizeof(buffer));

			//
			auto len = GetModuleFileNameA(nullptr, reinterpret_cast<LPSTR>(buffer), sizeof(buffer));
			if (len <= 0)
			{
				break;
			}

			// 处理字符串
			std::string full_path_name = buffer;
			auto index = full_path_name.find_last_of('\\');
			if (index <= 0)
			{
				break;
			}

			//
			name = full_path_name.substr(index + 1, full_path_name.length());
		} while (false);

		return name;
	}

	std::vector<uint32_t> get_thread_id(uint32_t pid)
	{
		std::vector<uint32_t> ret;
		HANDLE handle = INVALID_HANDLE_VALUE;

		do
		{
			handle = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
			if (handle == INVALID_HANDLE_VALUE)
			{
				break;
			}

			//
			THREADENTRY32 te;
			te.dwSize = sizeof(THREADENTRY32);
			if (!Thread32First(handle, &te))
			{
				break;
			}

			do {
				// pid
				if (te.th32OwnerProcessID == pid)
				{
					ret.push_back(te.th32ThreadID);
				}
			} while (Thread32Next(handle, &te));

		} while (false);

		if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
		{
			CloseHandle(handle);
		}

		return ret;
	}

	uint32_t get_first_thread_id(uint32_t pid)
	{
		uint32_t tid = 0;

		do
		{
			std::vector<uint32_t> ids = get_thread_id(pid);
			if (ids.size() <= 0)
			{
				break;
			}

			tid = ids[0];
		} while (false);

		return tid;
	}

	uint8_t* search(uint8_t* start, uint32_t size, const char* pattern, uint32_t len /*= -1*/, const char skip /*= '?'*/)
	{
		uint8_t* ret = nullptr;

		//
		return ret;
	}
}

