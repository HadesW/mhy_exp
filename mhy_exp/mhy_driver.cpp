#include "mhy_driver.hpp"
#include "mhy_driver_res.hpp"

std::unique_ptr<mhy> mhy::m_instance = nullptr;

// driver and service name
const char* driver_name = "mhyprot2.sys";
const char* device_name = "\\??\\mhyprot2";

mhy* mhy::instance()
{
	static std::once_flag flag;

	std::call_once(flag, [&]()
		{
			mhy::m_instance.reset(new mhy());
		});

	return m_instance.get();
}

std::string mhy::res_to_file()
{
	std::string  ret;
	HANDLE handle = INVALID_HANDLE_VALUE;

	do
	{
		// 获取临时目录
		char buffer[MAX_PATH + 1] = { 0 };
		if (!GetTempPathA(MAX_PATH + 1, buffer))
		{
			break;
		}

		// 拼接路径
		// temp_path + driver_name
		std::string temp = buffer;
		if (temp.empty())
		{
			break;
		}
		temp = temp + driver_name;

		// 如果文件存在,不在创建
		if (0 == _access(temp.c_str(), 0))
		{
			ret = temp;
			break;
		}

		// 创建文件
		handle = CreateFileA(temp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (handle == INVALID_HANDLE_VALUE)
		{
			break;
		}

		// 写入数据
		DWORD written = 0;
		if (!WriteFile(handle, mhy_driver_res, sizeof(mhy_driver_res), &written, NULL))
		{
			break;
		}

		// 成功，返回路径
		ret = temp;
	} while (false);

	// 
	if (handle != INVALID_HANDLE_VALUE && handle != nullptr)
	{
		CloseHandle(handle);
	}

	return ret;
}

bool mhy::load()
{
	driver drv;
	bool ret = false;

	do
	{
		// 已经初始化了
		if (m_drvhandle != INVALID_HANDLE_VALUE)
		{
			ret = true;
			break;
		}

		// 释放文件
		std::string driver_path = res_to_file();
		if (driver_path.empty())
		{
			break;
		}

		// 加载驱动
		if (!drv.Load(driver_path.c_str()))
		{
			break;
		}

		// 连接驱动
		HANDLE handle = drv.Open(device_name);
		if (handle == INVALID_HANDLE_VALUE)
		{
			break;
		}

		// 初始化驱动
		if (!init(handle))
		{
			break;
		}

		// bingo
		m_drvhandle = handle;
		ret = true;
	} while (false);

	return ret;
}

void mhy::unload()
{
	driver drv;

	// 句柄打开了就关闭它
	if (m_drvhandle != INVALID_HANDLE_VALUE && m_drvhandle != nullptr)
	{
		CloseHandle(m_drvhandle);
		m_drvhandle = INVALID_HANDLE_VALUE;
	}

	drv.Unload(driver_name);
	return;
}

bool mhy::init(HANDLE handle)
{
	driver drv;
	bool ret = false;

	do
	{
		uint64_t local_key = 0;
		uint64_t remote_key = 0;

		// 7
		auto count = 7;
		std::mt19937_64 m_rand = std::mt19937_64();
		do
		{
			local_key = m_rand();
		} while ((--count) != 0);

		// origin data
		init_data data = {};
		data.low.pid = GetCurrentProcessId();
		data.low.consts = 0xBAEBAEEC;
		data.high.seed = m_rand.default_seed;//

		// encrypt data
		data.low.enc = data.high.seed ^ data.low.sum;
		data.high.enc = data.high.seed ^ 0xEBBAAEF4FFF89042;

		// send encrypt init_data
		if (!drv.Send(handle, MHY_IOCTL_INIT, &data, sizeof(data), &remote_key, sizeof(remote_key)))
		{
			break;
		}

		if (local_key != remote_key)
		{
			break;
		}

		ret = true;
	} while (false);

	return ret;
}

auto mhy::encrypt(void* data, size_t size, bool check /*= true*/, uint64_t seed /*= std::mt19937_64::default_seed*/) ->bool
{
	auto ret = false;

	// 验证参数 8字节对齐，并且总大小 <0x9C0
	if (check)
	{
		if ((size % 8 != 0) || (size / 8 >= 312))
		{
			return ret;
		}
	}

	do
	{
		// 
		auto m_rand = std::mt19937_64();

		uint64_t* ptr = reinterpret_cast<uint64_t*>(data);
		auto count = 0;
		auto counts = size >> 3;///
		uint64_t len = 0;
		auto index = 0;
		do
		{
			auto rand = m_rand();
			auto sum = seed + len;
			*ptr = sum ^ rand ^ (*ptr);
			len += 0x10;
			ptr++;
			count++;
			m_rand._Idx = m_rand._Idx % 0x138 + 0x138;//index
		} while (count < counts);

		ret = true;
	} while (false);

	return ret;
}

auto mhy::decrypt(void* data, size_t size, uint64_t seed /*= std::mt19937_64::default_seed*/) ->bool
{
	// the decrypted seed is not the default value, but comes from the returned data
	return encrypt(data, size, false, seed);
}

bool mhy::rpm(uint32_t pid, uint64_t address, void* buffer, size_t size)
{
	return rwpm(false, pid, address, buffer, size);
}

bool mhy::wpm(uint32_t pid, uint64_t address, void* buffer, size_t size)
{
	return rwpm(true, pid, address, buffer, size);
}

bool mhy::rwpm(bool written, uint32_t pid, uint64_t address, void* buffer, size_t size)
{
	driver drv;
	bool ret = false;
	auto seed = std::mt19937_64::default_seed;

	do
	{
		rwpm_data data;
		data.written = written;
		data.pid = pid;
		data.size = size;

		if (written)
		{
			// write
			data.src = reinterpret_cast<uint64_t>(buffer);
			data.dst = address;

		}
		else
		{
			// read
			data.src = address;
			data.dst = reinterpret_cast<uint64_t>(buffer);
		}

		// ioctl input buffer
		struct send_rwpm_data
		{
			uint64_t seed;
			rwpm_data enc_data;
		}send_data = { seed , data };

		// send data need encrypt
		if (!encrypt(&send_data.enc_data, sizeof(send_data.enc_data)))
		{
			break;
		}

		//
		struct recv_rwpm_data
		{
			uint64_t seed;
			uint32_t rw_size;
		}recv_data = { 0 , 0 };

		// ioctl
		unsigned long bytes = 0;
		if (!drv.Send(m_drvhandle, MHY_IOCTL_RWPM, &send_data, sizeof(send_data), &recv_data, sizeof(recv_data), &bytes) || bytes == 0)
		{
			break;
		}

		// readed or written size error
		if (recv_data.rw_size != data.size)
		{
			break;
		}

		ret = true;
	} while (false);

	return ret;
}

bool mhy::rkm(uint64_t address, void* buffer, size_t size)
{
	return false;
}

bool mhy::kill(uint32_t pid)
{
	driver drv;
	auto ret = false;
	auto seed = std::mt19937_64::default_seed;

	do
	{
		// ioctl input buffer
		struct send_kill_data
		{
			uint64_t seed;
			uint64_t enc_data;
		}send_data = { seed , pid };

		// send data need encrypt
		if (!encrypt(&send_data.enc_data, sizeof(send_data.enc_data)))
		{
			break;
		}

		//
		struct recv_kill_data
		{
			uint64_t seed;
			uint32_t killed;
		}recv_data = { 0 , 0 };

		// ioctl
		unsigned long bytes = 0;
		if (!drv.Send(m_drvhandle, MHY_IOCTL_KILL, &send_data, sizeof(send_data), &recv_data, sizeof(recv_data), &bytes) || bytes == 0)
		{
			break;
		}

		// killed
		if (recv_data.killed != 0)
		{
			break;
		}

		ret = true;
	} while (false);

	return ret;
}

bool mhy::modules(std::vector<module_info>& info, uint32_t pid, uint32_t maxnum /*= 0x100*/)
{
	driver drv;
	char* buffer = nullptr;
	bool ret = false;
	auto seed = std::mt19937_64::default_seed;

	do
	{
		// ioctl input buffer
		struct send_module_data
		{
			uint64_t seed;
			module_data enc_data;
		}send_data = { seed ,{pid,maxnum} };

		// send data need encrypt
		if (!encrypt(&send_data.enc_data, sizeof(send_data.enc_data)))
		{
			break;
		}

		// alloc output buffer
		auto size = maxnum * sizeof(module_info);
		buffer = reinterpret_cast<char*>(malloc(size));
		if (!buffer)
		{
			break;
		}

		ZeroMemory(buffer, size);

		// ioctl
		unsigned long bytes = 0;
		if (!drv.Send(m_drvhandle, MHY_IOCTL_MODULES, &send_data, sizeof(send_data), buffer, static_cast<unsigned long>(size), &bytes) || bytes == 0)
		{
			break;
		}

		//
		// returned module_info need decrypt
		// returned struct(buffer)  is (seed(or called the key) + module_info array)
		//

		// key
		seed = *reinterpret_cast<uint64_t*>(buffer);

		// decrypt module_info
		void* p_info = reinterpret_cast<char*>(buffer) + sizeof(seed);
		if (!decrypt(p_info, bytes - sizeof(seed), seed))
		{
			break;
		}

		// save to vector
		auto count = (bytes - sizeof(seed)) / sizeof(module_info);

		for (size_t i = 0; i < count; i++)
		{
			info.push_back(reinterpret_cast<p_module_info>(p_info)[i]);
		}

		ret = true;
	} while (false);

	// free alloc
	if (buffer)
	{
		free(buffer);
	}

	return ret;
}

uint64_t mhy::module_base(std::vector<module_info>& info, std::wstring name)
{
	uint64_t base = 0;

	for (size_t i = 0; i < info.size(); i++)
	{
		if (_wcsicmp(info[i].base_dll_name, name.c_str()) == 0)
		{
			base = info[i].dll_base;
			break;
		}
	}

	return base;
}

uint64_t mhy::module_base(uint32_t pid, std::wstring name)
{
	uint64_t base = 0;

	std::vector<module_info> mods;

	do
	{
		if (!modules(mods, pid))
		{
			break;
		}

		base = module_base(mods, name);

	} while (false);

	return base;
}

uint32_t mhy::module_size(std::vector<module_info>& info, std::wstring name)
{
	uint32_t size = 0;

	for (size_t i = 0; i < info.size(); i++)
	{
		if (_wcsicmp(info[i].base_dll_name, name.c_str()) == 0)
		{
			size = info[i].size_of_image;
			break;
		}
	}

	return size;
}

uint32_t mhy::module_size(uint32_t pid, std::wstring name)
{
	uint32_t size = 0;

	std::vector<module_info> mods;

	do
	{
		if (!modules(mods, pid))
		{
			break;
		}

		size = module_size(mods, name);

	} while (false);

	return size;
}

bool mhy::udump(uint32_t pid, std::wstring name)
{
	auto ret = false;
	LPVOID buffer = nullptr;
	HANDLE handle = INVALID_HANDLE_VALUE;

	do
	{
		if (pid == 0 || name.empty())
		{
			break;
		}

		uint64_t base = module_base(pid, name);
		if (base == 0)
		{
			break;
		}

		uint32_t size = module_size(pid, name);
		if (size == 0)
		{
			break;
		}

		// alloc memory
		buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!buffer)
		{
			break;
		}

		// read
		if (!rpm(pid, base, buffer, size))
		{
			break;
		}

		// check pe
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			break;
		}
		PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(buffer) + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			break;
		}

		// fix section
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
		for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i, section++)
		{
			const std::string section_name((char*)section->Name);
			section->PointerToRawData = section->VirtualAddress;
			section->SizeOfRawData = section->Misc.VirtualSize;
		}

		// save file
		const std::wstring file_name(std::wstring(L"dump_") + name);
		handle = CreateFileW(file_name.c_str(), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE || handle == nullptr)
		{
			break;
		}
		if (!WriteFile(handle, buffer, size, NULL, NULL))
		{
			break;
		}

		ret = true;
	} while (false);

	//
	if (buffer)
	{
		VirtualFree(buffer, module_size(pid, name), MEM_RELEASE);
	}

	if (handle != INVALID_HANDLE_VALUE || handle != nullptr)
	{
		CloseHandle(handle);
	}

	return ret;
}

bool mhy::kdump(std::string name)
{
	auto ret = false;
	LPVOID buffer = nullptr;
	HANDLE handle = INVALID_HANDLE_VALUE;

	do
	{
		if (name.empty())
		{
			break;
		}

		auto [base, size] = utils::get_sysmodule_info(name.c_str());
		if (base == 0 || size == 0)
		{
			break;
		}

		// alloc memory
		buffer = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!buffer)
		{
			break;
		}

		// read
		if (!rkm(base, buffer, size))
		{
			break;
		}

		// check pe
		PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
		if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
		{
			break;
		}
		PIMAGE_NT_HEADERS nt_header = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<char*>(buffer) + dos_header->e_lfanew);
		if (nt_header->Signature != IMAGE_NT_SIGNATURE)
		{
			break;
		}

		// fix section
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_header);
		for (WORD i = 0; i < nt_header->FileHeader.NumberOfSections; ++i, section++)
		{
			const std::string section_name((char*)section->Name);
			section->PointerToRawData = section->VirtualAddress;
			section->SizeOfRawData = section->Misc.VirtualSize;
		}

		// save file
		const std::string file_name(std::string("dump_") + name);
		handle = CreateFileA(file_name.c_str(), GENERIC_ALL, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (handle == INVALID_HANDLE_VALUE || handle == nullptr)
		{
			break;
		}
		if (!WriteFile(handle, buffer, size, NULL, NULL))
		{
			break;
		}

		ret = true;
	} while (false);

	//
	if (buffer)
	{
		VirtualFree(buffer, utils::get_sysmodule_size(name.c_str()), MEM_RELEASE);
	}

	if (handle != INVALID_HANDLE_VALUE || handle != nullptr)
	{
		CloseHandle(handle);
	}

	return ret;
}

bool mhy::processes()
{
	return false;
}

bool mhy::handles()
{
	return false;
}