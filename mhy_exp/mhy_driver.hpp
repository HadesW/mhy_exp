#pragma once
#include <iostream>
#include <memory>
#include <mutex>
#include <random>
#include <stdint.h>
#include <io.h> 

#include "utils.hpp"
#include "driver_manager.hpp"

#define MHY_IOCTL_INIT					0x80034000
#define MHY_IOCTL_RKM					0x83064000
#define MHY_IOCTL_RWPM				0x81074000
#define MHY_IOCTL_KILL					0x81034000
#define MHY_IOCTL_MODULES			0x81054000
#define MHY_IOCTL_HANDLES			0X83014000// or process


class mhy
{
public:
#pragma pack(1)
	typedef struct _init_data
	{
		union {
			struct {
				uint32_t pid;
				uint32_t consts;
			};
			uint64_t sum;
			uint64_t enc;
		}low;
		union {
			uint64_t seed;
			uint64_t enc;
		}high;
	}init_data, *p_init_data;
	static_assert(sizeof(init_data) == 0x10, "init_data size fail");

	typedef struct _module_data
	{
		uint32_t pid;
		uint32_t maxnum;
	}module_data, *p_module_data;
	static_assert(sizeof(module_data) == 0x8, "module_data size fail");

	typedef struct _module_info
	{
		uint32_t pad0;
		uint64_t dll_base;
		uint32_t size_of_image;
		wchar_t  base_dll_name[0x100 / 2];
		wchar_t  full_dll_name[0x208 / 2];
	}module_info, *p_module_info;
	static_assert(sizeof(module_info) == 0x318, "module_info size fail");

	typedef struct _rwpm_data
	{
		uint32_t written;
		uint32_t padding;
		uint64_t pid;
		uint64_t dst;
		uint64_t src;
		uint64_t size;
	}rwpm_data, *p_rwpm_data;
	static_assert(sizeof(rwpm_data) == 0x28, "rwpm_data size fail");

	typedef struct _rkm_data
	{
		union _header
		{
			uint32_t		result;
			uint64_t		address;
		} header;
		uint32_t size;
	}rkm_data, *p_rkm_data;
	static_assert(sizeof(rkm_data) == 0xC, "rkm_data size fail");

	typedef struct _hooks_info
	{
		uint64_t handle;
		uint32_t type;
		uint32_t index;
		uint64_t function;
	}hooks_info, *p_hooks_info;
	static_assert(sizeof(hooks_info) == 0x18, "hooks_info size fail");
#pragma pack()
public:
	static mhy* instance();
	std::string res_to_file();
	bool load();
	void unload();

	bool init(HANDLE handle);
	auto encrypt(void* data, size_t size, bool check = true, uint64_t seed = std::mt19937_64::default_seed)->bool;
	auto decrypt(void* data, size_t size, uint64_t seed = std::mt19937_64::default_seed)->bool;

	//
	bool rwpm(bool written, uint32_t pid, uint64_t address, void* buffer, size_t size);

	bool rpm(uint32_t pid, uint64_t address, void* buffer, size_t size);
	template <typename x>
	x rpm(uint32_t pid, uint64_t address);

	bool wpm(uint32_t pid, uint64_t address, void* buffer, size_t size);
	template <typename x>
	bool wpm(uint32_t pid, uint64_t address, x value);

	bool rkm(uint64_t address, void* buffer, size_t size);
	template <typename x>
	x rkm(uint64_t address);

	//bool wkm(void* address, void* buffer, size_t size);

	//
	bool modules(std::vector<module_info> &info, uint32_t pid, uint32_t maxnum = 0x100);
	uint64_t module_base(uint32_t pid, std::wstring name);
	uint64_t module_base(std::vector<module_info> &info, std::wstring name);
	uint32_t module_size(uint32_t pid, std::wstring name);
	uint32_t module_size(std::vector<module_info> &info, std::wstring name);

	//
	bool udump(uint32_t pid, std::wstring name);
	bool kdump(std::string name);

	//
	bool kill(uint32_t pid);

	// TODO
	bool handles();
	bool processes();


private:
	mhy() = default;
	mhy(const mhy&) = delete;
	mhy& operator=(const mhy&) = delete;
	static std::unique_ptr<mhy> m_instance;
	HANDLE m_drvhandle = INVALID_HANDLE_VALUE;
};

template <typename x>
x mhy::rpm(uint32_t pid, uint64_t address)
{
	x buffer;
	rpm(pid, address, &buffer, sizeof(x));
	return buffer;
}

template <typename x>
bool mhy::wpm(uint32_t pid, uint64_t address, x value)
{
	return wpm(pid, address, &value, sizeof(x));
}

template <typename x>
x mhy::rkm(uint64_t address)
{
	x buffer;
	rkm(address, &buffer, sizeof(x));
	return buffer;
}
