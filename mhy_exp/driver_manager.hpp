#pragma once
#include <string>
#include <filesystem>
#include <windows.h>

#define USE_DEFINE_SERVICE_NAME 0

class driver
{
public:
	driver();
	~driver();
	BOOL Load(const char* path, const char* name = USE_DEFINE_SERVICE_NAME);
	VOID Unload(const char* service_name);
	HANDLE Open(const char* name);
	BOOL Send(HANDLE handle, DWORD io_code, PVOID in_buffer, DWORD in_size, PVOID out_buffer, DWORD out_size, DWORD* ret_bytes = nullptr);
	// 
	// TODO: 需要写强制卸载函数，和安全加载函数 UnloadForce();  LoadSafe();
	//

private:

};

