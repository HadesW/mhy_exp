#include "driver_manager.hpp"

driver::driver()
{
}

driver::~driver()
{
}

// 加载驱动
BOOL driver::Load(const char* path, const char* name/*=USE_DEFINE_SERVICE_NAME*/)
{
	BOOL ret = FALSE;

	// 服务名
	std::string service_name;
	if (name == USE_DEFINE_SERVICE_NAME)
	{
#if __cplusplus >= 201703L || _MSC_VER >=1921
		service_name = std::filesystem::path(std::string(path)).filename().string();
#else
		service_name = std::tr2::sys::path(std::string(path)).filename().string();
#endif // __cplusplus >= 201703L || _MSC_VER >=1921
	}
	else
	{
		service_name = name;
	}

	SC_HANDLE manager = nullptr;
	SC_HANDLE handle = nullptr;

	do
	{
		// 服务管理器
		manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (manager == nullptr)
			break;

		// 创建服务
		handle = CreateServiceA(manager, service_name.c_str(), service_name.c_str(), SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, path, nullptr, nullptr, nullptr, nullptr, nullptr);
		// 服务已经存在 直接打开
		if (handle == nullptr && (GetLastError() == ERROR_SERVICE_EXISTS))
		{
			handle = OpenServiceA(manager, service_name.c_str(), SERVICE_ALL_ACCESS);
		}
		// 最后还是没有句柄
		if (handle == nullptr)
			break;

		// 开启服务 查询服务状态
		if (!StartServiceA(handle, 0, nullptr))
			break;

		SERVICE_STATUS status = {};
		while (QueryServiceStatus(handle, &status))
		{
			if (status.dwCurrentState != SERVICE_START_PENDING)
			{
				break;
			}
			Sleep(500);
		}

		// 服务是否正常运行
		if (status.dwCurrentState != SERVICE_RUNNING)
		{
			break;
		}

		ret = TRUE;
	} while (false);

	// 释放资源
	if (handle)
		CloseServiceHandle(handle);
	if (manager)
		CloseServiceHandle(manager);

	return ret;
}

VOID driver::Unload(const char* service_name)
{
	SC_HANDLE manager = nullptr;
	SC_HANDLE handle = nullptr;

	do
	{
		// 服务管理器
		manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (manager == nullptr)
			break;

		// 打开服务
		handle = OpenServiceA(manager, service_name, SERVICE_STOP | DELETE);
		if (handle == nullptr)
			break;

		// 停止服务
		SERVICE_STATUS status = {};
		if (!ControlService(handle, SERVICE_CONTROL_STOP, &status))
			break;

		// 删除服务
		if (!DeleteService(handle))
		{
			break;
		}

	} while (false);

	// 释放资源
	if (handle)
		CloseServiceHandle(handle);
	if (manager)
		CloseServiceHandle(manager);

	return;
}

// 连接驱动
HANDLE driver::Open(const char* name)
{
	HANDLE handle = INVALID_HANDLE_VALUE;

	// 打开设备驱动
	handle = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	return handle;
}

BOOL driver::Send(HANDLE handle, DWORD io_code, PVOID in_buffer, DWORD in_size, PVOID out_buffer, DWORD out_size, DWORD* ret_bytes /*= nullptr*/)
{
	BOOL ret = FALSE;

	do
	{
		if (handle == INVALID_HANDLE_VALUE)
		{
			break;
		}

		DWORD bytes = 0;
		if (!DeviceIoControl(handle, io_code, in_buffer, in_size, out_buffer, out_size, &bytes, NULL))
		{
			break;
		}

		if (ret_bytes)
		{
			*ret_bytes = bytes;
		}

		ret = TRUE;
	} while (false);

	return ret;
}
