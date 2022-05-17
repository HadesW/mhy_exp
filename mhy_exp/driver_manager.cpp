#include "driver_manager.hpp"

driver::driver()
{
}

driver::~driver()
{
}

// ��������
BOOL driver::Load(const char* path, const char* name/*=USE_DEFINE_SERVICE_NAME*/)
{
	BOOL ret = FALSE;

	// ������
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
		// ���������
		manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (manager == nullptr)
			break;

		// ��������
		handle = CreateServiceA(manager, service_name.c_str(), service_name.c_str(), SERVICE_ALL_ACCESS,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, path, nullptr, nullptr, nullptr, nullptr, nullptr);
		// �����Ѿ����� ֱ�Ӵ�
		if (handle == nullptr && (GetLastError() == ERROR_SERVICE_EXISTS))
		{
			handle = OpenServiceA(manager, service_name.c_str(), SERVICE_ALL_ACCESS);
		}
		// �����û�о��
		if (handle == nullptr)
			break;

		// �������� ��ѯ����״̬
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

		// �����Ƿ���������
		if (status.dwCurrentState != SERVICE_RUNNING)
		{
			break;
		}

		ret = TRUE;
	} while (false);

	// �ͷ���Դ
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
		// ���������
		manager = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
		if (manager == nullptr)
			break;

		// �򿪷���
		handle = OpenServiceA(manager, service_name, SERVICE_STOP | DELETE);
		if (handle == nullptr)
			break;

		// ֹͣ����
		SERVICE_STATUS status = {};
		if (!ControlService(handle, SERVICE_CONTROL_STOP, &status))
			break;

		// ɾ������
		if (!DeleteService(handle))
		{
			break;
		}

	} while (false);

	// �ͷ���Դ
	if (handle)
		CloseServiceHandle(handle);
	if (manager)
		CloseServiceHandle(manager);

	return;
}

// ��������
HANDLE driver::Open(const char* name)
{
	HANDLE handle = INVALID_HANDLE_VALUE;

	// ���豸����
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
