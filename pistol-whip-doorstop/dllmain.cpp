// dllmain.cpp : Defines the entry point for the DLL application.
#include "framework.h"
#include "crt.h"

#include "winapi-util.h"

#include "proxy.h"

#include "assert-util.h"

#include <atomic>

extern "C" IMAGE_DOS_HEADER __ImageBase; // This is provided by MSVC with the infomration about this DLL

constexpr auto target_name = "GameAssembly";
constexpr auto modloader_name = "MODLOADER.dll";
constexpr auto modloader_load = "load";

std::atomic<bool> run = false;

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		hHeap = GetProcessHeap();

		wchar_t* dll_path = NULL;
		size_t dll_path_len = get_module_path((HINSTANCE)&__ImageBase, &dll_path, NULL, 0);

		wchar_t* dll_name = get_file_name_no_ext(dll_path, dll_path_len);

		loadProxy(dll_name);

		memfree(dll_name);
		memfree(dll_path);
	}

	if (ul_reason_for_call == DLL_THREAD_ATTACH && !run.load(std::memory_order_acquire))
	{
		run.store(true, std::memory_order_release);

		auto module = GetModuleHandleA(target_name);
		ASSERT(module, L"Could not find GameAssembly.dll module, we are in the wrong place!");

		// Now, let's call LoadLibrary on a bunch of libraries that we (hopefully?) can find
		HMODULE modloader = LoadLibraryA(modloader_name);
		ASSERT(modloader, L"Could not find Modloader.dll! Ensure that it is in the same folder as winhttp.dll!");

		FARPROC loadCall = GetProcAddress(modloader, modloader_load);
		ASSERT(loadCall, L"Could not find Modloader.dll 'load' method! Ensure that it is declared extern C and is exported!");

		// Call the Modloader.dll_load method
		loadCall();
	}

	return TRUE;
}

