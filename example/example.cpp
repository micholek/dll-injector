#include <injector/injector.h>
#include <iostream>
#include <print>
#include <string>
#include <windows.h>

void usage(const wchar_t *prog_name);

int wmain(int argc, wchar_t **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 0;
    }

    uint64_t load_lib_x64_addr =
        (uint64_t) GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryW");
    std::println("LoadLibraryW address = {:#018x}",
                 (uintptr_t) load_lib_x64_addr);
    dll_injector::Injector injector(load_lib_x64_addr, 0);

    std::vector<std::wstring> dll_names;
    dll_names.reserve(argc - 2);
    for (int i = 2; i < argc; i++) {
        dll_names.emplace_back(argv[i]);
    }

    const std::wstring process_name = argv[1];
    const std::vector<dll_injector::ProcessInfo> process_infos =
        dll_injector::get_process_info_values();
    const auto target_it =
        std::find_if(process_infos.cbegin(), process_infos.cend(),
                     [&process_name](const dll_injector::ProcessInfo &pi) {
                         return pi.name == process_name;
                     });
    if (target_it == std::cend(process_infos)) {
        std::wcout << "Could not find a process named " << process_name << "\n";
        return -1;
    }
    std::wcout << process_name << ": PID = " << target_it->pid << "\n";

    if (!injector.inject_multiple_dlls(target_it->pid, dll_names)) {
        std::println("Injection failed");
        return -2;
    }
    std::println("Injection succeeded");
    return 0;
}

void usage(const wchar_t *prog_name) {
    std::wcout
        << "Usage: " << prog_name << " <process_name> <dll_names>\n"
        << "process_name - target which dlls are to be injected to\n"
           "   dll_names - whitespace-seperated paths to dlls to inject\n\n";
}
