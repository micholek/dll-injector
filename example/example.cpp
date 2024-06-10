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

    dll_injector::Injector injector(dll_injector::DefaultInit::X64);
    std::println("LoadLibraryW address = {:#018x}",
                 (uintptr_t) injector.get_load_library_x64_addr());

    std::vector<std::wstring> dll_names;
    dll_names.reserve(argc - 2);
    for (int i = 2; i < argc; i++) {
        dll_names.emplace_back(argv[i]);
    }

    bool res = false;
    try {
        const uint32_t pid = std::stoul(argv[1]);
        std::println("Injecting into process with PID = {}", pid);
        res = injector.inject_dlls(pid, dll_names);
    } catch (...) {
        const std::wstring process_name = argv[1];
        std::wcout << "Injecting into process with name: " << process_name
                   << "\n";
        res = injector.inject_dlls(process_name, dll_names);
    }

    if (!res) {
        std::println("Injection failed");
        return -2;
    }
    std::println("Injection succeeded");
    return 0;
}

void usage(const wchar_t *prog_name) {
    std::wcout
        << "Usage: " << prog_name
        << " <process_name|pid> <dll_names>\n"
           "process_name - name of the target process\n"
           "         pid - id of the target process\n"
           "   dll_names - whitespace-separated paths to dlls to inject\n\n";
}
