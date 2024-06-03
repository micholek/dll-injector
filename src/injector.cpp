#include "injector/injector.h"

#include <string>
#include <vector>
// clang-format off
#include <windows.h>
#include <tlhelp32.h> // include after windows.h
// clang-format on

static bool inject_dll(HANDLE process, uint64_t load_library_addr,
                       const std::wstring &dll) {
    void *dll_name_addr =
        VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (dll_name_addr == nullptr) {
        return false;
    }
    if (WriteProcessMemory(process, dll_name_addr, dll.c_str(),
                           dll.length() * sizeof(wchar_t), nullptr) == 0) {
        return false;
    }
    HANDLE thread = CreateRemoteThread(
        process, nullptr, 0, (LPTHREAD_START_ROUTINE) load_library_addr,
        dll_name_addr, 0, nullptr);
    if (thread == nullptr) {
        return false;
    }
    CloseHandle(thread);
    return true;
}

namespace dll_injector {

std::vector<ProcessInfo> get_process_info_values() {
    std::vector<ProcessInfo> values;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return {};
    }
    PROCESSENTRY32W proc_entry;
    proc_entry.dwSize = sizeof(PROCESSENTRY32W);
    auto res = Process32FirstW(snapshot, &proc_entry);
    while (res) {
        values.push_back({ // 
            .pid = proc_entry.th32ProcessID,
            .name = proc_entry.szExeFile,
        });
        res = Process32NextW(snapshot, &proc_entry);
    }
    CloseHandle(snapshot);
    return values;
}

Injector::Injector(uint64_t load_library_x64_addr,
                   uint32_t load_library_x32_addr)
    : load_library_x64_addr_ {load_library_x64_addr},
      load_library_x32_addr_ {load_library_x32_addr} {}

bool Injector::inject_multiple_dlls(
    uint32_t pid, const std::vector<std::wstring> &dlls) const {
    if (!pid) {
        return false;
    }
    HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (process == nullptr) {
        return false;
    }
    BOOL wow64_process;
    if (!IsWow64Process(process, &wow64_process)) {
        return false;
    }
    uint64_t load_library_addr =
        wow64_process ? load_library_x32_addr_ : load_library_x64_addr_;
    if (!load_library_addr) {
        return false;
    }
    uint32_t injected_dlls_count = 0;
    for (const std::wstring &dll : dlls) {
        if (!inject_dll(process, load_library_addr, dll)) {
            continue;
        }
        injected_dlls_count++;
    }
    CloseHandle(process);
    return injected_dlls_count == dlls.size();
}

uint64_t Injector::get_load_library_x64_addr() const {
    return load_library_x64_addr_;
}

uint32_t Injector::get_load_library_x32_addr() const {
    return load_library_x32_addr_;
}

} // namespace dll_injector
