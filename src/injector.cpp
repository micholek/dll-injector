#include "injector/injector.h"

#include <algorithm>
#include <string>
#include <vector>
// clang-format off
#include <windows.h>
#include <tlhelp32.h> // include after windows.h
// clang-format on

static uint64_t get_default_addr() {
    return (uint64_t) GetProcAddress(GetModuleHandleA("kernel32"),
                                     "LoadLibraryW");
}

static uint32_t get_helper_addr(const std::wstring &helper_path) {
    if (helper_path.empty()) {
        return 0;
    }
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(helper_path.c_str(), nullptr, nullptr, nullptr, FALSE,
                        0, nullptr, nullptr, &si, &pi)) {
        return 0;
    }
    WaitForSingleObject(pi.hProcess, 1000);
    uint32_t addr = 0;
    if (!GetExitCodeProcess(pi.hProcess, (DWORD *) &addr)) {
        return 0;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return addr;
}

static std::vector<dll_injector::Process>
fetch_process_objects(bool (*valid_arch)(bool)) {
    std::vector<dll_injector::Process> objects;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return {};
    }
    PROCESSENTRY32W proc_entry;
    proc_entry.dwSize = sizeof(PROCESSENTRY32W);
    auto res = Process32FirstW(snapshot, &proc_entry);
    while (res) {
        const uint32_t process_id = proc_entry.th32ProcessID;
        HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
        if (process) {
            bool wow64;
            if (IsWow64Process(process, (BOOL *) &wow64) && valid_arch(wow64)) {
                objects.push_back({
                    .pid = process_id,
                    .name = proc_entry.szExeFile,
                });
            }
            CloseHandle(process);
        }
        res = Process32NextW(snapshot, &proc_entry);
    }
    CloseHandle(snapshot);
    return objects;
}

static uint32_t find_pid(const std::wstring &process_name,
                         const std::vector<dll_injector::Process> &processes) {
    const auto process_it =
        std::find_if(processes.cbegin(), processes.cend(),
                     [&process_name](const dll_injector::Process &process) {
                         return process.name == process_name;
                     });
    return process_it != processes.cend() ? process_it->pid : 0;
}

static bool inject(HANDLE process, uint64_t load_library_addr,
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

Injector::Injector(DefaultInit default_init) : Injector(0, 0) {
    const uint64_t default_addr = get_default_addr();
    if (default_init == DefaultInit::X64) {
        load_library_x64_addr_ = default_addr;
    } else {
        load_library_x32_addr_ = (uint32_t) default_addr;
    }
}

Injector::Injector(const std::wstring &helper_path)
    : Injector(get_default_addr(), get_helper_addr(helper_path)) {}

Injector::Injector(uint64_t load_library_x64_addr,
                   uint32_t load_library_x32_addr)
    : load_library_x64_addr_ {load_library_x64_addr},
      load_library_x32_addr_ {load_library_x32_addr} {}

bool Injector::inject_dll(const std::wstring &process_name,
                          const std::wstring &dll) const {
    const uint32_t pid =
        find_pid(process_name, fetch_process_objects_available());
    if (pid == 0) {
        return false;
    }
    return inject_dll(pid, dll);
}

bool Injector::inject_dll(uint32_t pid, const std::wstring &dll) const {
    return inject_dlls(pid, {dll});
}

bool Injector::inject_dlls(const std::wstring &process_name,
                           const std::vector<std::wstring> &dlls) const {
    const uint32_t pid =
        find_pid(process_name, fetch_process_objects_available());
    if (pid == 0) {
        return false;
    }
    return inject_dlls(pid, dlls);
}

bool Injector::inject_dlls(uint32_t pid,
                           const std::vector<std::wstring> &dlls) const {
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
    bool res = true;
    for (const std::wstring &dll : dlls) {
        if (!inject(process, load_library_addr, dll)) {
            res = false;
        }
    }
    CloseHandle(process);
    return res;
}

uint64_t Injector::get_load_library_x64_addr() const {
    return load_library_x64_addr_;
}

uint32_t Injector::get_load_library_x32_addr() const {
    return load_library_x32_addr_;
}

std::vector<Process> Injector::fetch_process_objects_all() const {
    return fetch_process_objects([](bool wow64) {
        (void) wow64;
        return true;
    });
}

std::vector<Process> Injector::fetch_process_objects_available() const {
    if (load_library_x64_addr_ && load_library_x32_addr_) {
        return fetch_process_objects_all();
    } else if (load_library_x64_addr_) {
        return fetch_process_objects([](bool wow64) { return !wow64; });
    } else {
        return fetch_process_objects([](bool wow64) { return wow64; });
    }
}

} // namespace dll_injector
