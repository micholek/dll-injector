#include <print>
// clang-format off
#include <windows.h>
#include <tlhelp32.h> // include after windows.h
// clang-format on

struct InjectCtx {
    HANDLE proc;
    FARPROC load_library_ptr;
    std::string dll_name;
};

void usage(const char *prog_name);
uint32_t get_pid(std::string process_name);
bool inject_dll(InjectCtx ctx);
FARPROC get_load_library_ptr();

void print_winapi_error(const char *func_name);

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 0;
    }
    std::string process_name {argv[1]};
    uint32_t pid = get_pid(process_name);
    if (pid == 0) {
        std::println("Could not find process {}", process_name);
        return 0;
    }
    std::println("{}: PID = {}", process_name, pid);

    const FARPROC load_library_ptr = get_load_library_ptr();
    if (load_library_ptr == 0) {
        std::println(stderr, "Could not get LoadLibraryA address");
        return -1;
    }
    std::println("LoadLibraryA address = {:#018x}",
                 (uintptr_t) load_library_ptr);

    HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (proc == nullptr) {
        print_winapi_error("OpenProcess");
        return -2;
    }

    InjectCtx ctx {.proc = proc, .load_library_ptr = load_library_ptr};
    for (int i = 2; i < argc; i++) {
        ctx.dll_name = std::string {argv[i]};
        if (!inject_dll(ctx)) {
            std::println(stderr, "Injecting {} failed", ctx.dll_name);
            continue;
        }
        std::println("Injected {}", ctx.dll_name);
    }

    CloseHandle(proc);
    return 0;
}

void usage(const char *prog_name) {
    std::print("Usage: {} <process_name> <dll_names>\n"
               "process_name - target which dlls are to be injected to\n"
               "   dll_names - whitespace-seperated paths to dlls to inject\n",
               prog_name);
}

uint32_t get_pid(std::string process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        print_winapi_error("CreateToolhelp32Snapshot");
        return 0;
    }
    PROCESSENTRY32 proc_entry;
    auto res = Process32First(snapshot, &proc_entry);
    while (res) {
        if (process_name == proc_entry.szExeFile) {
            break;
        }
        res = Process32Next(snapshot, &proc_entry);
    }
    CloseHandle(snapshot);
    return res ? proc_entry.th32ProcessID : 0;
}

FARPROC get_load_library_ptr() {
    HMODULE kernel32 = GetModuleHandleA("kernel32");
    if (kernel32 == nullptr) {
        print_winapi_error("GetModuleHandleA");
        return nullptr;
    }
    FARPROC load_library_addr = GetProcAddress(kernel32, "LoadLibraryA");
    if (load_library_addr == nullptr) {
        print_winapi_error("GetProcAddress");
    }
    return load_library_addr;
}

bool inject_dll(InjectCtx ctx) {
    void *dll_name_addr =
        VirtualAllocEx(ctx.proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                       PAGE_EXECUTE_READWRITE);
    if (dll_name_addr == nullptr) {
        print_winapi_error("VirtualAllocEx");
        return false;
    }
    std::println("Memory allocated at {:#018x} for \"{}\" string",
                 (uintptr_t) dll_name_addr, ctx.dll_name);
    if (WriteProcessMemory(ctx.proc, dll_name_addr, ctx.dll_name.c_str(),
                           ctx.dll_name.length(), nullptr) == 0) {
        print_winapi_error("WriteProcessMemory");
        return false;
    }
    HANDLE thread = CreateRemoteThread(
        ctx.proc, nullptr, 0, (LPTHREAD_START_ROUTINE) ctx.load_library_ptr,
        dll_name_addr, 0, nullptr);
    if (thread == nullptr) {
        print_winapi_error("CreateRemoteThread");
        return false;
    }
    CloseHandle(thread);
    return true;
}

void print_winapi_error(const char *func_name) {
    std::println(stderr, "{} failed, error: {}", func_name, GetLastError());
}
