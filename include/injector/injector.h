#pragma once

#include <string>
#include <vector>

namespace dll_injector {

struct Process {
    uint32_t pid;
    std::wstring name;
};

enum class DefaultInit : uint8_t { X64, X32 };

class Injector {
  public:
    // Constructs an object using the address of the LoadLibraryW function
    // previously loaded into the process context which is then assigned to the
    // private member address based on the default_init parameter.
    Injector(DefaultInit default_init);

    // The same as Injector(DefaultInit::X64) but additionally assigns the
    // 32-bit private member address using a helper app. The helper app should
    // return the address of a 32-bit LoadLibraryW function using the exit code.
    Injector(const std::wstring &helper_path);

    // Constructs an object with provided addresses.
    Injector(uint64_t load_library_x64_addr, uint32_t load_library_x32_addr);

    // Injects a DLL using target process name.
    bool inject_dll(const std::wstring &process_name,
                    const std::wstring &dll) const;

    // Injects a DLL using target process ID.
    bool inject_dll(uint32_t pid, const std::wstring &dll) const;

    // Injects DLLs using target process name.
    bool inject_dlls(const std::wstring &process_name,
                     const std::vector<std::wstring> &dlls) const;

    // Injects DLLs using target process ID.
    bool inject_dlls(uint32_t pid, const std::vector<std::wstring> &dlls) const;

    // Returns the address of the 64-bit LoadLibraryW function.
    uint64_t get_load_library_x64_addr() const;

    // Returns the address of the 32-bit LoadLibraryW function.
    uint32_t get_load_library_x32_addr() const;

    // Returns processes found in the system.
    std::vector<Process> fetch_process_objects_all() const;

    // Returns processes found in the system which can be used as target
    // processes for injection.
    std::vector<Process> fetch_process_objects_available() const;

  private:
    // Stores a 64-bit address of the LoadLibraryW function.
    uint64_t load_library_x64_addr_;
    // Stores a 32-bit address of the LoadLibraryW function.
    uint32_t load_library_x32_addr_;
};

} // namespace dll_injector
