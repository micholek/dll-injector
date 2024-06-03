#pragma once

#include <string>
#include <vector>

namespace dll_injector {

struct ProcessInfo {
    uint32_t pid;
    std::wstring name;
};

std::vector<ProcessInfo> get_process_info_values();

class Injector {
  public:
    Injector(uint64_t load_library_x64_addr, uint32_t load_library_x32_addr);
    bool inject_multiple_dlls(uint32_t pid,
                              const std::vector<std::wstring> &dlls) const;

    uint64_t get_load_library_x64_addr() const;
    uint32_t get_load_library_x32_addr() const;

  private:
    uint64_t load_library_x64_addr_;
    uint32_t load_library_x32_addr_;
};

} // namespace dll_injector
