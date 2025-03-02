#include "peb.h"

class memory {
	memory() : oldvp(0) {}
	DWORD oldvp;

	std::map<uint32_t, uint8_t> original;

public:

	static auto get() -> memory& {
		static memory instance;
		return instance;
	}

    template<class T>
    inline auto write_memory(uintptr_t addr, const T& value, bool vp = true) -> bool
    {
        DWORD oldProtect;
        if (VirtualProtect(reinterpret_cast<void*>(addr), sizeof(value), PAGE_READWRITE, &oldProtect)) {
            std::memcpy(reinterpret_cast<void*>(addr), (const void*)&value, sizeof(value));
            VirtualProtect(reinterpret_cast<void*>(addr), sizeof(value), oldProtect, &oldProtect);
            return true;
        }

        return false;
    }

    template<class T>
    inline auto read_memory(uintptr_t addr, bool vp = true) -> T
    {
        T value;
        DWORD oldProtect;
        if (vp && VirtualProtect(reinterpret_cast<void*>(addr), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            value = *reinterpret_cast<T*>(addr);
            VirtualProtect(reinterpret_cast<void*>(addr), sizeof(T), oldProtect, &oldProtect);
            return value;
        }

        return *reinterpret_cast<T*>(addr);
    }

    auto find_return_addr_offset(uint32_t address, uint32_t return_address) noexcept -> uint32_t {
        for (int index = 0u; index != 20u; ++index) {
            if (memory::get().read_memory<uint32_t>(address + index * sizeof(uint32_t)) == return_address) {
                return index;
            }
        }
        return 0u;
    }

    std::uint8_t* pattern_scan_memory(const char* signature)
    {
        static auto pattern_to_byte = [](const char* pattern) {
            auto bytes = std::vector<int>{};
            auto start = const_cast<char*>(pattern);
            auto end = const_cast<char*>(pattern) + strlen(pattern);

            for (auto current = start; current < end; ++current) {
                if (*current == '?') {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }
            return bytes;
            };

        auto patternBytes = pattern_to_byte(signature);
        auto s = patternBytes.size();
        auto d = patternBytes.data();

        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        LPVOID currentAddress = sysInfo.lpMinimumApplicationAddress;
        LPVOID maxAddress = sysInfo.lpMaximumApplicationAddress;

        while (currentAddress < maxAddress) {
            MEMORY_BASIC_INFORMATION memInfo;
            if (!VirtualQuery(currentAddress, &memInfo, sizeof(memInfo))) {
                break;
            }

            if (memInfo.State == MEM_COMMIT &&
                (memInfo.Protect & PAGE_READWRITE ||
                    memInfo.Protect & PAGE_EXECUTE_READ ||
                    memInfo.Protect & PAGE_EXECUTE_READWRITE)) {

                auto scanBytes = reinterpret_cast<std::uint8_t*>(memInfo.BaseAddress);
                auto regionSize = memInfo.RegionSize;

                for (size_t i = 0; i < regionSize - s; ++i) {
                    bool found = true;

                    if (IsBadReadPtr(&scanBytes[i], s)) {
                        break;
                    }

                    for (auto j = 0ul; j < s; ++j) {
                        if (scanBytes[i + j] != d[j] && d[j] != -1) {
                            found = false;
                            break;
                        }
                    }

                    if (found) {
                        return &scanBytes[i];
                    }
                }
            }

            currentAddress = (LPVOID)((DWORD_PTR)memInfo.BaseAddress + memInfo.RegionSize);
        }

        return nullptr;
    }

    std::uint8_t* pattern_scan_module(const std::wstring& module_name, const char* signature)
    {
        auto module = get_module_base(module_name);

        if (module == 0) {
            return nullptr;
        }

        static auto pattern_to_byte = [](const char* pattern) {
            auto bytes = std::vector<int>{};
            auto start = const_cast<char*>(pattern);
            auto end = const_cast<char*>(pattern) + strlen(pattern);

            for (auto current = start; current < end; ++current) {
                if (*current == '?') {
                    ++current;
                    if (*current == '?')
                        ++current;
                    bytes.push_back(-1);
                }
                else {
                    bytes.push_back(strtoul(current, &current, 16));
                }
            }
            return bytes;
            };

        auto dosHeader = (PIMAGE_DOS_HEADER)module;
        auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t*)module + dosHeader->e_lfanew);

        auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
        auto patternBytes = pattern_to_byte(signature);
        auto scanBytes = reinterpret_cast<std::uint8_t*>(module);

        auto s = patternBytes.size();
        auto d = patternBytes.data();

        for (auto i = 0ul; i < sizeOfImage - s; ++i) {
            bool found = true;
            for (auto j = 0ul; j < s; ++j) {
                if (scanBytes[i + j] != d[j] && d[j] != -1) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return &scanBytes[i];
            }
        }
        return nullptr;
    }

    uint32_t get_module_base(const std::wstring& module_name) {
        PEB2* peb = (PPEB2)__readfsdword(0x30);
        auto* ldr = (PPEB_LDR_DATA2)peb->Ldr;

        for (auto* dte = (LDR_DATA_TABLE_ENTRY2*)ldr->InLoadOrderModuleList.Flink;
            dte->DllBase != nullptr;
            dte = (LDR_DATA_TABLE_ENTRY2*)dte->InLoadOrderLinks.Flink) {

            std::wstring_view base_module_name(dte->BaseDllName.Buffer, dte->BaseDllName.Length / sizeof(wchar_t));

            if (module_name == base_module_name)
                return (uint32_t)dte->DllBase;
        }

        return 0;
    }

	std::vector<uint32_t*> scan_dword(uint32_t value)
	{
		SYSTEM_INFO systemInfo;
		GetSystemInfo(&systemInfo);

		MEMORY_BASIC_INFORMATION memInfo;
		uint8_t* addr = 0;
		uint8_t* maxAddr = (uint8_t*)systemInfo.lpMaximumApplicationAddress;

		std::vector<uint32_t*> addresses;

		while (addr < maxAddr) {
			if (VirtualQuery(addr, &memInfo, sizeof(memInfo)) == sizeof(memInfo)) {
				if (memInfo.State == MEM_COMMIT && (memInfo.Protect == PAGE_READWRITE || memInfo.Protect == PAGE_READONLY)) {
					uint32_t* memRegionStart = (uint32_t*)memInfo.BaseAddress;
					uint32_t* memRegionEnd = (uint32_t*)((char*)memInfo.BaseAddress + memInfo.RegionSize);

					for (uint32_t* pCurrent = memRegionStart; pCurrent < memRegionEnd; ++pCurrent)
						if (*pCurrent == value)
							addresses.push_back(pCurrent);
				}
			}
			addr += memInfo.RegionSize;
		}

		return addresses;
	}

    void make_jmp(BYTE* pAddress, DWORD dwJumpTo, DWORD dwLen)
    {
        DWORD dwOldProtect, dwBkup, dwRelAddr;
        VirtualProtect(pAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOldProtect);
        dwRelAddr = (DWORD)(dwJumpTo - (DWORD)pAddress) - 5;
        *pAddress = 0xE9;
        *((DWORD*)(pAddress + 0x1)) = dwRelAddr;
        for (DWORD x = 0x5; x < dwLen; x++) *(pAddress + x) = 0x90;
        VirtualProtect(pAddress, dwLen, dwOldProtect, &dwBkup);
        return;
    }

    auto make_patch_jmp(uint32_t address, uint32_t jump_addr, uint32_t length = 6) const noexcept -> void
    {
        byte* address_ptr = reinterpret_cast<byte*>(address);

        DWORD old_protect;
        VirtualProtect(address_ptr, length, PAGE_EXECUTE_READWRITE, &old_protect);

        *address_ptr = 0x68;
        *(address_ptr + 0x5) = 0xC3;
        *((uint32_t*)(address_ptr + 0x1)) = jump_addr;

        for (DWORD x = 0x6; x < length; x++) {
            *(address_ptr + x) = 0x90;
        }

        VirtualProtect(address_ptr, length, old_protect, &old_protect);
    }

    auto follow_chain(uint32_t base, const std::vector<uint32_t>& offsets) noexcept -> uint32_t {

        for (const auto& offset : offsets) {
            base = read_memory<uint32_t>(base + offset);
        }

        return base;
    }

    auto get_function_addr_vtable(uint32_t base, const std::vector<uint32_t>& offsets, uint32_t function_offset) const noexcept -> uint32_t {
        return memory::get().follow_chain(base, offsets) + function_offset;
    }
};