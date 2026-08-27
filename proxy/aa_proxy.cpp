// Lineage 2 client loads this dll from its own `system` folder.
//
// ProxyDLL forwards every export to the real system DLL. On top of
// that we spawn one thread that scans the client for the live
// ActiveAnticheatCrypt RSA context and hands the (modulus, private exponent)
// back to decoder over a named pipe.

#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "UltimateProxyDLL.h"

namespace {

constexpr SIZE_T kContextSize = 0x78;
constexpr SIZE_T kChunkSize = 4u * 1024u * 1024u;
constexpr SIZE_T kOverlap = kContextSize - 1;
constexpr SIZE_T kMaxRegionSize = 128u * 1024u * 1024u;
constexpr SIZE_T kMaxMpiBytes = 256;

// Modulus and private exponent as raw little-endian limbs, byte-for-byte as
// they sit in the client's memory -- exactly the `N_LE=` / `D_LE=` values the
// old aac_rsa.log carried.
struct RsaKey {
    std::vector<uint8_t> n_le;
    std::vector<uint8_t> d_le;
};

uint16_t ReadU16(const uint8_t* p, size_t at) {
    return static_cast<uint16_t>(p[at] | (p[at + 1] << 8));
}

uint32_t ReadU32(const uint8_t* p, size_t at) {
    return static_cast<uint32_t>(p[at]) | (static_cast<uint32_t>(p[at + 1]) << 8) |
           (static_cast<uint32_t>(p[at + 2]) << 16) | (static_cast<uint32_t>(p[at + 3]) << 24);
}

// Read `len` bytes from our own process.
bool ReadExact(uintptr_t address, uint8_t* out, size_t len) {
    SIZE_T read = 0;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), out, len,
                             &read) &&
           read == len;
}

bool DescriptorMatches(const uint8_t* ctx, size_t offset, uint16_t expected) {
    return ReadU16(ctx, offset + 4) == 1 && ReadU16(ctx, offset + 6) == expected;
}

// The 0x78-byte fingerprint of the RSA context we are after: a 0x100-byte
// modulus and the expected limb counts for each MPI descriptor.
bool ContextMatches(const uint8_t* ctx) {
    return ReadU32(ctx, 4) == 0x100 && DescriptorMatches(ctx, 0x08, 64) &&
           DescriptorMatches(ctx, 0x10, 1) && DescriptorMatches(ctx, 0x18, 64) &&
           DescriptorMatches(ctx, 0x20, 32) && DescriptorMatches(ctx, 0x28, 32) &&
           DescriptorMatches(ctx, 0x30, 32) && DescriptorMatches(ctx, 0x38, 32) &&
           DescriptorMatches(ctx, 0x40, 32);
}

// Follow one MPI descriptor and copy its limbs out of memory.
bool ReadMpi(const uint8_t* ctx, size_t offset, std::vector<uint8_t>& out) {
    uintptr_t pointer = ReadU32(ctx, offset);
    size_t limbs = ReadU16(ctx, offset + 6);
    size_t size = limbs * 4;
    if (pointer == 0 || size == 0 || size > kMaxMpiBytes) {
        return false;
    }
    out.assign(size, 0);
    return ReadExact(pointer, out.data(), size);
}

bool ExtractKey(const uint8_t* ctx, RsaKey& key) {
    return ReadMpi(ctx, 0x08, key.n_le) && ReadMpi(ctx, 0x18, key.d_le);
}

bool IsReadable(DWORD protect) {
    if (protect & (PAGE_GUARD | PAGE_NOACCESS)) {
        return false;
    }
    switch (protect & 0xFF) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
    }
}

// Sweep one committed region, reading it in overlapping chunks so a context
// straddling a chunk boundary is still found.
bool ScanRegion(uintptr_t base, size_t size, RsaKey& key) {
    std::vector<uint8_t> buffer(kChunkSize + kOverlap);
    size_t offset = 0;
    while (offset < size) {
        size_t remaining = size - offset;
        size_t wanted = remaining < buffer.size() ? remaining : buffer.size();
        SIZE_T read = 0;
        if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(base + offset),
                              buffer.data(), wanted, &read) &&
            read >= kContextSize) {
            for (size_t local = 0; local + kContextSize <= read; local += 4) {
                const uint8_t* ctx = buffer.data() + local;
                if (ContextMatches(ctx) && ExtractKey(ctx, key)) {
                    return true;
                }
            }
        }
        if (remaining <= kChunkSize) {
            break;
        }
        offset += kChunkSize;
    }
    return false;
}

// Walk every committed, readable region of our own process. Returns the first
// key that fully resolves.
bool FindRsaKey(RsaKey& key) {
    SYSTEM_INFO info{};
    GetSystemInfo(&info);
    uintptr_t cursor = reinterpret_cast<uintptr_t>(info.lpMinimumApplicationAddress);
    uintptr_t maximum = reinterpret_cast<uintptr_t>(info.lpMaximumApplicationAddress);
    while (cursor < maximum) {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &region, sizeof(region)) !=
            sizeof(region)) {
            break;
        }
        uintptr_t regionBase = reinterpret_cast<uintptr_t>(region.BaseAddress);
        uintptr_t next = regionBase + region.RegionSize;
        if (next <= cursor) {
            break;
        }
        if (region.State == MEM_COMMIT && IsReadable(region.Protect) &&
            region.RegionSize >= kContextSize && region.RegionSize <= kMaxRegionSize) {
            if (ScanRegion(regionBase, region.RegionSize, key)) {
                return true;
            }
        }
        cursor = next;
    }
    return false;
}

std::string ToHex(const std::vector<uint8_t>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0F]);
    }
    return out;
}

void SendKey(const RsaKey& key) {
    wchar_t name[256];
    DWORD len = GetEnvironmentVariableW(L"AA_DECODER_PIPE", name, 256);
    if (len == 0 || len >= 256) {
        return;
    }
    std::string message = "N_LE=" + ToHex(key.n_le) + "\r\nD_LE=" + ToHex(key.d_le) + "\r\n";
    HANDLE pipe = CreateFileW(name, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return;
    }
    DWORD written = 0;
    WriteFile(pipe, message.data(), static_cast<DWORD>(message.size()), &written, nullptr);
    CloseHandle(pipe);
}

DWORD WINAPI CaptureThread(LPVOID) {
    // The RSA context only exists once the client has finished start-up, so the
    // first sweeps usually miss; poll with tight interval to avoid worst-case.
    for (int attempt = 0; attempt < 60; ++attempt) {
        RsaKey key;
        if (FindRsaKey(key)) {
            SendKey(key);
            return 0;
        }
        Sleep(200);
    }
    return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    (void)lpReserved;
    if (fdwReason == DLL_PROCESS_ATTACH) {
#if !AA_PROXY_ENABLE_DEBUG_LOG
        UPD::MuteLogging(true);
#endif
        UPD::CreateProxy(hinstDLL);
        HANDLE thread = CreateThread(nullptr, 0, &CaptureThread, nullptr, 0, nullptr);
        if (thread) {
            CloseHandle(thread);
        }
    }
    return TRUE;
}
