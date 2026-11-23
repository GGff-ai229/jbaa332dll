#include "injector.h"
#include "process.h"
#include <psapi.h>
#include <winternl.h>
#include <vector>

namespace inj {
namespace {

class MappedFile {
public:
    MappedFile() = default;
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    ~MappedFile() { close(); }

    bool open(const std::wstring& path) {
        close();
        file_ = CreateFileW(path.c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file_ == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER sz{};
        if (!GetFileSizeEx(file_, &sz) || sz.QuadPart <= 0) { close(); return false; }
        size_ = static_cast<size_t>(sz.QuadPart);

        map_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
        if (!map_) { close(); return false; }

        data_ = static_cast<const BYTE*>(MapViewOfFile(map_, FILE_MAP_READ, 0, 0, 0));
        if (!data_) { close(); return false; }
        return true;
    }

    void close() {
        if (data_) { UnmapViewOfFile(data_); data_ = nullptr; }
        if (map_) { CloseHandle(map_); map_ = nullptr; }
        if (file_ != INVALID_HANDLE_VALUE) { CloseHandle(file_); file_ = INVALID_HANDLE_VALUE; }
        size_ = 0;
    }

    const BYTE* data() const { return data_; }
    size_t size() const { return size_; }

private:
    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE map_ = nullptr;
    const BYTE* data_ = nullptr;
    size_t size_ = 0;
};

constexpr uint32_t kPeMagic = 0x00004550;

struct Headers {
    const BYTE* base = nullptr;
    size_t size = 0;
    uint32_t peOff = 0;
    WORD machine = 0;
    WORD sections = 0;
    size_t optOff = 0;
    WORD optSize = 0;
    WORD optMagic = 0;
    size_t secOff = 0;
};

bool ParseHeaders(const BYTE* b, size_t n, Headers* h) {
    if (!b || n < 0x40) return false;
    uint32_t peOff = *reinterpret_cast<const uint32_t*>(b + 0x3C);
    if (peOff < 0x40 || static_cast<size_t>(peOff) + 24 > n) return false;
    if (*reinterpret_cast<const uint32_t*>(b + peOff) != kPeMagic) return false;

    h->base = b;
    h->size = n;
    h->peOff = peOff;
    h->machine = *reinterpret_cast<const WORD*>(b + peOff + 4);
    h->sections = *reinterpret_cast<const WORD*>(b + peOff + 6);
    h->optSize = *reinterpret_cast<const WORD*>(b + peOff + 20);
    h->optOff = static_cast<size_t>(peOff) + 24;
    if (h->optOff + h->optSize > n || h->optSize < 96) return false;
    h->optMagic = *reinterpret_cast<const WORD*>(b + h->optOff);
    if (h->optMagic != 0x20B && h->optMagic != 0x10B) return false;
    h->secOff = h->optOff + h->optSize;
    if (h->secOff + static_cast<size_t>(h->sections) * 40 > n) return false;
    return true;
}

bool RvaToOffset(const Headers& h, uint32_t rva, size_t need, size_t* out) {
    for (WORD i = 0; i < h.sections; ++i) {
        size_t o = h.secOff + static_cast<size_t>(i) * 40;
        uint32_t vs = *reinterpret_cast<const uint32_t*>(h.base + o + 8);
        uint32_t va = *reinterpret_cast<const uint32_t*>(h.base + o + 12);
        uint32_t rs = *reinterpret_cast<const uint32_t*>(h.base + o + 16);
        uint32_t pr = *reinterpret_cast<const uint32_t*>(h.base + o + 20);
        uint32_t span = (vs > rs) ? vs : rs;
        if (rva >= va && rva < va + span) {
            uint64_t off = static_cast<uint64_t>(rva - va) + pr;
            if (off + need > h.size) return false;
            *out = static_cast<size_t>(off);
            return true;
        }
    }
    return false;
}

uint32_t DataDirRva(const Headers& h, int index) {
    size_t dd = h.optOff + (h.optMagic == 0x20B ? 112 : 96);
    size_t entry = dd + static_cast<size_t>(index) * 8;
    if (entry + 8 > h.size) return 0;
    return *reinterpret_cast<const uint32_t*>(h.base + entry);
}

std::uintptr_t ProcAddr(const wchar_t* module, const char* symbol) {
    HMODULE m = GetModuleHandleW(module);
    if (!m) return 0;
    return reinterpret_cast<std::uintptr_t>(GetProcAddress(m, symbol));
}

using NtCreateThreadEx_t = NTSTATUS(NTAPI*)(PHANDLE thread, ACCESS_MASK access, PVOID objAttr,
                                            HANDLE process, PVOID start, PVOID param,
                                            ULONG flags, SIZE_T zeroBits, SIZE_T stackSize,
                                            SIZE_T maxStackSize, PVOID attrList);

bool SpawnRemote(HANDLE proc, std::uintptr_t start, std::uintptr_t param, bool useNt,
                 DWORD* err, HANDLE* threadOut) {
    if (threadOut) *threadOut = nullptr;

    if (!useNt) {
        HANDLE t = CreateRemoteThread(proc, nullptr, 0,
                                      reinterpret_cast<LPTHREAD_START_ROUTINE>(start),
                                      reinterpret_cast<LPVOID>(param), 0, nullptr);
        if (t) {
            if (threadOut) *threadOut = t; else CloseHandle(t);
            return true;
        }
        *err = GetLastError();
        return false;
    }

    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    auto fn = nt ? reinterpret_cast<NtCreateThreadEx_t>(
                       GetProcAddress(nt, "NtCreateThreadEx"))
                 : nullptr;
    if (!fn) { *err = ERROR_PROC_NOT_FOUND; return false; }

    HANDLE t = nullptr;
    const NTSTATUS st = fn(&t, THREAD_ALL_ACCESS, nullptr, proc,
                           reinterpret_cast<PVOID>(start), reinterpret_cast<PVOID>(param),
                           0, 0, 0, 0, nullptr);
    if (st < 0 || !t) {
        *err = static_cast<DWORD>(st);
        return false;
    }
    if (threadOut) *threadOut = t; else CloseHandle(t);
    return true;
}

} // namespace

WORD PeMachine(const std::wstring& path) {
    MappedFile f;
    if (!f.open(path)) return 0;
    Headers h{};
    if (!ParseHeaders(f.data(), f.size(), &h)) return 0;
    return h.machine;
}

std::uint32_t ExportRva(const std::wstring& path, const char* exportName) {
    if (!exportName || !*exportName) return 0;
    MappedFile f;
    if (!f.open(path)) return 0;
    Headers h{};
    if (!ParseHeaders(f.data(), f.size(), &h)) return 0;

    const uint32_t expRva = DataDirRva(h, 0);
    if (!expRva) return 0;

    size_t expOff = 0;
    if (!RvaToOffset(h, expRva, 40, &expOff)) return 0;
    const BYTE* e = h.base + expOff;

    const uint32_t nameCount = *reinterpret_cast<const uint32_t*>(e + 24);
    const uint32_t funcCount = *reinterpret_cast<const uint32_t*>(e + 20);
    const uint32_t namesRva = *reinterpret_cast<const uint32_t*>(e + 32);
    const uint32_t ordRva = *reinterpret_cast<const uint32_t*>(e + 36);
    const uint32_t funcRva = *reinterpret_cast<const uint32_t*>(e + 28);
    if (!nameCount || !funcCount || nameCount > 65536 || funcCount > 65536) return 0;

    size_t namesOff = 0, ordOff = 0, funcOff = 0;
    if (!RvaToOffset(h, namesRva, nameCount * 4ull, &namesOff)) return 0;
    if (!RvaToOffset(h, ordRva, nameCount * 2ull, &ordOff)) return 0;
    if (!RvaToOffset(h, funcRva, funcCount * 4ull, &funcOff)) return 0;

    for (uint32_t i = 0; i < nameCount; ++i) {
        const uint32_t strRva = *reinterpret_cast<const uint32_t*>(h.base + namesOff + i * 4);
        size_t strOff = 0;
        if (!RvaToOffset(h, strRva, 1, &strOff)) continue;
        const char* s = reinterpret_cast<const char*>(h.base + strOff);
        const size_t room = h.size - strOff;
        size_t len = 0;
        while (len < room && s[len]) ++len;
        if (len >= room) continue;
        if (std::string(s, len) != exportName) continue;

        const uint16_t ord = *reinterpret_cast<const uint16_t*>(h.base + ordOff + i * 2);
        if (ord >= funcCount) return 0;
        return *reinterpret_cast<const uint32_t*>(h.base + funcOff + ord * 4);
    }
    return 0;
}

Launch StartLoadLibrary(HANDLE proc, const std::wstring& dllPath, bool useNt) {
    Launch r;
    const std::uintptr_t loadLib = ProcAddr(L"kernel32.dll", "LoadLibraryW");
    if (!loadLib) {
        r.stage = L"resolve LoadLibraryW";
        r.err = GetLastError();
        return r;
    }

    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* mem = VirtualAllocEx(proc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) {
        r.stage = L"VirtualAllocEx";
        r.err = GetLastError();
        return r;
    }

    if (!WriteProcessMemory(proc, mem, dllPath.c_str(), bytes, nullptr)) {
        r.stage = L"WriteProcessMemory";
        r.err = GetLastError();
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        return r;
    }

    DWORD err = 0;
    if (!SpawnRemote(proc, loadLib, reinterpret_cast<std::uintptr_t>(mem), useNt, &err, nullptr)) {
        r.stage = useNt ? L"NtCreateThreadEx" : L"CreateRemoteThread";
        r.err = err;
        VirtualFreeEx(proc, mem, 0, MEM_RELEASE);
        return r;
    }

    r.ok = true;
    r.argMem = mem;
    return r;
}

void ReleaseArg(HANDLE proc, void* argMem) {
    if (argMem) VirtualFreeEx(proc, argMem, 0, MEM_RELEASE);
}

bool WaitModule(HANDLE proc, const std::wstring& moduleFileName, DWORD timeoutMs) {
    const DWORD start = GetTickCount();
    for (;;) {
        if (px::RemoteModuleBase(proc, moduleFileName)) return true;
        if (GetTickCount() - start >= timeoutMs) return false;
        Sleep(50);
    }
}

bool WaitModuleGone(HANDLE proc, const std::wstring& moduleFileName, DWORD timeoutMs) {
    const DWORD start = GetTickCount();
    for (;;) {
        if (!px::RemoteModuleBase(proc, moduleFileName)) return true;
        if (GetTickCount() - start >= timeoutMs) return false;
        Sleep(50);
    }
}

bool FreeRemoteLibrary(HANDLE proc, std::uintptr_t moduleBase, bool useNt, DWORD* err) {
    const std::uintptr_t freeLib = ProcAddr(L"kernel32.dll", "FreeLibrary");
    if (!freeLib) { *err = GetLastError(); return false; }
    HANDLE t = nullptr;
    if (!SpawnRemote(proc, freeLib, moduleBase, useNt, err, &t)) return false;
    WaitForSingleObject(t, 5000);
    CloseHandle(t);
    return true;
}

bool CallRemoteExport(HANDLE proc, std::uintptr_t moduleBase, const std::wstring& dllPath,
                      const char* exportName, bool useNt, DWORD timeoutMs, DWORD* err) {
    // The export sits at the same RVA in the remote image as on disk, so the
    // local file is the authority for the address.
    const std::uint32_t rva = ExportRva(dllPath, exportName);
    if (!rva) { *err = ERROR_PROC_NOT_FOUND; return false; }

    HANDLE t = nullptr;
    if (!SpawnRemote(proc, moduleBase + rva, 0, useNt, err, &t)) return false;
    const DWORD wait = WaitForSingleObject(t, timeoutMs ? timeoutMs : 10000);
    CloseHandle(t);
    if (wait != WAIT_OBJECT_0) { *err = ERROR_TIMEOUT; return false; }
    return true;
}

} // namespace inj
