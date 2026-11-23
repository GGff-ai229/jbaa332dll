#pragma once
#include <windows.h>
#include <cstdint>
#include <string>

namespace inj {

struct Launch {
    bool ok = false;
    DWORD err = 0;
    std::wstring stage;
    void* argMem = nullptr;   // remote allocation holding the DLL path
};

// Resolves and creates the remote LoadLibraryW call. Does not wait for the load.
Launch StartLoadLibrary(HANDLE proc, const std::wstring& dllPath, bool useNt);

// Frees the remote path buffer once the load has finished (or failed).
void ReleaseArg(HANDLE proc, void* argMem);

// Polls the module list until the module shows up.
bool WaitModule(HANDLE proc, const std::wstring& moduleFileName, DWORD timeoutMs);
bool WaitModuleGone(HANDLE proc, const std::wstring& moduleFileName, DWORD timeoutMs);

bool FreeRemoteLibrary(HANDLE proc, std::uintptr_t moduleBase, bool useNt, DWORD* err);
bool CallRemoteExport(HANDLE proc, std::uintptr_t moduleBase, const std::wstring& dllPath,
                      const char* exportName, bool useNt, DWORD timeoutMs, DWORD* err);

// Local PE reads, used to sanity-check the DLL before it goes anywhere.
WORD PeMachine(const std::wstring& path);
std::uint32_t ExportRva(const std::wstring& path, const char* exportName); // 0 on miss

} // namespace inj
