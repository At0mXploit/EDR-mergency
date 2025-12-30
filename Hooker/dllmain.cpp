// dllmain.cpp
// User-mode EDR hooking DLL using MinHook
// Detects common process injection techniques

#include "pch.h"

// Proper NTSTATUS constant definitions
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>      // NTSTATUS + NT API types
#include <ntstatus.h>      // Defines STATUS_ACCESS_DENIED and other NTSTATUS codes
#include <iostream>
#include <unordered_map>

#include "MinHook.h"       // MinHook API
#include "logger.hpp"      // Custom logger

// =======================================================
// GLOBAL STATE
// =======================================================

// Indicates whether hooks are active and enforcement is enabled
BOOL hooked = FALSE;

// =======================================================
// PROCESS TRACKING STRUCTURES
// =======================================================

// Tracks suspicious behavior per process (basic injection chain)
struct ProcessTrackingInfo {
    bool allocatedExecutableMemory = false;  // RWX or executable allocation detected
    bool wroteToExecutableMemory   = false;  // Write into executable memory detected
    PVOID  allocatedBaseAddress    = nullptr;
    SIZE_T allocatedRegionSize     = 0;
};

// PID -> tracking info
static std::unordered_map<DWORD, ProcessTrackingInfo> processTrackingMap;

// =======================================================
// ORIGINAL NT / WIN32 FUNCTION TYPEDEFS
// =======================================================

// NtAllocateVirtualMemory
typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

// NtProtectVirtualMemory
typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect);

// NtWriteVirtualMemory
typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten);

// CreateRemoteThread
typedef HANDLE (WINAPI* pCreateRemoteThread)(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

// OpenProcess
typedef HANDLE (WINAPI* pOpenProcess)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId);

// =======================================================
// POINTERS TO ORIGINAL FUNCTIONS
// =======================================================

static pNtAllocateVirtualMemory pOriginalNtAllocateVirtualMemory = nullptr;
static pNtProtectVirtualMemory  pOriginalNtProtectVirtualMemory  = nullptr;
static pNtWriteVirtualMemory    pOriginalNtWriteVirtualMemory    = nullptr;
static pCreateRemoteThread      pOriginalCreateRemoteThread      = nullptr;
static pOpenProcess             pOriginalOpenProcess             = nullptr;

// =======================================================
// HELPER FUNCTIONS
// =======================================================

// Safely resolve a PID from a process handle
// Handles pseudo-handles like GetCurrentProcess()
static DWORD ResolvePid(HANDLE hProcess)
{
    if (hProcess == NULL || hProcess == GetCurrentProcess())
        return GetCurrentProcessId();

    return GetProcessId(hProcess);
}

// =======================================================
// HOOKED API IMPLEMENTATIONS
// =======================================================

// -------------------------------------------------------
// NtAllocateVirtualMemory
// Detects executable memory allocation (RWX)
// -------------------------------------------------------
NTSTATUS NTAPI HookedNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect)
{
    if (hooked && Protect == PAGE_EXECUTE_READWRITE) {
        DWORD pid = ResolvePid(ProcessHandle);

        Logger::LogMessage(
            "NtAllocateVirtualMemory with PAGE_EXECUTE_READWRITE pid=" +
            std::to_string(pid));

        // Block allocation in remote processes (EDR enforcement)
        if (pid != GetCurrentProcessId()) {
            Logger::LogMessage("Blocked executable memory allocation");
            return STATUS_ACCESS_DENIED;  // Now properly defined
        }

        // Track allocation for injection chain detection
        processTrackingMap[pid].allocatedExecutableMemory = true;
    }

    // Call original API
    return pOriginalNtAllocateVirtualMemory(
        ProcessHandle,
        BaseAddress,
        ZeroBits,
        RegionSize,
        AllocationType,
        Protect);
}

// -------------------------------------------------------
// NtProtectVirtualMemory
// Detects protection changes to executable memory
// -------------------------------------------------------
NTSTATUS NTAPI HookedNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect)
{
    if (hooked && NewProtect == PAGE_EXECUTE_READWRITE) {
        DWORD pid = ResolvePid(ProcessHandle);

        Logger::LogMessage(
            "NtProtectVirtualMemory changed to executable pid=" +
            std::to_string(pid));

        processTrackingMap[pid].allocatedExecutableMemory = true;
    }

    return pOriginalNtProtectVirtualMemory(
        ProcessHandle,
        BaseAddress,
        RegionSize,
        NewProtect,
        OldProtect);
}

// -------------------------------------------------------
// NtWriteVirtualMemory
// Detects shellcode write into executable memory
// -------------------------------------------------------
NTSTATUS NTAPI HookedNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten)
{
    if (hooked) {
        DWORD pid = ResolvePid(ProcessHandle);

        auto& info = processTrackingMap[pid];
        if (info.allocatedExecutableMemory) {
            Logger::LogMessage(
                "NtWriteVirtualMemory to executable memory pid=" +
                std::to_string(pid));

            info.wroteToExecutableMemory = true;
        }
    }

    return pOriginalNtWriteVirtualMemory(
        ProcessHandle,
        BaseAddress,
        Buffer,
        NumberOfBytesToWrite,
        NumberOfBytesWritten);
}

// -------------------------------------------------------
// CreateRemoteThread
// Final stage of classic process injection
// -------------------------------------------------------
HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId)
{
    if (hooked) {
        DWORD pid = ResolvePid(hProcess);
        auto& info = processTrackingMap[pid];

        // Injection chain detected → block execution
        if (info.allocatedExecutableMemory &&
            info.wroteToExecutableMemory) {

            Logger::LogMessage(
                "Blocked CreateRemoteThread pid=" +
                std::to_string(pid));
            return NULL;
        }
    }

    return pOriginalCreateRemoteThread(
        hProcess,
        lpThreadAttributes,
        dwStackSize,
        lpStartAddress,
        lpParameter,
        dwCreationFlags,
        lpThreadId);
}

// -------------------------------------------------------
// OpenProcess
// Detects suspicious PROCESS_ALL_ACCESS usage
// -------------------------------------------------------
HANDLE WINAPI HookedOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId)
{
    if (hooked && (dwDesiredAccess & PROCESS_ALL_ACCESS)) {
        Logger::LogMessage(
            "OpenProcess(PROCESS_ALL_ACCESS) pid=" +
            std::to_string(dwProcessId));
    }

    return pOriginalOpenProcess(
        dwDesiredAccess,
        bInheritHandle,
        dwProcessId);
}

// =======================================================
// HOOK INITIALIZATION
// =======================================================

void InitializeHooks()
{
    // Initialize MinHook
    if (MH_Initialize() != MH_OK) {
        Logger::LogMessage("MinHook initialization failed");
        return;
    }

    // NTDLL hooks — cast detour functions to LPVOID
    MH_CreateHookApi(L"ntdll", "NtAllocateVirtualMemory",
        (LPVOID)&HookedNtAllocateVirtualMemory,
        (LPVOID*)&pOriginalNtAllocateVirtualMemory);

    MH_CreateHookApi(L"ntdll", "NtProtectVirtualMemory",
        (LPVOID)&HookedNtProtectVirtualMemory,
        (LPVOID*)&pOriginalNtProtectVirtualMemory);

    MH_CreateHookApi(L"ntdll", "NtWriteVirtualMemory",
        (LPVOID)&HookedNtWriteVirtualMemory,
        (LPVOID*)&pOriginalNtWriteVirtualMemory);

    // Kernel32 hooks
    MH_CreateHookApi(L"kernel32", "CreateRemoteThread",
        (LPVOID)&HookedCreateRemoteThread,
        (LPVOID*)&pOriginalCreateRemoteThread);

    MH_CreateHookApi(L"kernel32", "OpenProcess",
        (LPVOID)&HookedOpenProcess,
        (LPVOID*)&pOriginalOpenProcess);

    // Enable all hooks
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        Logger::LogMessage("Failed to enable hooks");
        return;
    }

    hooked = TRUE;
    Logger::LogMessage("Hooks installed successfully");
}

// =======================================================
// DLL ENTRY POINT
// =======================================================

BOOL APIENTRY DllMain(
    HMODULE hModule,
    DWORD reason,
    LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        // Prevent thread attach spam
        DisableThreadLibraryCalls(hModule);

        Logger::LogMessage("Injected into process");
        InitializeHooks();
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (hooked) {
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
        Logger::Cleanup();
    }

    return TRUE;
}


