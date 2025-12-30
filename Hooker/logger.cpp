// logger.cpp
#include "pch.h"
#include "logger.hpp"
#include <windows.h>
#include <evntprov.h>        // For ETW
#include <string>
#include <mutex>

namespace Logger {
    HANDLE hPipe = INVALID_HANDLE_VALUE;
    std::string processName;
    DWORD processId = 0;

    // === ETW SECTION ===
    // Generate your own GUID! (Use 'uuidgen' or online generator)
    // This is HealEDR's provider GUID
    static const GUID HealEDR_ETW_Provider = 
    { 0x1a2b3c4d, 0x5e6f, 0x7a8b, { 0x9c, 0x0d, 0x1e, 0x2f, 0x3a, 0x4b, 0x5c, 0x6d } };

    REGHANDLE g_EtwRegHandle = 0;
    bool g_EtwInitialized = false;
    std::once_flag g_EtwInitFlag;

    void InitializeETW() {
        std::call_once(g_EtwInitFlag, []() {
            ULONG status = EventRegister(&HealEDR_ETW_Provider, NULL, NULL, &g_EtwRegHandle);
            g_EtwInitialized = (status == ERROR_SUCCESS);
        });
    }

    void EmitETWEvent(const std::string& message) {
        if (!g_EtwInitialized) return;

        // Split message into structured fields if you want later!
        // For now, send as a single UTF-16 string (ETW prefers WCHAR)
        int len = MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1, NULL, 0);
        if (len <= 0) return;

        std::wstring wmsg(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1, &wmsg[0], len);

        EVENT_DATA_DESCRIPTOR desc;
        EventDataDescCreate(&desc, wmsg.c_str(), (ULONG)(wmsg.size() * sizeof(WCHAR)));

        // Event ID = 1 (you can define more later)
        // Keyword = 0x1 (custom category), Level = 4 (INFO)
        EventWrite(g_EtwRegHandle, /* EventDescriptor = */ nullptr, 1, &desc);
    }
    // === END ETW ===

    void GetCurrentProcessInfo(std::string& processName, DWORD& processId) {
        processId = GetCurrentProcessId();
        char path[MAX_PATH];
        if (GetModuleFileNameA(NULL, path, MAX_PATH)) {
            char* name = strrchr(path, '\\');
            processName = name ? (name + 1) : path;
        } else {
            processName = "Unknown";
        }
    }

    bool EnsurePipeConnection() {
        if (hPipe != INVALID_HANDLE_VALUE)
            return true;

        for (int i = 0; i < 3; ++i) {
            hPipe = CreateFileA(
                "\\\\.\\pipe\\HookPipe",
                GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (hPipe != INVALID_HANDLE_VALUE)
                return true;
            Sleep(500);
        }
        return false;
    }

    void LogMessage(const std::string& message) {
        // Initialize process info if not done
        if (processId == 0)
            GetCurrentProcessInfo(processName, processId);

        // Emit to ETW (fast, async, zero-cost if no listener)
        EmitETWEvent(message);

        // Fallback to pipe (your original logic)
        if (!EnsurePipeConnection()) {
            std::string fallback = "[FALLBACK] " + message;
            OutputDebugStringA(fallback.c_str());
            return;
        }

        std::string fullMsg = "Process: " + processName +
                             " | PID: " + std::to_string(processId) +
                             " | " + message + "\n";

        DWORD written;
        WriteFile(hPipe, fullMsg.c_str(), (DWORD)fullMsg.size(), &written, NULL);
    }

    void Cleanup() {
        if (hPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(hPipe);
            hPipe = INVALID_HANDLE_VALUE;
        }

        // Unregister ETW provider (good practice)
        if (g_EtwInitialized) {
            EventUnregister(g_EtwRegHandle);
            g_EtwInitialized = false;
        }
    }
}
