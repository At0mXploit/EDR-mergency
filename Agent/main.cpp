#include <stdio.h>
#include <windows.h>
#include <fstream>
#include <thread>
#include <iostream>
#include <filesystem>

// ==============================================
// NAMED PIPE SERVER FUNCTIONS
// ==============================================

/**
 * Handles communication with a single client connected to the pipe
 * 
 * @param hPipe Handle to the named pipe
 */
void HandleClientConnection(HANDLE hPipe) {
    char buffer[1024];
    DWORD bytesRead;
    
    printf("[+] Client handler thread started\n");
    
    while (true) {
        // Read message from pipe
        BOOL result = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        
        // Check for errors or disconnection
        if (!result || bytesRead == 0) {
            DWORD error = GetLastError();
            if (error == ERROR_BROKEN_PIPE) {
                printf("[-] Client disconnected\n");
            } else if (error != ERROR_NO_DATA) {
                printf("[!] ReadFile failed! Error: %ld\n", error);
            }
            break;
        }
        
        // Null-terminate and process the message
        buffer[bytesRead] = '\0';
        std::cout << "[LOG] " << buffer << std::endl;
        // Forward to shared log file for Python
        std::ofstream logFile("edr_shared.log", std::ios::app);
        logFile << buffer;
        logFile.flush(); // std::flush not needed with .flush()
    }
    
    // Cleanup
    CloseHandle(hPipe);
}

/**
 * Creates and manages the named pipe server for receiving logs from vhook.dll
 */
void StartNamedPipeServer() {
    printf("[+] Named pipe server starting...\n");
    
    // Set up security to allow all clients
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;  // NULL = default security (allows everyone)
    sa.bInheritHandle = FALSE;       // Don't allow handle inheritance
    
    while (true) {
        // Create the named pipe (same name used by vhook.dll)
        HANDLE hPipe = CreateNamedPipe(
            TEXT("\\\\.\\pipe\\HookPipe"),      // Pipe name
            PIPE_ACCESS_DUPLEX,                 // Bidirectional communication
            PIPE_TYPE_MESSAGE |                 // Message mode pipe
            PIPE_READMODE_MESSAGE |             // Read messages
            PIPE_WAIT,                          // Blocking mode
            PIPE_UNLIMITED_INSTANCES,           // Multiple clients
            4096,                               // Output buffer size
            4096,                               // Input buffer size
            0,                                  // Default timeout
            &sa);                               // Security attributes
        
        if (hPipe == INVALID_HANDLE_VALUE) {
            printf("[!] Failed to create named pipe! Error: %ld\n", GetLastError());
            Sleep(5000);  // Wait before retrying
            continue;
        }
        
        printf("[+] Named pipe created. Waiting for vhook.dll to connect...\n");
        
        // Wait for client connection (vhook.dll will connect)
        BOOL isConnected = ConnectNamedPipe(hPipe, NULL);
        if (!isConnected && GetLastError() != ERROR_PIPE_CONNECTED) {
            printf("[!] ConnectNamedPipe failed! Error: %ld\n", GetLastError());
            CloseHandle(hPipe);
            Sleep(1000);
            continue;
        }
        
        printf("[+] vhook.dll connected! Starting handler thread...\n");
        
        // Handle client in separate thread (allows multiple clients)
        std::thread clientThread(HandleClientConnection, hPipe);
        clientThread.detach();  // Detach so we can accept new connections
    }
}

// ==============================================
// MAIN FUNCTION
// ==============================================

/**
 * Main EDR Agent function
 * 
 * Usage:
 *   vAgent.exe               - Start only pipe server (for vhook.dll logs)
 *   vAgent.exe kernel        - Also load kernel driver (Not Yet Implemented)
 */
int main(int argc, char* argv[]) {
    printf("========================================\n");
    printf("       vEDR Agent - Starting Up\n");
    printf("========================================\n");
    
    // ==============================================
    // PART 2: START PIPE SERVER (for vhook.dll logs)
    // ==============================================
    printf("\n[Phase 1] Starting Log Server\n");
    printf("==============================\n");
    printf("[+] Creating named pipe: \\\\.\\pipe\\HookPipe\n");
    printf("[+] vhook.dll will connect to this pipe\n");
    printf("[+] Logs will appear below:\n");
    printf("----------------------------------------\n");
    
    // Start the pipe server (this runs forever)
    StartNamedPipeServer();
    
    // Note: StartNamedPipeServer() runs in infinite loop,
    // so we never reach here
    
    return 0;
}
