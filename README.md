# EDR-mergency
EDR-mergency is a proof-of-concept Endpoint Detection and Response (EDR) agent for Windows, designed to demonstrate real-time user-mode hooking, monitoring, blocking and alert logging. 

> [!WARNING]
> This project is intended for educational and research purposes only.
## Overview

It leverages inline API hooking via [MinHook](https://github.com/TsudaKageyu/minhook) to intercept and log critical process and file operations, providing visibility into potentially malicious activity.

The system consists of three main components:
- **`vhook.dll`**: A DLL that implements API hooks using a custom trampoline (based on hde64).
- **`Agent.exe`**: A monitoring agent that initializes logging and may coordinate telemetry collection.
- **`DLLLoader.exe`**: A simple injector that loads `vhook.dll` into a target process using `VirtualAllocEx` + `CreateRemoteThread`. 
- **`monitor.py`**: A Python script to tail and pretty-print JSONL alerts.

```sh
Target Process (e.g., notepad.exe)
   │
   └─ vhook.dll (hooks NtAllocateVirtualMemory, etc.)
        │
        ↓
Named Pipe → \\.\pipe\HookPipe
     ╱                ╲
    /                  \
Agent.exe          edr_monitor.py 
 (console logs)      (analysis, alerting, storage)
```

## Demo
<img width="1365" height="726" alt="testy" src="https://github.com/user-attachments/assets/0fa02937-53b2-47ed-9d78-200ca6b82030" />

## Building 

The project is built using the **x86_64-w64-mingw32** toolchain. Ensure you have `g++-mingw-w64-x86-64` (or equivalent) installed `sudo apt install mingw-w64`.

```sh
x86_64-w64-mingw32-g++ -shared -O2 \
  -DUNICODE -D_UNICODE \
  -I"./includes" \
  -I"./Hooker" \
  -I"./lib" \
  Hooker/dllmain.cpp \
  Hooker/logger.cpp \
  Hooker/pch.cpp \
  lib/buffer.c \
  lib/hde/hde64.c \
  lib/hook.c \
  lib/trampoline.c \
  -o vhook.dll \
  -lntdll -lkernel32 -luser32 -lpsapi \
  -static -static-libgcc -static-libstdc++
```

- `-shared`: Produces a DLL.
- `-O2`: Enables standard optimizations.
- `-DUNICODE -D_UNICODE`: Ensures wide-character (UTF-16) Windows API usage.
- `-I` paths: Include directories for headers (MinHook, project internals).
- `-l*`: Links essential Windows system libraries.
- `-static -static-libgcc -static-libstdc++`: Statically links C/C++ runtime to avoid dependency issues on target machines.

```sh
x86_64-w64-mingw32-g++ -O2 \
  -D_WIN32_WINNT=0x0A00 \
  Agent/main.cpp \
  -o Agent.exe \
  -lkernel32 -ladvapi32 -lpsapi \
  -static -static-libgcc -static-libstdc++
```

- `-D_WIN32_WINNT=0x0A00`: Targets Windows 10 (required for newer APIs).
- Links `advapi32` for registry/event log access and psapi for process enumeration.

```sh
x86_64-w64-mingw32-g++ -O2 \
  DLLLoader/main.cpp \
  -o DLLLoader.exe \
  -lkernel32 -luser32 -lpsapi \
  -static -static-libgcc -static-libstdc++
```
After a successful build, the following binaries are generated:

- vhook.dll - Hooking payload (x64)
- Agent.exe - Monitoring agent
- DLLLoader.exe - DLL injector

Runtime artifacts (created during execution):

- `edr_shared.log` - Human-readable event log
- `edr_alerts.jsonl` - Newline-delimited JSON alerts (machine-readable)

The `builds/` and `logs/` directories are used to keep output files organized. Make build from root folder.
## Running

1. Start 64-bit `notepad.exe`. (This is the where our process injection occours)
2. `python.exe monitor.py` to monitor logs.
3. Start the `Agent.exe`.
4. Run `DLLLoader.exe` (Agent will block allocating the memory location where shellcode is supposed to run hence popping `calc.exe`)
## Limitations

I mean yeah this could go on forever.

- User-mode only (no kernel visibility)
- Hooks are hardcoded (not dynamically updated)
- No persistence, network telemetry, or evasion detection
- Process injection may be flagged by real EDRs (for testing only)

> [!NOTE]
> You can try to take on simple challenge and try to evade the EDR and inject the shellcode `msfvenom -p windows/x64/exec CMD="calc.exe" -f c`  to pop a `calc` ( `Target Process: notepad.exe`, 
`Target Architecture: x64` )

---

