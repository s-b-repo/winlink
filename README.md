# DLL Injector and Anti-Forensics Tool

This is a simple debugging tool for injecting a DLL into a target process and implementing basic anti-forensics techniques. The tool allows the following functionalities:
- DLL injection into a running process
- Renaming the executable and modifying its memory to obfuscate its hash
- Hiding the injector process from the Task Manager (user-mode technique)

## Features
- **DLL Injection**: Injects a specified DLL into the target process by creating a remote thread that calls `LoadLibraryA`.
- **Executable Obfuscation**: Changes the name of the executable on disk and modifies a few bytes of the executable in memory to prevent detection via hash-based methods.
- **Process Hiding**: Uses `NtSetInformationProcess` to attempt hiding the process from the Task Manager.

## How It Works

### DLL Injection
The tool allocates memory in the target process for the DLL path, writes the path into that memory, and uses `CreateRemoteThread` to execute `LoadLibraryA` in the context of the target process.

### Anti-Forensics
1. **ChangeNameAndHash**: 
   - Renames the executable by appending `.bak` to the original file name.
   - Alters a few bytes in the executable's memory to change its hash.
   
2. **HideFromTaskManager**: 
   - Uses the `NtSetInformationProcess` API from `ntdll.dll` to hide the process from being displayed in Task Manager (user-mode technique, success may vary depending on OS version and privileges).

## Requirements

- Windows OS (Tested on Windows 10)
- Visual Studio or any C++ compiler that supports Windows API
- Administrator privileges for certain functions (e.g., process injection and hiding)

## How to Use


Enter the process ID to inject into: <process_id>
Enter full path to the DLL to inject: <dll_path>

The tool will:

    Rename the executable and modify its hash.
    Inject the specified DLL into the target process.
    Attempt to hide the injector from Task Manager.

Example


Enter the process ID to inject into: 1234
Enter full path to the DLL to inject: C:\path\to\your.dll

Executable renamed to injector.exe.bak
Executable memory modified to change hash.
Process hidden from Task Manager.
DLL injected successfully!
Injection succeeded.

Security and Legal Considerations

This tool is intended for educational purposes, security research, and debugging in controlled environments. Use it responsibly. Malicious use of DLL injection and anti-forensics techniques may violate laws and agreements (e.g., end-user license agreements, corporate policies).

Always get permission before using this tool on systems you do not own or have explicit authorization to test.
Disclaimer

The author is not responsible for any misuse of this tool. Ensure you are complying with all applicable laws and regulations when using this software.
Contributing

If you'd like to contribute to this project, feel free to fork the repository and submit a pull request. Bug reports and feature requests are welcome!
