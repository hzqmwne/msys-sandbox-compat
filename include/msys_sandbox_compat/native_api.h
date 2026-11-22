#pragma once

#include <windows.h>
#include <winternl.h>

namespace msys_sandbox_compat {

inline HANDLE current_process() { return reinterpret_cast<HANDLE>(-1); }
constexpr NTSTATUS status_success = 0;
constexpr NTSTATUS status_invalid_image = static_cast<NTSTATUS>(0xc000007b);
constexpr NTSTATUS status_not_supported = static_cast<NTSTATUS>(0xc00000bb);
constexpr NTSTATUS status_unsuccessful = static_cast<NTSTATUS>(0xc0000001);
constexpr NTSTATUS status_access_denied = static_cast<NTSTATUS>(0xc0000022);
constexpr ULONG thread_create_suspended = 1;
constexpr ULONG section_original_base_information = 3;

using AllocateMemory = NTSTATUS(NTAPI *)(HANDLE, PVOID *, ULONG_PTR, PSIZE_T, ULONG, ULONG);
using FreeMemory = NTSTATUS(NTAPI *)(HANDLE, PVOID *, PSIZE_T, ULONG);
using ReadMemory = NTSTATUS(NTAPI *)(HANDLE, const void *, void *, SIZE_T, PSIZE_T);
using WriteMemory = NTSTATUS(NTAPI *)(HANDLE, void *, const void *, SIZE_T, PSIZE_T);
using ProtectMemory = NTSTATUS(NTAPI *)(HANDLE, PVOID *, PSIZE_T, ULONG, PULONG);
using QueryMemory = NTSTATUS(NTAPI *)(HANDLE, const void *, ULONG, void *, SIZE_T, PSIZE_T);
using QueryProcess = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, void *, ULONG, PULONG);
using ResumeThread = NTSTATUS(NTAPI *)(HANDLE, PULONG);
using TerminateProcess = NTSTATUS(NTAPI *)(HANDLE, NTSTATUS);
using CreateSection = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER,
                                        ULONG, ULONG, HANDLE);
using MapSection = NTSTATUS(NTAPI *)(HANDLE, HANDLE, PVOID *, ULONG_PTR, SIZE_T, PLARGE_INTEGER,
                                     PSIZE_T, ULONG, ULONG, ULONG);
using UnmapSection = NTSTATUS(NTAPI *)(HANDLE, PVOID);
using QuerySection = NTSTATUS(NTAPI *)(HANDLE, ULONG, void *, SIZE_T, PSIZE_T);
using QueryObject = NTSTATUS(NTAPI *)(HANDLE, ULONG, void *, ULONG, PULONG);
using OpenFile = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
                                   ULONG, ULONG);
using WriteFile = NTSTATUS(NTAPI *)(HANDLE, HANDLE, void *, void *, PIO_STATUS_BLOCK, const void *,
                                    ULONG, PLARGE_INTEGER, PULONG);
using FlushCode = NTSTATUS(NTAPI *)(HANDLE, const void *, SIZE_T);
using Close = NTSTATUS(NTAPI *)(HANDLE);
using SetSecurity = NTSTATUS(NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR);
using QuerySecurity = NTSTATUS(NTAPI *)(HANDLE, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, ULONG,
                                        PULONG);
using CompareObjects = NTSTATUS(NTAPI *)(HANDLE, HANDLE);
using QueryToken = NTSTATUS(NTAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, void *, ULONG, PULONG);
using OpenToken = NTSTATUS(NTAPI *)(HANDLE, ACCESS_MASK, PHANDLE);
using SetToken = NTSTATUS(NTAPI *)(HANDLE, TOKEN_INFORMATION_CLASS, void *, ULONG);
using CreateUserProcess = NTSTATUS(NTAPI *)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK,
                                            POBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, ULONG, ULONG,
                                            PRTL_USER_PROCESS_PARAMETERS, void *, void *);
using CreateDirectory = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using CreateMutant = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, BOOLEAN);
using CreateSymbolicLink = NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                             PUNICODE_STRING);
using CreatePipe = NTSTATUS(NTAPI *)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG,
                                     ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG, ULONG,
                                     PLARGE_INTEGER);

// Early-loader calls use ntdll. Intercepted entries point to original
// trampolines in an activated agent. Console ownership stays in the native host.
struct NativeApi {
    AllocateMemory allocate;
    FreeMemory free;
    ReadMemory read;
    WriteMemory write;
    ProtectMemory protect;
    QueryMemory query_memory;
    QueryProcess query_process;
    ResumeThread resume;
    TerminateProcess terminate;
    CreateSection create_section;
    MapSection map_section;
    UnmapSection unmap_section;
    QuerySection query_section;
    QueryObject query_object;
    OpenFile open_file;
    WriteFile write_file;
    FlushCode flush_code;
    Close close;
    SetSecurity set_security;
    QuerySecurity query_security;
    CompareObjects compare_objects;
    QueryToken query_token;
    OpenToken open_token;
    SetToken set_token;
    CreateUserProcess create_process;
    CreateDirectory create_directory;
    CreateMutant create_mutant;
    CreateSymbolicLink create_link;
    CreatePipe create_pipe;
    decltype(&RtlAddFunctionTable) add_function_table;
};

} // namespace msys_sandbox_compat
