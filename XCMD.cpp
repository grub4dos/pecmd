


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header
#define _WIN32_WINNT 0x501

#include "Define.h"
#include "UniBase.h"
#include "Resource.h"
#pragma comment(lib, "ShLwAPI.lib")

HINSTANCE g_hInst = NULL;
INT g_iShowCmd = SW_NORMAL;


// Command list
#define LEN_Command 4
const TCHAR c_tzCmd[][5] =
{
	TEXT("INIT"), TEXT("LOAD"), TEXT("EXEC"), TEXT("CALL"),
	TEXT("REGI"), TEXT("ENVI"), TEXT("FILE"), TEXT("LINK"),
	TEXT("SEND"), TEXT("WAIT"), TEXT("KILL"), TEXT("SHUT"),
	TEXT("DEVI"), TEXT("SERV"), TEXT("PAGE"), TEXT("DISP"), 
	TEXT("LOGO"), TEXT("TEXT"), TEXT("XLOG"), TEXT("EXIF"),	
};

enum
{
	CMD_INIT, CMD_LOAD, CMD_EXEC, CMD_CALL,
	CMD_REGI, CMD_ENVI, CMD_FILE, CMD_LINK,
	CMD_SEND, CMD_WAIT, CMD_KILL, CMD_SHUT,
	CMD_DEVI, CMD_SERV, CMD_PAGE, CMD_DISP,
	CMD_LOGO, CMD_TEXT, CMD_XLOG, CMD_EXIF,
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log result
HANDLE g_hXLog = NULL;
VOID XLog(UINT uFmtRes, ...)
{
	if (g_hXLog)
	{
		va_list va;
		TCHAR tzLog[MAX_STR];
		TCHAR tzStr[MAX_PATH];
		va_start(va, uFmtRes);
		UINT i = UStrPrintV(tzLog, _GetStr(uFmtRes), va);
		va_end(va);
		UFileWrite(g_hXLog, tzLog, i * sizeof(TCHAR));
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Help dialog
INT_PTR CALLBACK HelpProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		TCHAR tzStr[MAX_NAME];
		TCHAR tzText[MAX_PATH];
		GetDlgItemText(hWnd, IDC_Version, tzStr, MAX_PATH);
		UStrPrint(tzText, tzStr, STR_VersionStamp);
		SetDlgItemText(hWnd, IDC_Version, tzText);
		GetDlgItemText(hWnd, IDC_Build, tzStr, MAX_PATH);
		UStrPrint(tzText, tzStr, STR_BuildStamp);
		SetDlgItemText(hWnd, IDC_Build, tzText);
		SetDlgItemTextA(hWnd, IDC_Help, (PCSTR) LoadResource(g_hInst, FindResource(g_hInst, _MakeIntRes(IDR_Help), RT_RCDATA)));
		return TRUE;

	case WM_COMMAND:
		if (LOWORD(wParam) == IDCANCEL)
		{
			EndDialog(hWnd, IDCANCEL);
		}
		break;
	}

	return FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Logo dialog
#ifndef LWA_COLORKEY
#define LWA_ALPHA 0x00000002
//#define LWA_COLORKEY 0x00000001
#define WS_EX_LAYERED 0x00080000
typedef BOOL (WINAPI *PSLW)(HWND hWnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags);
PSLW SetLayeredWindowAttributes = NULL;
#endif

struct GPSTART {UINT uVersion; PROC pCallback; BOOL bSuppressThread; BOOL bSuppressExternal;};
typedef HRESULT (WINAPI* PGdiplusStartup)(HANDLE* phToken, const GPSTART* gpIn, PVOID pvOut);
typedef HRESULT (WINAPI* PGdiplusShutdown)(HANDLE hToken);
typedef HRESULT (WINAPI* PGdipLoadImageFromFile)(const PWSTR pwzPath, HANDLE* phImage);
typedef HRESULT (WINAPI* PGdipDisposeImage)(HANDLE hImage);
typedef HRESULT (WINAPI* PGdipCreateFromHDC)(HDC hDC, HANDLE* phGraph);
typedef HRESULT (WINAPI* PGdipDrawImageRectI)(HANDLE hGraph, HANDLE hImage, INT iLeft, INT iTop, INT iWidth, INT iHeight);

HWND s_hLogo = NULL;
HANDLE s_hImage = NULL;

RECT s_rtText = {4, 4, 320, 24};
TCHAR s_tzText[MAX_NAME] = {0};
COLORREF s_crText = 0x00FFFFFF;

PGdiplusStartup pGdiplusStartup = NULL;
PGdiplusShutdown pGdiplusShutdown = NULL;
PGdipDisposeImage pGdipDisposeImage = NULL;
PGdipCreateFromHDC pGdipCreateFromHDC = NULL;
PGdipDrawImageRectI pGdipDrawImageRectI = NULL;
PGdipLoadImageFromFile pGdipLoadImageFromFile = NULL;

INT_PTR CALLBACK LogoProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		// Adjust window size
		s_hLogo = hWnd;
		SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN), 0);
#ifndef LWA_COLORKEY
		SetLayeredWindowAttributes = (PSLW) GetProcAddress(GetModuleHandle(TEXT("USER32")), "SetLayeredWindowAttributes"); 
		if (SetLayeredWindowAttributes)
#endif
		{
			SetLayeredWindowAttributes(hWnd, 0, 255, LWA_ALPHA);
		}
		break;

	case WM_COMMAND:
		if (wParam == IDCANCEL)
		{
#ifndef LWA_COLORKEY
			if (SetLayeredWindowAttributes)
#endif
			{
				// Close window
				for (UINT i = 0; i <= 255; i += 5, Sleep(20))
				{
					// Fake out
					SetLayeredWindowAttributes(hWnd, 0, 255 - i, LWA_ALPHA);
				}
			}
			return EndDialog(hWnd, IDCLOSE);
		}
		break;

	case WM_PAINT:
		PAINTSTRUCT ps;
		BeginPaint(hWnd, &ps);
		SetBkMode(ps.hdc, TRANSPARENT);
		SetTextColor(ps.hdc, s_crText);
		SelectObject(ps.hdc, GetStockObject(DEFAULT_GUI_FONT));
		DrawText(ps.hdc, s_tzText, -1, &s_rtText, DT_VCENTER | DT_SINGLELINE);
		EndPaint(hWnd, &ps);
		break;

	case WM_ERASEBKGND:
		HANDLE hGraph;
		if (s_hImage && (pGdipCreateFromHDC((HDC) wParam, &hGraph) == S_OK))
		{
			pGdipDrawImageRectI(hGraph, s_hImage, 0, 0, GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
			return (INT_PTR) GetStockObject(NULL_BRUSH);
		}
	}

	return FALSE;
}

HRESULT WINAPI Text(PTSTR ptzCmd)
{
	// Parse TEXT command
	PTSTR p = UStrRChr(ptzCmd, '#');
	if (p)
	{
		*p = 0;
		s_crText = UStrToInt(++p);
		p = UStrChr(p, ',');
		if (p)
		{
			s_rtText.left = UStrToInt(++p);
			p = UStrChr(p, ',');
			if (p)
			{
				s_rtText.top = UStrToInt(++p);
				p = UStrChr(p, ',');
				if (p)
				{
					s_rtText.right = UStrToInt(++p);
					p = UStrChr(p, ',');
					if (p)
					{
						s_rtText.bottom = UStrToInt(++p);
					}
				}
			}
		}
	}
	UStrCopyN(s_tzText, ptzCmd, _NumOf(s_tzText));
	return (s_hLogo && InvalidateRect(s_hLogo, &s_rtText, TRUE)) ? S_OK : ERROR_NOT_READY;
}

const struct {DLGTEMPLATE dtDlg; WCHAR  wzMenu[1]; WCHAR wzClass[1]; WCHAR wzCaption[5]; WORD wEnd[5];} c_dtLogo =
{{WS_POPUP | WS_VISIBLE | DS_CENTER, WS_EX_LAYERED | WS_EX_TOOLWINDOW/* | WS_EX_TRANSPARENT*/, 0, 0, 0, 400, 300}, 0, 0, L"XCMD"};
BOOL WINAPI Logo(PTSTR ptzCmd)
{
	// Copy parameter
	WCHAR wzPath[MAX_PATH];
	UStrToWStr(wzPath, ptzCmd, MAX_PATH);
	ptzCmd[0] = NULL;

	// Reload LOGO
	if (s_hLogo)
	{
		if (s_hImage)
		{
			pGdipDisposeImage(s_hImage);
			s_hImage = NULL;
		}
		if (pGdipLoadImageFromFile)
		{
			pGdipLoadImageFromFile(wzPath, &s_hImage);
		}
		return InvalidateRect(s_hLogo, NULL, TRUE);
	}

	// Load GDI+
	HMODULE hLib = LoadLibrary(TEXT("GdiPlus.dll"));
	if (hLib == NULL)
	{
		// Search GDI+
		HANDLE hFind;
		WIN32_FIND_DATA fd;
		TCHAR tzDir[MAX_PATH];
		ExpandEnvironmentStrings(TEXT("%SystemRoot%\\WinSxS\\*"), tzDir, MAX_PATH);
		if ((hFind = FindFirstFile(tzDir, &fd)) != INVALID_HANDLE_VALUE)
		{
			UDirSplitPath(tzDir);
			do
			{
				if ((fd.cFileName[0] != '.') && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
				{
					TCHAR tzPath[MAX_PATH];
					UStrPrint(tzPath, TEXT("%s\\%s\\GdiPlus.dll"), tzDir, fd.cFileName);
					hLib = LoadLibrary(tzPath);
				}
			}
			while (!hLib && FindNextFile(hFind, &fd));
			FindClose(hFind);
		}
	}

	// Get GDI+ function
	pGdiplusStartup = (PGdiplusStartup) GetProcAddress(hLib, "GdiplusStartup");
	pGdiplusShutdown = (PGdiplusShutdown) GetProcAddress(hLib, "GdiplusShutdown");
	pGdipLoadImageFromFile = (PGdipLoadImageFromFile) GetProcAddress(hLib, "GdipLoadImageFromFile");
	pGdipDisposeImage = (PGdipDisposeImage) GetProcAddress(hLib, "GdipDisposeImage");
	pGdipCreateFromHDC = (PGdipCreateFromHDC) GetProcAddress(hLib, "GdipCreateFromHDC");
	pGdipDrawImageRectI = (PGdipDrawImageRectI) GetProcAddress(hLib, "GdipDrawImageRectI");

	// Load Image
	HANDLE hToken;
	if (pGdipLoadImageFromFile)
	{
		GPSTART s = {1};
		pGdiplusStartup(&hToken, &s, NULL);
		pGdipLoadImageFromFile(wzPath, &s_hImage);
	}

	// Show LOGO
	DialogBoxIndirect(g_hInst, (LPCDLGTEMPLATE) &c_dtLogo, NULL, (DLGPROC) LogoProc);

	if (hLib)
	{
		// Free GDI+
		if (s_hImage)
		{
			pGdipDisposeImage(s_hImage);
			s_hImage = NULL;
		}
		if (pGdiplusShutdown)
		{
			pGdiplusShutdown(hToken);
		}
		FreeLibrary(hLib);
	}

	s_hLogo = NULL;
	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Get privilege
HRESULT Priv(PCTSTR ptzName)
{
	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES tPriv;
	LookupPrivilegeValue(NULL, ptzName, &tPriv.Privileges[0].Luid);
	tPriv.PrivilegeCount = 1;
	tPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	return AdjustTokenPrivileges(hToken, FALSE, &tPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Change display setting
BOOL Disp(PCTSTR ptzCmd)
{
	DEVMODE dmOld;
	EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &dmOld);

	DEVMODE dmNew = dmOld;
	dmNew.dmPelsWidth = UStrToInt(ptzCmd);
	ptzCmd = UStrChr(ptzCmd, ',');
	if (ptzCmd)
	{
		dmNew.dmPelsHeight = UStrToInt(++ptzCmd);
		ptzCmd = UStrChr(ptzCmd, ',');
		if (ptzCmd)
		{			
			dmNew.dmBitsPerPel = UStrToInt(++ptzCmd);
			ptzCmd = UStrChr(ptzCmd, ',');
			if (ptzCmd)
			{
				dmNew.dmDisplayFrequency = UStrToInt(++ptzCmd);
			}
		}
	}

	if ((dmNew.dmPelsWidth == dmOld.dmPelsWidth) && (dmNew.dmPelsHeight == dmOld.dmPelsHeight) &&
		(dmNew.dmBitsPerPel == dmOld.dmBitsPerPel) && (dmNew.dmDisplayFrequency == dmOld.dmDisplayFrequency))
	{
		return S_OK;
	}

	LONG lResult = ChangeDisplaySettings(&dmNew, CDS_UPDATEREGISTRY);
	if (lResult != DISP_CHANGE_SUCCESSFUL)
	{
		ChangeDisplaySettings(&dmOld, CDS_UPDATEREGISTRY);
	}

	return lResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Set page file
#include <NTSecAPI.h>
#define REG_PageFile TEXT("PagingFiles")
#define REG_MemMgr TEXT("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management")
HRESULT Page(PTSTR ptzCmd)
{
	// Parse size
	UINT uMin = 0;
	UINT uMax = 0;
	PTSTR p = UStrChr(ptzCmd, ' ');
	if (p)
	{
		*p++ = 0;
		uMin = UStrToInt(p);
		p = UStrChr(p, ' ');
		if (p)
		{
			*p++ = 0;
			uMax = UStrToInt(p);
		}
	}

	if (uMax<uMin)
	{
		uMax=uMin;
	}

	// Get DOS device name for page file
	TCHAR tzDrive[16];
	TCHAR tzDos[MAX_PATH];
	TCHAR tzFile[MAX_PATH];
	tzDrive[0] = ptzCmd[0]; tzDrive[1] = ptzCmd[1]; tzDrive[2] = 0;
	UStrCopy(tzFile, ptzCmd + 2);
	QueryDosDevice(tzDrive, tzDos, MAX_PATH);
	UStrCat(tzDos, tzFile);

	WCHAR wzPath[MAX_PATH];
	UStrToWStr(wzPath, tzDos, MAX_PATH);

	UNICODE_STRING sPath;
	sPath.Length = UWStrLen(wzPath) * sizeof(WCHAR);
	sPath.MaximumLength = sPath.Length + sizeof(WCHAR);
	sPath.Buffer = wzPath;

	// Fill size param
	ULARGE_INTEGER ulMax, ulMin;
	ulMin.QuadPart = uMin * 1024 * 1024;
	ulMax.QuadPart = uMax * 1024 * 1024;

	// Get function address
	typedef NTSTATUS (NTAPI* PNtCreatePagingFile)(PUNICODE_STRING sPath, PULARGE_INTEGER puInitSize, PULARGE_INTEGER puMaxSize, ULONG uPriority);
	PNtCreatePagingFile NtCreatePagingFile = (PNtCreatePagingFile) GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtCreatePagingFile");
	if (!NtCreatePagingFile)
	{
		return E_FAIL;
	}

	// Create page file
	Priv(SE_CREATE_PAGEFILE_NAME);
	HRESULT hResult = NtCreatePagingFile(&sPath, &ulMin, &ulMax, 0);
	if (hResult == S_OK)
	{
		// Log to Windows Registry
		TCHAR tzStr[MAX_PATH];
		DWORD i = sizeof(tzStr);
		if (SHGetValue(HKEY_LOCAL_MACHINE, REG_MemMgr, REG_PageFile, NULL, tzStr, &i) != S_OK)
		{
			i = 0;
		}
		else
		{
			i = (i / sizeof(TCHAR)) - 1;
		}

		i += UStrPrint(tzStr + i, TEXT("%s %d %d"), ptzCmd, uMin, uMax);
		tzStr[++i] = 0;
		SHSetValue(HKEY_LOCAL_MACHINE, REG_MemMgr, REG_PageFile, REG_MULTI_SZ, tzStr, i * sizeof(TCHAR));
	}

	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Start service
HRESULT Serv(PCTSTR ptzCmd)
{
	BOOL bResult = FALSE;
	SC_HANDLE hManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hManager)
	{
		BOOL bStop = (*ptzCmd == '!');
		if (bStop) ptzCmd++;

		SC_HANDLE hService = OpenService(hManager, ptzCmd, SERVICE_START | SERVICE_STOP);
		if (hService)
		{
			if (bStop)
			{
				SERVICE_STATUS ss;
				bResult = ControlService(hService, SERVICE_CONTROL_STOP, &ss);
			}
			else
			{
				bResult = StartService(hService, 0, NULL);
			}
			CloseServiceHandle(hService);
		}
		CloseServiceHandle(hManager);
	}
	return bResult ? S_OK : S_FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Test string equal
template <typename T1, typename T2> inline BOOL TStrEqual(T1 ptStr1, T2 ptStr2, UINT uLen)
{
	for (UINT i = 0; i < uLen; i++)
	{
		if (!UChrEqual((TCHAR) ptStr1[i], (TCHAR) ptStr2[i]))
		{
			return FALSE;
		}
	}
	return TRUE;
}

// Search string
template <typename T1, typename T2> PVOID TStrStr(T1 ptStr1, T2 ptStr2, UINT uLen)
{
	for (T1 p = ptStr1; *p; p++)
	{
		if (TStrEqual(p, ptStr2, uLen))
		{
			return p;
		}
	}
	return NULL;
}

// Lookup device ID from INFs
PCTSTR DevGetInf(PCTSTR ptzDevID, PCTSTR ptzSrcInf)
{
	PVOID pvFile = UFileLoad(ptzSrcInf, NULL, NULL);
	if (pvFile)
	{
		BOOL bASCII = ((PBYTE) pvFile)[3];//!IsTextUnicode(pvFile, -1, NULL); // Trick for UNICODE
		for (ptzDevID++; ptzDevID[-1]; ptzDevID += UStrLen(ptzDevID) + 2)
		{
			if (bASCII ? TStrStr((PSTR) pvFile, ptzDevID, ptzDevID[-1]) : TStrStr((PWSTR) pvFile, ptzDevID, ptzDevID[-1]))
			{
				XLog(IDS_FoundDriver, ptzDevID, ptzSrcInf);
				UMemFree(pvFile);
				return ptzDevID;
			}
		}
		UMemFree(pvFile);
	}
	return NULL;
}

// Update device driver
#ifdef _UNICODE
#define STR_UpdateDriverForPlugAndPlayDevices "UpdateDriverForPlugAndPlayDevicesW"
#else
#define STR_UpdateDriverForPlugAndPlayDevices "UpdateDriverForPlugAndPlayDevicesA"
#endif
typedef BOOL (WINAPI* PUPNP)(HWND hWnd, PCTSTR ptzDevID, PCTSTR ptzPath, DWORD dwFlags, PBOOL pbReboot);
BOOL DevIns(PCTSTR ptzDevID, PCTSTR ptzInfPath, DWORD dwForce = 3)
{
	BOOL bResult = FALSE;
	HMODULE hLib = LoadLibrary(TEXT("NewDev.dll"));
	if (hLib)
	{
		// Install INF
		PUPNP p = (PUPNP) GetProcAddress(hLib, STR_UpdateDriverForPlugAndPlayDevices);
		if (p)
		{
			BOOL bReboot = FALSE;
			bResult = p(NULL, ptzDevID, ptzInfPath, dwForce, &bReboot);
		}
		FreeLibrary(hLib);
	}
	return bResult;
}

// Install driver from DIR
#include <SetupAPI.h>
#pragma comment(lib, "SetupAPI.lib")
UINT DevDir(PCTSTR ptzDir, PCTSTR ptzDevID, PCTSTR ptzClass)
{
	TCHAR tzPath[MAX_NAME];
	if (ptzDir[0] == '\\')
	{
		ptzDir++;
		TCHAR tzDrives[MAX_NAME];
		GetLogicalDriveStrings(MAX_NAME, tzDrives);
		for (PTSTR p = tzDrives; *p; p += UStrLen(p) + 1)
		{
			UStrPrint(tzPath, TEXT("%s%s"), p, ptzDir);
			DevDir(tzPath, ptzDevID, ptzClass);
		}
		return S_OK;
	}

	WIN32_FIND_DATA fd;
	UStrPrint(tzPath, TEXT("%s\\INF\\*.INF"), ptzDir);
	HANDLE hFind = FindFirstFile(tzPath, &fd);
	if (hFind == INVALID_HANDLE_VALUE)
	{
		return ERROR_FILE_NOT_FOUND;
	}

	do
	{
		UStrPrint(tzPath, TEXT("%s\\INF\\%s"), ptzDir, fd.cFileName);
		if (ptzClass)
		{
			GUID idClass;
			TCHAR tzClass[MAX_NAME];
			SetupDiGetINFClass(tzPath, &idClass, tzClass, MAX_NAME, NULL);
			if (UStrCmpI(tzClass, ptzClass))
			{
				continue;
			}
		}
		PCTSTR p = DevGetInf(ptzDevID, tzPath);
		if (p)
		{
			DevIns(p, tzPath, 0);
		}
	}
	while (FindNextFile(hFind, &fd));

	FindClose(hFind);
	return S_OK;
}

// Extract driver from CAB
PTSTR g_ptzDevInf = NULL;
UINT CALLBACK DevCab(PVOID pvContext, UINT uMsg, UINT_PTR upParam1, UINT_PTR upParam2)
{
	static UINT s_uExtract = 0;

	if (uMsg == SPFILENOTIFY_FILEINCABINET)
	{
		PTSTR ptzTarget = ((FILE_IN_CABINET_INFO*) upParam1)->FullTargetName;
		PCTSTR ptzName = ((FILE_IN_CABINET_INFO*) upParam1)->NameInCabinet;

		PCTSTR p = UStrRChr(ptzName, '\\');
		if (p)
		{
			ptzName = p + 1;
		}

		// Extract INF or driver file
		p = ptzName + UStrLen(ptzName) - 4;
		if (UStrCmpI(p, TEXT(".INF")) == 0)
		{
			p = TEXT("%SystemRoot%\\INF\\");
		}
		else if (s_uExtract)
		{
			if (UStrCmpI(p, TEXT(".SYS")) == 0)
			{
				p = TEXT("%SystemRoot%\\SYSTEM32\\DRIVERS\\");
			}
			else if (UStrCmpI(p, TEXT(".DLL")) == 0)
			{
				p = TEXT("%SystemRoot%\\SYSTEM32\\");
			}
			else
			{
				p = TEXT("%SystemRoot%\\");
			}
		}
		else
		{
			// Skip
			return FILEOP_SKIP;
		}

		ExpandEnvironmentStrings(p, ptzTarget, MAX_PATH);
		UStrCat(ptzTarget, ptzName);
		UStrRep(ptzTarget, '#', '\\');
		UDirCreate(ptzTarget);
		return FILEOP_DOIT;
	}
	else if (uMsg == SPFILENOTIFY_FILEEXTRACTED)
	{
		PCTSTR ptzTarget = ((FILEPATHS*) upParam1)->Target;
		if (UStrCmpI(ptzTarget + UStrLen(ptzTarget) - 4, TEXT(".INF")))
		{
			// Not INF
			s_uExtract++;
			return NO_ERROR;
		}

		// Get Device from INF
		PCTSTR ptzDevID = DevGetInf((PCTSTR) pvContext, ptzTarget);
		if (ptzDevID)
		{
			// Found Driver
			s_uExtract = 1;
			do {*g_ptzDevInf++ = *ptzDevID;} while (*ptzDevID++);
			do {*g_ptzDevInf++ = *ptzTarget;} while (*ptzTarget++);
			return NO_ERROR;
		}

		// Delete INF
		if (s_uExtract != 1)
		{
			// Driver has been extracted completely.
			s_uExtract = 0;
			UFileDelete(ptzTarget);
		}
	}
	return NO_ERROR;
}

// Install device driver
#if (_MSC_VER < 1300)
#define DN_HAS_PROBLEM 0x00000400
#define CM_PROB_NOT_CONFIGURED 0x00000001
typedef DWORD (WINAPI* PCM_Get_DevNode_Status)(OUT PULONG pulStatus, OUT PULONG pulProblemNumber, IN  DWORD dnDevInst, IN  ULONG ulFlags);
#else
#include <CfgMgr32.h>
#endif
#define MAX_DevID 2048
#define NUM_DevID ((UINT) ((PBYTE) p - (PBYTE) tzDevID))
HRESULT Devi(PTSTR ptzCmd)
{
	// Lookup device
	HDEVINFO hDev = SetupDiGetClassDevs(NULL, NULL, 0, DIGCF_ALLCLASSES);
	if (hDev == INVALID_HANDLE_VALUE)
	{
		return E_FAIL;
	}

	// Build SPDRP_HARDWAREID list
	TCHAR tzDevID[MAX_DevID];
	PTSTR p = tzDevID + 1;
	SP_DEVINFO_DATA sdDev = {sizeof(SP_DEVINFO_DATA)};
	for (UINT i = 0; (NUM_DevID < MAX_DevID) && SetupDiEnumDeviceInfo(hDev, i, &sdDev); i++)
	{
#if (_MSC_VER < 1300)
		PCM_Get_DevNode_Status CM_Get_DevNode_Status = (PCM_Get_DevNode_Status) GetProcAddress(GetModuleHandle(TEXT("SetupAPI")), "CM_Get_DevNode_Status");
		if (CM_Get_DevNode_Status)
#endif
		{
			// Exclude configured device
			ULONG uProblem = 0;
			ULONG uStatus = DN_HAS_PROBLEM;
			CM_Get_DevNode_Status(&uStatus, &uProblem, sdDev.DevInst, 0);
			if (uProblem != CM_PROB_NOT_CONFIGURED)
			{
#ifndef _DEBUG
				continue;
#endif
			}
		}

		// Get device ID
		if (SetupDiGetDeviceRegistryProperty(hDev, &sdDev, SPDRP_HARDWAREID, NULL, (PBYTE) p, MAX_DevID - NUM_DevID, NULL) && UStrCmpNI(p, TEXT("ACPI"), 4))
		{
			XLog(IDS_FoundDevice, p);

			// Trim some stuff for quick search
			UINT j = 0;
			for (UINT k = 0; p[j]; j++)
			{
				if ((p[j] == '&') && (++k == 2))
				{
					break;
				}
			}
			p[-1] = j;
			for (p += j; *p; p++);
			p += 2;
		}
	}
	p[-1] = 0;

	SetupDiDestroyDeviceInfoList(hDev);
	if (tzDevID[0] == 0)
	{
		// No device
		return ERROR_NO_MATCH;
	}

	// Parse param
	BOOL bInstall = (ptzCmd[0] == '$');
	if (bInstall) ptzCmd++;
	PTSTR ptzClass = UStrChr(ptzCmd, ',');
	if (ptzClass) *ptzClass++ = 0;

	if (UStrCmpI(ptzCmd + UStrLen(ptzCmd) - 4, TEXT(".CAB")))
	{
		// Lookup driver from directory
		return DevDir(ptzCmd, tzDevID, ptzClass);
	}
	else
	{
		// Lookup CAB file
		TCHAR tzDevInf[MAX_PATH * 16];
		g_ptzDevInf = tzDevInf;
		HRESULT hResult = SetupIterateCabinet(ptzCmd, 0, (PSP_FILE_CALLBACK) DevCab, tzDevID) ? S_OK : E_FAIL;
		if (bInstall)
		{
			for (PTSTR p = tzDevInf; p < g_ptzDevInf; p += UStrLen(p) + 1)
			{
				PTSTR ptzDevID = p;
				p += UStrLen(p) + 1;
				DevIns(ptzDevID, p);
			}
		}
		return hResult;
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Set Windows Registry
HRESULT Regi(PTSTR ptzCmd)
{
	PTSTR ptzSubKey = UStrChr(ptzCmd, '\\');
	if (!ptzSubKey)
	{
		return E_INVALIDARG;
	}
	else
	{
		*ptzSubKey++ = 0;
	}

	HKEY hKey;
	if (UStrCmpI(ptzCmd, TEXT("HKLM")) == 0)
	{
		hKey = HKEY_LOCAL_MACHINE;
	}
	else if (UStrCmpI(ptzCmd, TEXT("HKCU")) == 0)
	{
		hKey = HKEY_CURRENT_USER;
	}
	else if (UStrCmpI(ptzCmd, TEXT("HKCR")) == 0)
	{
		hKey = HKEY_CLASSES_ROOT;
	}
	else if (UStrCmpI(ptzCmd, TEXT("HKU")) == 0)
	{
		hKey = HKEY_USERS;
	}
	else if (UStrCmpI(ptzCmd, TEXT("HKCC")) == 0)
	{
		hKey = HKEY_CURRENT_CONFIG;
	}
	else
	{
		return E_INVALIDARG;
	}

	PTSTR ptzData = UStrChr(ptzSubKey, '=');
	if (ptzData)
	{
		*ptzData++ = 0;
	}

	PTSTR ptzValue = UStrRChr(ptzSubKey, '\\');
	if (!ptzValue)
	{
		return E_INVALIDARG;
	}
	else
	{
		*ptzValue++ = 0;
	}

	if (ptzData)
	{
		if (ptzData[0] == '#')
		{
			DWORD dwData = UStrToInt(ptzData + 1);
			return SHSetValue(hKey, ptzSubKey, ptzValue, REG_DWORD, &dwData, sizeof(DWORD));
		}
		else if (ptzData[0] == '@')
		{
			UINT i = 0;
			BYTE bData[MAX_PATH];
			for (ptzData++; i < sizeof(bData);)
			{
				bData[i++] = UStrToInt(ptzData);
				ptzData = UStrChr(ptzData, ' ');
				if (ptzData)
				{
					ptzData++;
				}
				else
				{
					break;
				}
			}
			return SHSetValue(hKey, ptzSubKey, ptzValue, REG_BINARY, bData, i);
		}
		else
		{
			return SHSetValue(hKey, ptzSubKey, ptzValue, REG_SZ, ptzData, UStrLen(ptzData) * sizeof(TCHAR));
		}
	}
	else
	{
		if ((ptzValue[0] == '!') && (ptzValue[1] == 0))
		{
			return SHDeleteKey(hKey, ptzSubKey);
		}
		else
		{
			return SHDeleteValue(hKey, ptzSubKey, ptzValue);
		}
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//  Folder macro
#include <ShlObj.h>
const struct {INT iFolder; PCTSTR ptzMacro;} c_sMacro[] =
{
	{CSIDL_FAVORITES,		TEXT("Favorites")},
	{CSIDL_DESKTOPDIRECTORY,TEXT("Desktop")},
	{CSIDL_STARTMENU,		TEXT("StartMenu")},
	{CSIDL_STARTUP,			TEXT("Startup")},
	{CSIDL_PROGRAMS,		TEXT("Programs")},
	{CSIDL_SENDTO,			TEXT("SendTo")},
	{CSIDL_PERSONAL,		TEXT("Personal")},
	{CSIDL_APPDATA,			TEXT("QuickLaunch")},
};

//  Set environment
HRESULT Envi(PTSTR ptzEnv, BOOL bSystem = FALSE)
{
	TCHAR tzStr[MAX_STR];
	if (!ptzEnv[0] || (ptzEnv[0] == '='))
	{
		for (UINT i = 0; i < _NumOf(c_sMacro); i++)
		{
			if (ptzEnv[0]/* == '='*/)
			{
				Envi((PTSTR) c_sMacro[i].ptzMacro, bSystem);
				continue;
			}

			PTSTR p = tzStr + UStrPrint(tzStr, TEXT("%s="), c_sMacro[i].ptzMacro);
			if (SHGetSpecialFolderPath(NULL, p, c_sMacro[i].iFolder, TRUE))
			{
				if (c_sMacro[i].iFolder == CSIDL_APPDATA)
				{
					// Trick
					UStrCat(p, TEXT("\\Microsoft\\Internet Explorer\\Quick Launch\\"));
					UDirCreate(p);
					CreateDirectory(p, NULL);
				}
				Envi(tzStr, bSystem);
			}
		}

		if (ptzEnv[0]/* == '='*/)
		{
			return Envi((PTSTR) STR_AppName, bSystem);
		}
		else
		{
			UStrPrint(tzStr, TEXT("%s=%s/%s"), STR_AppName, STR_VersionStamp, STR_BuildStamp);
			return Envi(tzStr, bSystem);
		}
	}

	if (bSystem)
	{
		UStrPrint(tzStr, TEXT("HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\\%s"), ptzEnv);
		Regi(tzStr);
	}

	PTSTR ptzValue = UStrChr(ptzEnv, '=');
	if (ptzValue)
	{
		// Trick : If no '=', ptzEnv can be a constant string.
		*ptzValue++ = 0;
	}
	HRESULT hResult = SetEnvironmentVariable(ptzEnv, ptzValue) ? S_OK : GetLastError();

	if (bSystem)
	{
		if (!ptzValue)
		{
			ptzValue = ptzEnv + UStrLen(ptzEnv) + 1;
		}
		DWORD dwResult = 0;
		SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM) TEXT("Environment"), SMTO_ABORTIFHUNG, 5000, &dwResult);
	}
	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Delete file or directory
HRESULT File(PTSTR ptzCmd)
{
	SHFILEOPSTRUCT so = {0};
	so.pFrom = ptzCmd;
	so.wFunc = FO_DELETE;
	so.fFlags = FOF_NOCONFIRMATION | FOF_NOCONFIRMMKDIR | FOF_NOERRORUI| FOF_SILENT;

	PTSTR p = ptzCmd;
	for (; *p; p++)
	{
		if (*p == ';')
		{
			*p = 0;
		}
		else if (*p == '}')
		{
			if (p[-1] == '=')
			{
				p[-1] = 0;
				so.pTo = p + 1;
				so.wFunc = FO_COPY;
			}
			else if (p[-1] == '-')
			{
				p[-1] = 0;
				so.pTo = p + 1;
				so.wFunc = FO_MOVE;
			}
			*p = 0;
		}
	}
	p[1] = 0;

	return SHFileOperation(&so);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Create shortcut
HRESULT Link(PTSTR ptzCmd)
{
	// Parse Shortcut,Target,Param,IconPath,IconIndex
	PTSTR ptzTarget = UStrChr(ptzCmd, ',');
	if (ptzTarget == NULL)
	{
		return ERROR_PATH_NOT_FOUND;
	}

	INT iIcon = 0;
	PTSTR ptzIcon = NULL;

	*ptzTarget++ = 0;
	PTSTR ptzParam = UStrChr(ptzTarget, ',');
	if (ptzParam)
	{
		*ptzParam++ = 0;
		ptzIcon = UStrChr(ptzParam, ',');
		if (ptzIcon)
		{
			*ptzIcon++ = 0;
			PTSTR ptzIndex = UStrChr(ptzIcon, ',');
			if (ptzIndex)
			{
				*ptzIndex++ = 0;
				iIcon = UStrToInt(ptzIndex);
			}
		}
	}

	// Search target
	if (*ptzCmd == '*')
	{
		ptzCmd++;
	}
	else
	{
		TCHAR tzTarget[MAX_PATH];
		if (SearchPath(NULL, ptzTarget, NULL, MAX_PATH, tzTarget, NULL))
		{
			ptzTarget = tzTarget;
		}
		else if (!UDirExist(ptzTarget))
		{
			return ERROR_PATH_NOT_FOUND;
		}
	}

	// Create shortcut
	IShellLink *pLink;
	CoInitialize(NULL);
	HRESULT hResult = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (PVOID *) &pLink);
	if (hResult == S_OK)
	{
		IPersistFile *pFile;
		hResult = pLink->QueryInterface(IID_IPersistFile, (PVOID *) &pFile);
		if (hResult == S_OK)
		{
			if (*ptzCmd == '!')
			{
				ptzCmd++;
				hResult = pLink->SetShowCmd(SW_SHOWMINIMIZED);
			}

			// Shortcut settings
			hResult = pLink->SetPath(ptzTarget);
			hResult = pLink->SetArguments(ptzParam);
			hResult = pLink->SetIconLocation(ptzIcon, iIcon);
			if (UDirSplitPath(ptzTarget) != ptzTarget)
			{
				hResult = pLink->SetWorkingDirectory(ptzTarget);
			}

			// Save link
			WCHAR wzLink[MAX_PATH];
			UStrCat(ptzCmd, TEXT(".LNK"));
			UStrToWStr(wzLink, ptzCmd, MAX_PATH);
			UDirCreate(ptzCmd);
			hResult = pFile->Save(wzLink, FALSE);

			pFile->Release();
		}
		pLink->Release();
	}

	CoUninitialize();
	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Synthesizes a keystroke
HRESULT Send(PCTSTR ptzCmd)
{
	INT i = 0;
	PCTSTR p = ptzCmd;
	do
	{
		if ((*p == ',') || (*p == 0))
		{
			i = UStrToInt(ptzCmd);
			if (*(p - 1) != '^')
			{
				keybd_event(i, 0, 0, 0);
			}
			if (*(p - 1) != '_')
			{
				keybd_event(i, 0, KEYEVENTF_KEYUP, 0);
			}
			ptzCmd = p + 1;
		}
	}
	while (*p++);
	return i ? S_OK : S_FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Kill process
#include <TLHelp32.h>
HRESULT Kill(PCTSTR ptzCmd)
{
	HRESULT hResult = S_FALSE;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		for (BOOL b = Process32First(hSnap, &pe); b; b = Process32Next(hSnap, &pe))
		{
			if (UStrCmpNI(pe.szExeFile, ptzCmd, UStrLen(ptzCmd)) == 0)
			{
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
				if (hProcess)
				{
					if (TerminateProcess(hProcess, 0))
					{
						hResult = S_OK;
					}
					CloseHandle(hProcess);
				}
			}
		}
		CloseHandle(hSnap);
	}

	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Shutdown
HRESULT Shut(BOOL bReboot)
{
	// End session
	DWORD dwResult;
	SendMessageTimeout(HWND_BROADCAST, WM_QUERYENDSESSION, 0, 0, 0, 2000, &dwResult);
	SendMessageTimeout(HWND_BROADCAST, WM_ENDSESSION, 0, 0, 0, 2000, &dwResult);
	//SendMessageTimeout(HWND_BROADCAST, WM_CLOSE, 0, 0, 0, 2000, &dwResult);
	SendMessageTimeout(HWND_BROADCAST, WM_DESTROY, 0, 0, 0, 2000, &dwResult);

	// Get function address
	typedef DWORD (NTAPI *PNtShutdownSystem)(DWORD dwAction);
	PNtShutdownSystem NtShutdownSystem = (PNtShutdownSystem) GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "NtShutdownSystem");
	if (!NtShutdownSystem)
	{
		return E_FAIL;
	}

	// Shutdown
	Priv(SE_SHUTDOWN_NAME);
	return NtShutdownSystem(bReboot ? 1: 2);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Call DLL function
typedef HRESULT (WINAPI *PROC1)(PVOID pv0);
typedef HRESULT (WINAPI *PROC2)(PVOID pv0, PVOID pv1);
typedef HRESULT (WINAPI *PROC3)(PVOID pv0, PVOID pv1, PVOID pv2);
typedef HRESULT (WINAPI *PROC4)(PVOID pv0, PVOID pv1, PVOID pv2, PVOID pv3);
HRESULT WINAPI Call(PTSTR ptzCmd)
{
	UINT uArg = 0;
	PTSTR ptzArg[4];
	HRESULT hResult = E_NOINTERFACE;
	PTSTR ptzProc = UStrChr(ptzCmd, ',');
	if (ptzProc)
	{
		*ptzProc++ = 0;
		for (PTSTR p = ptzProc; (uArg < 4) && (p = UStrChr(p, ',')); uArg++)
		{
			*p++ = 0;
			ptzArg[uArg] = p;
			if (*p == '#')
			{
				ptzArg[uArg] = (PTSTR) (INT_PTR) UStrToInt(p + 1);
			}
		}
	}
	else
	{
		ptzProc = TEXT("DllRegisterServer");
	}

	HMODULE hLib = LoadLibrary(ptzCmd);
	if (hLib)
	{
		CHAR szProc[MAX_NAME];
		UStrToAStr(szProc, ptzProc, MAX_NAME);
		PROC f = GetProcAddress(hLib, szProc);
		if (f)
		{
			switch (uArg)
			{
			case 0: hResult = f(); break;
			case 1: hResult = ((PROC1) f)(ptzArg[0]); break;
			case 2: hResult = ((PROC2) f)(ptzArg[0], ptzArg[1]); break;
			case 3: hResult = ((PROC3) f)(ptzArg[0], ptzArg[1], ptzArg[2]); break;
			case 4: hResult = ((PROC4) f)(ptzArg[0], ptzArg[1], ptzArg[2], ptzArg[3]); break;
			}
		}
		FreeLibrary(hLib);
	}

	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hook ExitWindows to execute a command
VOID Hook(HANDLE hProcess)
{
	__asm
	{
		// BOOL WINAPI WriteProcessMemory(HANDLE hProcess, PVOID pvBaseAddress, PVOID pvBuffer, DWORD dwSize, PDWORD pdwNumberOfBytesWritten);
		// Write code to target
		PUSH    NULL;
		MOV     EAX, OFFSET _End;
		SUB     EAX, OFFSET _Code;
		PUSH    EAX;
		PUSH    OFFSET _Code;
		PUSH    ExitWindowsEx;
		PUSH    hProcess;
		CALL    DWORD PTR [WriteProcessMemory];

		// Write True WinExec address to target
		PUSH    NULL;
		PUSH    4;
		LEA     EAX, WinExec;
		PUSH    EAX;
		MOV     EAX, OFFSET _WinExec;
		SUB     EAX, OFFSET _Code;
		ADD     EAX, ExitWindowsEx;
		PUSH    EAX;
		PUSH    hProcess;
		CALL    DWORD PTR [WriteProcessMemory];

		// Return
		JMP		_End;

		// Target code (Call WinExec to execute a command), address independent
		//BOOL WINAPI ExitWindowsEx(UINT uFlags, DWORD dwReason)
		//UINT WINAPI WinExec(PCSTR pszCmdLine, UINT uCmdShow)
_Code:
		MOV     EAX, [ESP + 4];	// Get uFlags
		PUSH    EAX;			// Push  uCmdShow
		CALL    _GetWinExec;	// Push _WinExec
_WinExec:
		_EMIT   0;
		_EMIT   0;
		_EMIT   0;
		_EMIT   0;
_GetWinExec:
		POP     EAX;			// Get _WinExec
		CALL    _Call;			// Push pszCmdLine
		_EMIT   'X';
		_EMIT   'C';
		_EMIT   'M';
		_EMIT   'D';
		_EMIT   '.';
		_EMIT   'E';
		_EMIT   'X';
		_EMIT   'E';
		_EMIT   ' ';
		_EMIT   'S';
		_EMIT   'H';
		_EMIT   'U';
		_EMIT   'T';
		_EMIT   0;
_Call:
		CALL    [EAX];			// Call WinExec
		RET     8;
_End:
	}
}

// Execute command
HRESULT Exec(PTSTR ptzCmd)
{
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = TEXT("WinSta0\\Default");

	BOOL bWait = FALSE;
	BOOL bHook = FALSE;
	BOOL bRunKey = FALSE;
	while (TRUE)
	{
		if (*ptzCmd == '!') si.dwFlags = STARTF_USESHOWWINDOW;
		else if (*ptzCmd == '@') si.lpDesktop = TEXT("WinSta0\\WinLogon");
		else if (*ptzCmd == '=') bWait = TRUE;
		else if (*ptzCmd == '$') bHook = TRUE;
		else if (*ptzCmd == '&') bRunKey = TRUE;
		else break;
		ptzCmd++;
	}

	if (bRunKey)
	{
		PTSTR ptzName = UStrRChr(ptzCmd, '\\');
		ptzName = ptzName ? (ptzName + 1) : ptzCmd;
		HKEY hKey = bWait ? HKEY_LOCAL_MACHINE : HKEY_CURRENT_USER;
		return SHSetValue(hKey, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), ptzName, REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
	}

	BOOL bResult = CreateProcess(NULL, ptzCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (bResult)
	{
		if (bHook)
		{
			Sleep(1000);
			Hook(pi.hProcess);
		}
		if (bWait)
		{
			WaitForSingleObject(pi.hProcess, INFINITE);
		}
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}

	return bResult ? S_OK : S_FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Load command file
HRESULT Command(PTSTR);
HRESULT Load(PCTSTR ptzPath)
{
	if (ptzPath[0] == 0)
	{
		ptzPath = TEXT("\\XCMD.INI");
	}
	if (ptzPath[0] == '\\')
	{
		ptzPath++;
		TCHAR tzDrives[MAX_NAME];
		GetLogicalDriveStrings(MAX_NAME, tzDrives);
		for (PTSTR p = tzDrives; *p; p += UStrLen(p) + 1)
		{
			TCHAR tzPath[MAX_NAME];
			UStrPrint(tzPath, TEXT("%s%s"), p, ptzPath);
			Load(tzPath);
		}
		return S_OK;
	}

	TCHAR tzPath[MAX_PATH];
	if (!SearchPath(NULL, ptzPath, NULL, MAX_PATH, tzPath, NULL))
	{
		return ERROR_FILE_NOT_FOUND;
	}

	UINT uSize = -1;
	PBYTE pbFile = (PBYTE) UFileLoad(tzPath, NULL, &uSize);
	if (pbFile == NULL)
	{
		return S_FALSE;
	}

	// Set current directory to COMMAND FILE directory
	PTSTR p = UStrRChr(tzPath, '\\');
	if (p)
	{
		p[1] = 0;
		SetCurrentDirectory(tzPath);
		p[0] = 0;
		SetEnvironmentVariable(TEXT("CurDir"), tzPath);
		tzPath[2] = 0;
		SetEnvironmentVariable(TEXT("CurDrv"), tzPath);
	}

	// Convert ASCII <=> UNICODE
	p = (PTSTR) pbFile;
#ifdef _UNICODE
	if (pbFile[3])	// !IsTextUnicode(pbFile, -1, NULL)
	{
		uSize += 16;
		p = (PTSTR) UMemAlloc(uSize * sizeof(TCHAR));
		UAStrToWStr(p, (PCSTR) pbFile, uSize);
		UMemFree(pbFile);
		pbFile = (PBYTE) p;
	}
#else
	if (!pbFile[3])	// IsTextUnicode(pbFile, -1, NULL)
	{
		uSize += 16;
		p = (PTSTR) UMemAlloc(uSize * sizeof(TCHAR));
		UWStrToAStr(p, (PCWSTR) pbFile, uSize);
		UMemFree(pbFile);
		pbFile = (PBYTE) p;
	}
#endif

	for (PTSTR q = p; *q; q++)
	{
		if ((*q == '\r') || (*q == '\n'))
		{
			*q = 0;
			if (p[0] != '/')
			{
				// Log command
				if (g_hXLog)
				{
					UFileWrite(g_hXLog, p, (UINT) (q - p) * sizeof(TCHAR));
				}

				// Exec command
				HRESULT hResult = Command(p);

				// Log result
				if (g_hXLog)
				{
					TCHAR tzStr[MAX_PATH];
					PTSTR p = tzStr; *p++ = '\t';
					p += FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, hResult, 0, p, _NumOf(tzStr), NULL);
					if (p == tzStr + 1)
					{
						p += LoadString(g_hInst, IDS_CmdErr, p, MAX_NAME);
						p += UStrPrint(p, TEXT("%08X"), hResult);
					}
					*p++ = '\r'; *p++ = '\n';
					UFileWrite(g_hXLog, tzStr, (UINT) (p - tzStr) * sizeof(TCHAR));
				}
			}
			for (q++; (*q == '\r') || (*q == '\n'); q++);
			p = q;
		}
	}

	UMemFree(pbFile);
	return S_OK;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Ctrl+Alt+Del handler
HHOOK g_hHook = NULL;
LRESULT CALLBACK InitProc(INT iCode, WPARAM wParam, LPARAM lParam)
{
	if ((iCode == HC_ACTION) && (wParam == WM_KEYDOWN) && (((LPKBDLLHOOKSTRUCT) lParam)->vkCode == VK_DELETE))
	{
		if ((GetAsyncKeyState(VK_CONTROL) & 0x8000) && (GetAsyncKeyState(VK_MENU) & 0x8000))
		{
			if ((GetAsyncKeyState(VK_SHIFT) & 0x8000))
			{
				// Ctrl+Shift+Alt+Del to Exit
				PostQuitMessage(VK_DELETE);
			}
			else
			{
				TCHAR tzCmd[] = TEXT("TaskMgr.exe");
				Exec(tzCmd);
			}
			return TRUE;
		}
	}
	return CallNextHookEx(g_hHook, iCode, wParam, lParam);
}

// Init desktop
HRESULT Init(PCTSTR ptzCmd)
{
	// Switch desktop
	HDESK hDesk = OpenDesktop(TEXT("Default"), 0, TRUE, GENERIC_ALL);
	if (hDesk)
	{
		if (SetThreadDesktop(hDesk))
		{
			SwitchDesktop(hDesk);
		}
		CloseDesktop(hDesk);
	}

	// Execute LOAD command
	TCHAR tzCmd[MAX_PATH];
	UStrPrint(tzCmd + GetModuleFileName(NULL, tzCmd, MAX_PATH), TEXT(" LOAD %s"), ptzCmd);
	Exec(tzCmd);

	// Hook Ctrl+Alt++Del
	MSG msg;
	g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, InitProc, g_hInst, 0);
	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// Exit
	UnhookWindowsHookEx(g_hHook);
	return (HRESULT) msg.wParam;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Conditional execute
#if (_MSC_VER < 1300)
#define MEMORYSTATUSEX MEMORYSTATUS
#define ullAvailPhys dwAvailPhys
#define GlobalMemoryStatusEx GlobalMemoryStatus
#endif
HRESULT ExIf(PTSTR ptzCmd)
{
	PTSTR p = UStrChr(ptzCmd, ',');
	if (!p)
	{
		return E_INVALIDARG;
	}

	*p++ = 0;
	UINT uRes = 0;
	if ((ptzCmd[3] == '>') || (ptzCmd[3] == '<') || (ptzCmd[3] == '=') || (ptzCmd[3] == '!'))
	{
		if (UStrCmpNI(ptzCmd, TEXT("MEM"), 3))
		{
			ptzCmd[2] = 0;
			ULARGE_INTEGER uiFree, uiTotal, uiUFree;
			if (GetDiskFreeSpaceEx(ptzCmd, &uiUFree, &uiTotal, &uiFree))
			{
				uRes = (UINT) (uiUFree.QuadPart / (1024 * 1024));
			}
		}
		else
		{
			MEMORYSTATUSEX ms = {sizeof(MEMORYSTATUSEX)};
			GlobalMemoryStatusEx(&ms);
			uRes = (UINT) (ms.ullAvailPhys / (1024 * 1024));
		}
		UINT uCmp = UStrToInt(ptzCmd + 4);
		if (ptzCmd[3] == '=') uRes = (uRes == uCmp);
		else if (ptzCmd[3] == '>') uRes = (uRes > uCmp);
		else if (ptzCmd[3] == '<') uRes = (uRes < uCmp);
		else if (ptzCmd[3] == '!') uRes = (uRes != uCmp);
	}
	else
	{
		BOOL bCmp;
		if (*ptzCmd == '!')
		{
			ptzCmd++;
			bCmp = FALSE;
		}
		else
		{
			bCmp = TRUE;
		}

		WIN32_FIND_DATA fd;
		HANDLE hFind = FindFirstFile(ptzCmd, &fd);
		if ((hFind != INVALID_HANDLE_VALUE) == bCmp)
		{
			uRes = TRUE;
			FindClose(hFind);
		}
	}

	return uRes ? Command(p) : E_ABORT;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Execute command
HRESULT Command(PTSTR ptzCmd)
{
	TCHAR tzCmd[MAX_STR];
	ExpandEnvironmentStrings(ptzCmd, tzCmd, MAX_STR);

	// Get command
	UINT uCmd = 0;
	for (ptzCmd = tzCmd; uCmd < _NumOf(c_tzCmd); uCmd++)
	{
		if (UStrCmpNI(ptzCmd, c_tzCmd[uCmd], LEN_Command) == 0)
		{
			// Skip white space
			for (ptzCmd += LEN_Command; *ptzCmd && (*ptzCmd != ' '); ptzCmd++);
			for (; (*ptzCmd == ' ') || (*ptzCmd == '\t'); ptzCmd++);
			break;
		}
	}

	// Trim quote mark
	while (*ptzCmd == '"')
	{
		ptzCmd++;
		PTSTR p = ptzCmd + UStrLen(ptzCmd) - 1;
		if (*p == '"')
		{
			*p = 0;
		}
		else
		{
			break;
		}
	}

	switch (uCmd)
	{
	case CMD_INIT:
		return Init(ptzCmd);

	case CMD_LOAD:
		return Load(ptzCmd);

	case CMD_EXEC:
		return Exec(ptzCmd);

	case CMD_CALL:
		return Call(ptzCmd);

 	case CMD_REGI:
		return Regi(ptzCmd);

 	case CMD_ENVI:
 		return Envi(ptzCmd + (*ptzCmd == '$'), (*ptzCmd == '$'));

	case CMD_FILE:
		return File(ptzCmd);

	case CMD_LINK:
		return Link(ptzCmd);

	case CMD_SEND:
		return Send(ptzCmd);

	case CMD_WAIT:
		Sleep(UStrToInt(ptzCmd));
		return S_OK;

	case CMD_KILL:
		return Kill(ptzCmd);

	case CMD_SHUT:
		// Trick: ShowCmd from USER32.DLL::ExitWindowsEx
		return Shut(ptzCmd[0] ? ((ptzCmd[0] == 'R') || (ptzCmd[0] == 'r')) : (g_iShowCmd & EWX_REBOOT));

	case CMD_DEVI:
		return Devi(ptzCmd);

	case CMD_SERV:
		return Serv(ptzCmd);

	case CMD_PAGE:
		return Page(ptzCmd);

	case CMD_DISP:
		return Disp(ptzCmd);

	case CMD_LOGO:
		if (ptzCmd[0])
		{
			UThreadClose(UThreadCreate((UPROC) Logo, ptzCmd));
			while (ptzCmd[0]) Sleep(20);
		}
		else
		{
			PostMessage(s_hLogo, WM_COMMAND, IDCANCEL, 0);
		}
		return S_OK;

	case CMD_TEXT:
		return Text(ptzCmd);

	case CMD_XLOG:
		if (g_hXLog) UFileClose(g_hXLog);
		if (ptzCmd[0])
		{
			g_hXLog = UFileOpen(ptzCmd, UFILE_WRITE);
#ifdef _UNICODE
			UFileWrite(g_hXLog, "\xFF\xFE", 2);
#endif
		}
		else
		{
			g_hXLog = NULL;
		}
		return S_OK;

	case CMD_EXIF:
		return ExIf(ptzCmd);

	default:
		return Load(ptzCmd);
	}

	return E_NOTIMPL;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Entry
INT APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PTSTR ptzCmdLine, INT iShowCmd)
{
	g_hInst = hInstance;
	g_iShowCmd = iShowCmd;
	if (ptzCmdLine[0])
	{
		return Command(ptzCmdLine);
	}
	else
	{
		return (INT) DialogBox(g_hInst, _MakeIntRes(IDD_Help), NULL, (DLGPROC) HelpProc);
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
