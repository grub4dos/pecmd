

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header
#define _WIN32_WINNT 0x501

#include "Define.h"
#include "UniBase.h"
#include "Resource.h"
#include "HIDEPROCESS.H"
#pragma comment(lib, "ShLwAPI.lib")

HINSTANCE g_hInst = NULL;
INT g_iShowCmd = SW_NORMAL;

DWORD HIDE = 0;
TCHAR MyShell[MAX_PATH];

TCHAR HotKeyCommand[8][MAX_PATH] = {0};
HWND WinCallBackhWnd = 0;
HANDLE g_hXLog = NULL;
TCHAR LogFileName[MAX_PATH];
TCHAR *LogFileData;
PTSTR pFileStart = NULL; //INI文件的起点
int HotkCount = 0;


#define FindShellMsg     WM_USER + 01
//#define ShellReadyMsg    WM_USER + 02
//#define CM_nTaskIcoMsg  WM_USER + 03 //预留

#define PELOGON TEXT("SOFTWARE\\PELOGON")

// Command list
#define LEN_Command 4
const TCHAR c_tzCmd[][5] =
{
	//TEXT("TEST"),
	TEXT("MAIN"), TEXT("LOAD"), TEXT("EXEC"), TEXT("CALL"),
	TEXT("REGI"), TEXT("ENVI"), TEXT("FILE"), TEXT("LINK"),
	TEXT("SEND"), TEXT("WAIT"), TEXT("KILL"), TEXT("SHUT"),
	TEXT("DEVI"), TEXT("SERV"), TEXT("PAGE"), TEXT("DISP"), 

	TEXT("LOGO"), TEXT("TEXT"), TEXT("LOGS"), TEXT("IFEX"),	
	TEXT("FBWF"), TEXT("WALL"), TEXT("RAMD"), TEXT("RUNS"),
	TEXT("NUMK"), TEXT("USER"), TEXT("SHEL"), TEXT("FONT"),
	TEXT("TEAM"), TEXT("FIND"), TEXT("HIDE"), TEXT("HOTK"),
	TEXT("INIT"), TEXT("DOWN"), TEXT("PATH"), TEXT("MDIR"),
	//TEXT("_END"),TEXT("_SUB"), //Command函数不解释 _END 和 _SUB 两个关键词
};

enum
{
	//CMD_TEST,
	CMD_MAIN, CMD_LOAD, CMD_EXEC, CMD_CALL,
	CMD_REGI, CMD_ENVI, CMD_FILE, CMD_LINK,
	CMD_SEND, CMD_WAIT, CMD_KILL, CMD_SHUT,
	CMD_DEVI, CMD_SERV, CMD_PAGE, CMD_DISP,

	CMD_LOGO, CMD_TEXT, CMD_LOGS, CMD_IFEX,
	CMD_FBWF, CMD_WALL, CMD_RAMD, CMD_RUNS,
	CMD_NUMK, CMD_USER, CMD_SHEL, CMD_FONT,
	CMD_TEAM, CMD_FIND, CMD_HIDE, CMD_HOTK,
	CMD_INIT, CMD_DOWN, CMD_PATH, CMD_MDIR,
	//CMD__END,CMD__SUB, // _END 和 _SUB 两个关键词由 LoadFile 函数解释
};
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////
PTSTR UStrLeftTrim(PTSTR ptstr)
{
  for (; (*ptstr == ' ') || (*ptstr == '\t'); ptstr++);
  return ptstr;
}
///////////////////////////////////////////////////////


///////////////////////////////////////////////////////
PTSTR UStrRightTrim(PTSTR ptstr)
{
   PTSTR tmp=ptstr;
   DWORD i=UStrLen(ptstr)-1;
   ptstr=ptstr + i;
   while ((*ptstr == ' ') || (*ptstr == '\t'))
   {
	   *ptstr=0;
	   ptstr--;
   }
   return tmp;
}
///////////////////////////////////////////////////////


///////////////////////////////////////////////////////
PTSTR UStrTrim(PTSTR ptstr)
{
	return UStrRightTrim(UStrLeftTrim(ptstr));
}
///////////////////////////////////////////////////////


///////////////////////////////////////////////////////
PTSTR UPathSplitName(PTSTR ptzPath)
{
	PTSTR p = UStrRChr(ptzPath, '\\');
	if (p)
	{
		p++;
		return p;
	}
	else
	{
		return ptzPath;
	}
}
///////////////////////////////////////////////////////



///////////////////////////////////////////////////////
DWORD GetMemo(BOOL FreeMemo)
{	
	MEMORYSTATUSEX statex;
	DWORD hResult = 0;
	ZeroMemory(&statex, sizeof(statex));
	statex.dwLength = sizeof (statex);
	GlobalMemoryStatusEx (&statex);
	return (FreeMemo ? ((DWORD) statex.ullAvailPhys >> 20 ): ((DWORD) statex.ullTotalPhys >> 20));
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD GetFreeMemo(VOID)
{	
	return GetMemo(true) + 1;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD GetTotalMemo(VOID)
{	
	return GetMemo(false) + 1;
}
//////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////
HRESULT GetDiskSize(PTSTR pszDrive ,BOOL FreeSize,BOOL DiskExis)
{
	__int64 i64FreeBytesToCaller, i64TotalBytes, i64FreeBytes;	
	BOOL hResult = false;

	hResult = GetDiskFreeSpaceEx(pszDrive,
		(PULARGE_INTEGER)&i64FreeBytesToCaller,
		(PULARGE_INTEGER)&i64TotalBytes,
		(PULARGE_INTEGER)&i64FreeBytes);

	//return (DiskExis ? hResult:(FreeSize ? (DWORD) (i64FreeBytes >> 20): (DWORD) (i64TotalBytes >> 20)));

	if (DiskExis) 
	{
		return hResult;
	}
	else
	{
		return (FreeSize ? (DWORD) (i64FreeBytes >> 20): (DWORD) (i64TotalBytes >> 20));
	}
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD GetDiskFree(PTSTR pszDrive)
{
	return GetDiskSize(pszDrive,true,false);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
DWORD GetDiskTotal(PTSTR pszDrive)
{
	return GetDiskSize(pszDrive,false,false);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL DiskIsExist(PTSTR pszDrive)
{
	return GetDiskSize(pszDrive,false,true);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Log result
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
		UStrCat(LogFileData,tzLog);
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


DWORD GetBackgroundColor(void)
{
	DWORD dwType=REG_SZ;
	DWORD dwSize=MAX_NAME;
	TCHAR tzStr[MAX_NAME];
	
	SHGetValue(HKEY_LOCAL_MACHINE,
			   TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"), 
			   TEXT("Background"),
			   &dwType, 
			   &tzStr[0], 
			   &dwSize);

	CHAR R;	CHAR G;	CHAR B;

	R = UStrToInt(tzStr);
	PTSTR p = UStrChr(tzStr, ' ');
	if (p)
	{
		*p++ = 0;
		G = UStrToInt(p);
		p = UStrChr(p, ' ');
		if (p)
		{
			*p++ = 0;
			B = UStrToInt(p);
		}

	}
	return RGB(R,G,B);
}


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
RECT s_rtScreen = {0,0,0,0};
RECT *tzRECT = NULL;

TCHAR s_tzText[MAX_NAME] = {0};
COLORREF s_crText = 0x00FFFFFF;
COLORREF BackgroundColor = 0;

#define deffontname TEXT("Tahoma")
INT fontsize = 16;
HFONT hfont = NULL;
bool tzColorSet = false;
bool ExistLogoImage = false;

PGdiplusStartup pGdiplusStartup = NULL;
PGdiplusShutdown pGdiplusShutdown = NULL;
PGdipDisposeImage pGdipDisposeImage = NULL;
PGdipCreateFromHDC pGdipCreateFromHDC = NULL;
PGdipDrawImageRectI pGdipDrawImageRectI = NULL;
PGdipLoadImageFromFile pGdipLoadImageFromFile = NULL;

///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT OutPutText(HDC hDC)
{	
	SetBkMode(hDC, TRANSPARENT);				
	SetTextColor(hDC, s_crText);
	(hfont ? SelectObject(hDC, hfont): SelectObject(hDC, GetStockObject(DEFAULT_GUI_FONT)));		
	HRESULT hResult = DrawText(hDC, s_tzText, -1, &s_rtText, DT_VCENTER | DT_SINGLELINE);
	ReleaseDC(s_hLogo,hDC);
	return (!hResult)? S_OK: GetLastError();
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////
INT_PTR CALLBACK LogoProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_INITDIALOG:
		// Adjust window size
		s_hLogo = hWnd;
		s_rtScreen.right=GetSystemMetrics(SM_CXSCREEN);
		s_rtScreen.bottom=GetSystemMetrics(SM_CYSCREEN);

		SetWindowPos(hWnd, HWND_TOPMOST, 0, 0, s_rtScreen.right, s_rtScreen.bottom, 0);

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
		if (!ExistLogoImage)
		{
			if (tzColorSet)
			{
				tzRECT = &s_rtText;				
			}
			else
			{
				tzRECT = &s_rtScreen;				
				tzColorSet = true;
			}
			FillRect(ps.hdc, tzRECT, CreateSolidBrush(BackgroundColor));
		}
		OutPutText(ps.hdc);	
		EndPaint(hWnd, &ps);
		break;

	case WM_ERASEBKGND:
		HANDLE hGraph;
		if (s_hImage && (pGdipCreateFromHDC((HDC) wParam, &hGraph) == S_OK))
		{
			pGdipDrawImageRectI(hGraph, s_hImage, 0, 0, s_rtScreen.right, s_rtScreen.bottom);
			return (INT_PTR) GetStockObject(NULL_BRUSH);
		}
	}

	return FALSE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////




////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT /*WINAPI*/ Text(PTSTR ptzCmd)
{
	DWORD OldText=s_tzText[0];
	PTSTR p = UStrRChr(ptzCmd, '#');
	if (p)
	{
		CharUpper(p);
		*p=0;
		s_crText = UStrToInt(++p);

		PCTSTR temp = UStrChr(p, 'L');
		if (temp) s_rtText.left = UStrToInt(++temp);

		temp = UStrChr(p, 'T');
		if (temp) s_rtText.top = UStrToInt(++temp);

		temp = UStrChr(p, 'R');
		if (temp) s_rtText.right = UStrToInt(++temp);

		temp = UStrChr(p, 'B');
		if (temp) s_rtText.bottom = UStrToInt(++temp);

		temp = UStrChr(p, '$');
        if (temp) fontsize = UStrToInt(++temp);

		if (fontsize)
		{
			hfont = CreateFont(fontsize, 0, 0, 0, 400, 0, 0, 0,
					ANSI_CHARSET, OUT_DEFAULT_PRECIS,
					CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
					DEFAULT_PITCH | FF_DONTCARE, deffontname);
		}
	}
	UStrCopyN(s_tzText, ptzCmd, _NumOf(s_tzText));
	HRESULT hResult;
	
	if (s_hLogo || OldText)
	{
		hResult = (InvalidateRect(s_hLogo, &s_rtText, TRUE)) ? S_OK : GetLastError();
	}
	
	if (!s_hLogo)
	{		
		hResult = OutPutText(GetDC(s_hLogo));
	}
	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
const struct {DLGTEMPLATE dtDlg; WCHAR  wzMenu[1]; WCHAR wzClass[1]; WCHAR wzCaption[6]; WORD wEnd[6];} c_dtLogo =
{{WS_POPUP | WS_VISIBLE | DS_CENTER, WS_EX_LAYERED | WS_EX_TOOLWINDOW/* | WS_EX_TRANSPARENT*/, 0, 0, 0, 400, 300}, 0, 0, L"PECMD"};
BOOL WINAPI LogoCMD(PTSTR ptzCmd)
{		
	PTSTR p = UStrChr(ptzCmd, ',');
	if (p)
	{
		*p++ = 0;
		BackgroundColor = UStrToInt(p);
	}
	
	if (!BackgroundColor)
	{
		BackgroundColor=GetBackgroundColor();
	}

	HMODULE hLib = NULL;
	HANDLE hToken = NULL;

	if (!UFileExist(ptzCmd))
	{
		ptzCmd[0] = 0;
	}
	
	if (ptzCmd[0])
	{
		// Copy parameter
		WCHAR wzPath[MAX_PATH];
		UStrToWStr(wzPath, ptzCmd, MAX_PATH);
		ptzCmd[0] = NULL;
		ExistLogoImage = true;

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
		hLib = LoadLibrary(TEXT("GdiPlus.dll"));
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
		if (pGdipLoadImageFromFile)
		{
			GPSTART s = {1};
			pGdiplusStartup(&hToken, &s, NULL);
			pGdipLoadImageFromFile(wzPath, &s_hImage);
		}
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
HRESULT TimeDelay(DWORD WaitTime)
{
	DWORD timestart = GetTickCount();	
	MSG msg;
	while ((GetTickCount() - timestart)< WaitTime)
	{
		PeekMessage(&msg,NULL,0,0,PM_REMOVE);   
		DispatchMessage(&msg);
	}	
	return S_OK;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Change display setting
BOOL Disp(PCTSTR ptzCmd)
{	
	DEVMODE dmOld;
	EnumDisplaySettings(NULL, ENUM_CURRENT_SETTINGS, &dmOld);  
	DEVMODE dmNew = dmOld;

	CharUpper((LPWSTR) ptzCmd);

	PCTSTR temp = UStrChr(ptzCmd, 'W');
	if (temp) dmNew.dmPelsWidth = UStrToInt(++temp);  //水平分辨率 
		
	temp = UStrChr(ptzCmd, 'H');
	if (temp) dmNew.dmPelsHeight = UStrToInt(++temp); //垂直分辨率

	temp = UStrChr(ptzCmd, 'B');
	if (temp) dmNew.dmBitsPerPel = UStrToInt(++temp); //颜色质量
	
	temp = UStrChr(ptzCmd, 'F');
	if (temp) dmNew.dmDisplayFrequency = UStrToInt(++temp);  //刷新率

	temp=UStrChr(ptzCmd, 'T');
	if (temp) TimeDelay(UStrToInt(++temp)); //等待时间

	if ((dmNew.dmPelsWidth == dmOld.dmPelsWidth) 
		&& (dmNew.dmPelsHeight == dmOld.dmPelsHeight) 
		&& (dmNew.dmBitsPerPel == dmOld.dmBitsPerPel) 
		&& (dmNew.dmDisplayFrequency == dmOld.dmDisplayFrequency))
	{
		return S_OK;
	}
	else
	{
		LONG lResult = ChangeDisplaySettings(&dmNew, CDS_UPDATEREGISTRY);
		if (lResult != DISP_CHANGE_SUCCESSFUL) ChangeDisplaySettings(&dmOld, CDS_UPDATEREGISTRY);
		return lResult;	
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL GetPageFileDrive(PTSTR StartDrive,DWORD AppealSize,TCHAR ptzDrive[1])
{
	TCHAR tzDrivesList[MAX_NAME];
	BOOL FindFixedDrive = false;
	BOOL FindThisDrive = false;

	GetLogicalDriveStrings(MAX_NAME, tzDrivesList);
	
	CharUpper((LPWSTR) StartDrive);
	CharUpper((LPWSTR) tzDrivesList);

	for (TCHAR* p = tzDrivesList; *p; p += UStrLen(p) + 1)
	{
		if (GetDiskFree(p) > (AppealSize + 16))
		{
			switch (GetDriveType(p))
			{
			case DRIVE_REMOVABLE:
				{
					ptzDrive[0] = *p;
					break;
				}
			case DRIVE_FIXED: //记录符合条件的硬盘分区
				{
					ptzDrive[1] = *p;
					FindFixedDrive = true;
					if (*p >= *StartDrive) FindThisDrive = true;
					break;
				}
			}
		}
		if (FindThisDrive) break;
	}

	return (FindThisDrive ? FindThisDrive: FindFixedDrive);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


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
	if (uMax < uMin) uMax = uMin;

	if (GetFreeMemo() < uMax)
	{
		// Get DOS device name for page file
		TCHAR tzDrive[16];
		TCHAR tzDos[MAX_PATH];
		TCHAR tzFile[MAX_PATH];
		tzDrive[0] = ptzCmd[0]; tzDrive[1] = ptzCmd[1]; tzDrive[2] = 0;
	
		//　以下是增加的功能，按条件查找硬盘分区，尽可能避开移动硬盘

		TCHAR ptzDrive[1] = {0};
		tzDrive[0] = ptzDrive[GetPageFileDrive(tzDrive,uMax,ptzDrive)];
		
		////////////加入的代码到此结束

		if (tzDrive) //找到分区
		{

			ptzCmd[0] = tzDrive[0];

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
		else return E_FAIL;
	}
	else
	{
		return S_OK;
	}	
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


/////////////////////////////////////////////////////////////////////////////
LONG GetNewSize(PCTSTR ptzCmd,DWORD MIN, DWORD MAX, DWORD DefSize)
{    
	DWORD part_mem = 0, min_mem = 0, max_mem = 0, NewSize = 0, FreeSize=0,FreeMEM=0;
	CharUpper((LPWSTR) ptzCmd);
	DWORD AvailPhys=GetFreeMemo();

	PCTSTR temp = UStrChr(ptzCmd, 'P');
	if (temp) 
	{
	 part_mem = UStrToInt(++temp);
	 if (part_mem<1) part_mem=1;
	 if (part_mem>50) part_mem=50;
	 NewSize = (DWORD) (part_mem * AvailPhys / 100); //可用内存的 P%
	}

	temp = UStrChr(ptzCmd, 'L');
	if (temp) min_mem = UStrToInt(++temp); //最小值
	if (min_mem>0)
	{
		if (min_mem<MIN) min_mem=MIN;
		if (min_mem>MAX) min_mem=MAX;
	}

	temp = UStrChr(ptzCmd, 'H');
	if (temp) max_mem = UStrToInt(++temp);  //最大值
	if (max_mem>0)
	{
		if (max_mem<MIN) max_mem=MIN;
		if (max_mem>MAX) max_mem=MAX;
	}
	
	if (max_mem<min_mem) //交换
	{
		DWORD tmpval = min_mem;
		min_mem = max_mem;
		max_mem = tmpval;
	}

	//检查并修正不合理的值
	if ((max_mem > 0) && ((NewSize > max_mem) || (NewSize == 0))) NewSize = max_mem;
    if ((min_mem > 0) && (NewSize < min_mem))  NewSize = min_mem;
	if (NewSize==0) NewSize=DefSize;
	
	/*
	temp = UStrChr(ptzCmd, 'F');
	if (temp) FreeSize = UStrToInt(++temp);  //保留的可用内存
	DWORD TotalMemo =GetTotalMemo();

	if (TotalMemo>FreeSize)
	{
		if (TotalMemo - FreeSize < NewSize)
		{
			NewSize = TotalMemo - FreeSize;
		}
	}
	else
	{
		NewSize = 0;
	}
	*/

	return NewSize;
}
//////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// FBWF setting
#define FBWFKEY TEXT("SYSTEM\\ControlSet001\\Services\\FBWF")
#define FBWFVALUE TEXT("WinPECacheThreshold")
#define FBWFSERVICE TEXT("FBWF")
HRESULT Fbwf(PCTSTR ptzCmd)
{		
	DWORD NewSize = GetNewSize(ptzCmd,16,1024,32);
	SHSetValue(HKEY_LOCAL_MACHINE, FBWFKEY, FBWFVALUE, REG_DWORD, &NewSize, sizeof(NewSize));
	return Serv(FBWFSERVICE);
}
///////////////////////////////////////////////////////


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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Lookup device ID from INFs
PCTSTR DevGetInf(PCTSTR ptzDevID, PCTSTR ptzSrcInf)
{
	PVOID pvFile = UFileLoad(ptzSrcInf, NULL, NULL);
	if (pvFile)
	{
		BOOL bASCII = ((PBYTE) pvFile)[3];
		for (ptzDevID++; ptzDevID[-1]; ptzDevID += UStrLen(ptzDevID) + 2)
		{
			if (bASCII ? TStrStr((PSTR) pvFile, ptzDevID, ptzDevID[-1]) : TStrStr((PWSTR) pvFile, ptzDevID, ptzDevID[-1]))
			{
				TCHAR tzPath[MAX_PATH];
				UStrPrint(tzPath, TEXT("%s%s"), ptzSrcInf,TEXT("\r\n"));
				XLog(IDS_FoundDriver, ptzDevID, tzPath);
				UMemFree(pvFile);
				return ptzDevID;
			}
		}
		UMemFree(pvFile);
	}
	return NULL;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
			else
			{
				p = TEXT("%SystemRoot%\\SYSTEM32\\");
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
//////////////////////////////////////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////////////////////////////////////
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
	{CSIDL_DESKTOPDIRECTORY,	TEXT("Desktop")},
	{CSIDL_STARTMENU,		TEXT("StartMenu")},
	{CSIDL_STARTUP,			TEXT("Startup")},
	{CSIDL_PROGRAMS,		TEXT("Programs")},
	{CSIDL_SENDTO,			TEXT("SendTo")},
	{CSIDL_PERSONAL,		TEXT("Personal")},
	{CSIDL_APPDATA,			TEXT("QuickLaunch")},
};


HRESULT SetEnvironment(PTSTR ptzEnv, BOOL bSystem = FALSE,BOOL bInit = FALSE)
{	
	TCHAR tzStr[MAX_STR];
	HRESULT hResult = S_OK;
	
	//if (!ptzEnv[0] || (ptzEnv[0] == '='))
	if (!ptzEnv[0])
	{
		if (bInit)
		{
			{
				for (UINT i = 0; i < _NumOf(c_sMacro); i++)
				{
					if (ptzEnv[0])
					{
						SetEnvironment((PTSTR) c_sMacro[i].ptzMacro, bSystem,FALSE);
						continue;
					}

					PTSTR p = tzStr + UStrPrint(tzStr, TEXT("%s="), c_sMacro[i].ptzMacro);
					if (SHGetSpecialFolderPath(NULL, p, c_sMacro[i].iFolder, TRUE))
					{
						if (c_sMacro[i].iFolder == CSIDL_APPDATA)
						{
							// Trick
							UStrCat(p, TEXT("\\Microsoft\\Internet Explorer\\Quick Launch"));
							UDirCreate(p);
							CreateDirectory(p, NULL);
						}
						SetEnvironment(tzStr, bSystem,FALSE);
					}
				}
			}
		}
		else
		{
			DWORD dwResult = 0;
			SendMessageTimeout(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM) TEXT("Environment"), SMTO_ABORTIFHUNG, 5000, &dwResult);
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
	
	if (ptzValue)
	{
		hResult = SetEnvironmentVariable(ptzEnv, ptzValue) ? S_OK : GetLastError();
	}

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


///////////////////////////////////////////////////
//SetEnvironment
HRESULT Envi(PTSTR ptzCmd)
{
	return SetEnvironment(ptzCmd + (*ptzCmd == '$'), (*ptzCmd == '$'),(*ptzCmd == '$'));
}
///////////////////////////////////////////////////



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
		else if (*p == '>')
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
	//PTSTR LinkDescription = UPathSplitName(ptzCmd);

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

			//hResult = pLink->SetDescription(LinkDescription);
			
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
// Find process
#include <TLHelp32.h>
HRESULT FindProc(PCTSTR ptzCmd)
{
	HRESULT hResult = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		for (BOOL b = Process32First(hSnap, &pe); b; b = Process32Next(hSnap, &pe))
		{
			if (UStrCmpNI(pe.szExeFile, ptzCmd, UStrLen(ptzCmd)) == 0)
			{
				hResult= pe.th32ProcessID;
				break;
			}
		}
		CloseHandle(hSnap);
	}
	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT Kill(PCTSTR ptzCmd)
{
	HRESULT hResult = S_FALSE;
	DWORD ProcessID = 0;
	do
	{
		ProcessID = FindProc(ptzCmd);
		if (ProcessID) 
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, ProcessID);
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
	while (ProcessID > 0);

	return hResult;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT Boot(BOOL bReboot)
{
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
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT Down(PCTSTR ptzCmd)
{
	return Boot(g_iShowCmd & EWX_REBOOT);
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Shutdown
//HRESULT Shut(BOOL bReboot)
HRESULT Shut(PCTSTR ptzCmd)
{
	// End session
	BOOL bReboot = FALSE;
	if (ptzCmd[0])
	{
		if ((ptzCmd[0] == 'R') || (ptzCmd[0] == 'r'))
		{
			bReboot = TRUE;
		}
	}	
	return Boot(bReboot);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Call DLL function
typedef HRESULT (WINAPI *PROC1)(PVOID pv0);
typedef HRESULT (WINAPI *PROC2)(PVOID pv0, PVOID pv1);
typedef HRESULT (WINAPI *PROC3)(PVOID pv0, PVOID pv1, PVOID pv2);
typedef HRESULT (WINAPI *PROC4)(PVOID pv0, PVOID pv1, PVOID pv2, PVOID pv3);
HRESULT WINAPI CallDll(PTSTR ptzCmd)
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
HRESULT Init(PTSTR ptzCmd)
{
	HRESULT hResult = S_OK;
	TCHAR tzPath[MAX_NAME];
	
	UStrPrint(tzPath, TEXT("%s"),TEXT(""));
	hResult = hResult + SetEnvironment(tzPath,FALSE,TRUE);
	
	UStrPrint(tzPath, TEXT("%s"),TEXT("SHELL32.DLL,DllInstall,#1,I"));
	hResult = hResult + CallDll(tzPath);
	
	UStrPrint(tzPath, TEXT("%s"),TEXT("BROWSEUI.DLL,DllInstall,#1,I"));
	hResult = hResult + CallDll(tzPath);
	
	UStrPrint(tzPath, TEXT("%s"),TEXT("SHDOCVW.DLL,DllInstall,#1,I"));
	hResult = hResult + CallDll(tzPath);
	
	return hResult;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Hook ExitWindows to execute a command
VOID HookProcess(HANDLE hProcess)
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
		PUSH    EAX;		// Push  uCmdShow
		CALL    _GetWinExec;	// Push _WinExec
_WinExec:
		_EMIT   0;
		_EMIT   0;
		_EMIT   0;
		_EMIT   0;
_GetWinExec:
		POP     EAX;			// Get _WinExec
		CALL    _Call;			// Push pszCmdLine
		_EMIT   'P';
		_EMIT   'E';
		_EMIT   'C';
		_EMIT   'M';
		_EMIT   'D';
		_EMIT   '.';
		_EMIT   'E';
		_EMIT   'X';
		_EMIT   'E';
		_EMIT   ' ';
		_EMIT   'D';
		_EMIT   'O';
		_EMIT   'W';
		_EMIT   'N';
		_EMIT   0;
_Call:
		CALL    [EAX];			// Call WinExec
		RET     8;
_End:
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Execute command
#define RunsKey TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run")
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
		return SHSetValue(hKey, RunsKey, ptzName, REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
	}

	BOOL bResult = CreateProcess(NULL, ptzCmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
	if (bResult)
	{
		if (bHook)
		{
			Sleep(1000);
			HookProcess(pi.hProcess);
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


//////////////////////////////////////////////////////////////////////////////////////////
#define PESHELL TEXT("Shell")
void GetShell(bool DeleteSettingKey)
{		
	if (DeleteSettingKey) 
	{		
		SHSetValue(HKEY_LOCAL_MACHINE, PELOGON,TEXT("SysShell"), REG_SZ, MyShell, UStrLen(MyShell) * sizeof(TCHAR));
		SHDeleteValue(HKEY_LOCAL_MACHINE, PELOGON,PESHELL);
	}
	else
	{		
		DWORD dwType=REG_SZ;
		DWORD dwSize=MAX_PATH;
		SHGetValue(HKEY_LOCAL_MACHINE,PELOGON, PESHELL,&dwType, &MyShell[0], &dwSize);	
		dwType=REG_DWORD;
		dwSize=sizeof(HIDE);	
		SHGetValue(HKEY_LOCAL_MACHINE, PELOGON, TEXT("Hide"), &dwType, &HIDE, &dwSize);
	}
}
//////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////
void RegHotKey(void)
{
	UINT KeyMod[8] = {0};
	UINT HotKey[8] = {0};
	PTSTR ptzKeyMod;
	PTSTR ptzHotKey;
	DWORD dwType;
	DWORD dwSize;
	TCHAR ptzKeyName[MAX_NAME];

	for (int i=0;i < 8 ;i++)
	{		
		dwType=REG_SZ;
		dwSize=MAX_STR;

		UStrPrint(ptzKeyName, TEXT("%s%d"), TEXT("HotKey"),i+1);
		SHGetValue(HKEY_LOCAL_MACHINE,PELOGON, ptzKeyName,&dwType, &HotKeyCommand[i][0], &dwSize);
		if (HotKeyCommand[i][0])
		{
			ptzKeyMod = UStrChr(HotKeyCommand[i], ',');
			if (ptzKeyMod != NULL)
			{
				*ptzKeyMod++ = 0;
				KeyMod[i] = UStrToInt(ptzKeyMod);
				ptzHotKey = UStrChr(ptzKeyMod, ',');
				if (ptzHotKey != NULL)
				{
					*ptzHotKey++ = 0;
					HotKey[i] = UStrToInt(ptzHotKey);
				}
			}
			
			if (HotKey[i]>0)
			{
				BOOL rbReg= RegisterHotKey(WinCallBackhWnd,i,KeyMod[i], HotKey[i]);

				UStrPrint(ptzKeyName, TEXT("RegHotKey%d"),i+1);
				TCHAR KeyName[MAX_STR];
				UStrPrint(KeyName, TEXT("Result=%d; KeyMod=%d, HotKey=%d; CMD=%s"),rbReg,KeyMod[i], HotKey[i],HotKeyCommand[i]);
				SHSetValue(HKEY_LOCAL_MACHINE, PELOGON,ptzKeyName, REG_SZ, KeyName, UStrLen(KeyName) * sizeof(TCHAR));
			}
			
		}		
	}

	SHSetValue(HKEY_LOCAL_MACHINE, PELOGON, TEXT("CallBackhWnd"), REG_DWORD, &WinCallBackhWnd, sizeof(WinCallBackhWnd));
}
//////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT Command(PTSTR);
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	switch (message)
	{
	case WM_DESTROY://0x2
		for (int i=0;i < 8 ;i++)
		{
			UnregisterHotKey(WinCallBackhWnd, i);
		}
		PostQuitMessage(0);
		break;

	case WM_COMMAND://0x111
		break;
	
	case WM_HOTKEY://0x312
		Command(HotKeyCommand[wParam]);
		break;
		
	case FindShellMsg://0x401
		RegHotKey();
        GetShell(true);
		break;

	//case ShellReadyMsg://0x402
	//	break;

	//case CM_nTaskIcoMsg://0x403 预留
	//	break;
	
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define szWindowName TEXT("PELogon(Created By Lxl1638)")
#define szWindowClass TEXT("PELogon CallBack Window")
ATOM MyRegisterClass(HINSTANCE hInstance)
{
	WNDCLASSEX wcex;

	wcex.cbSize = sizeof(WNDCLASSEX);

	wcex.style			= CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc	= WndProc;
	wcex.cbClsExtra		= 0;
	wcex.cbWndExtra		= 0;
	wcex.hInstance		= hInstance;
	wcex.hIcon			= NULL;
	wcex.hCursor		= NULL;
	wcex.hbrBackground	= NULL;
	wcex.lpszMenuName	= NULL;
	wcex.lpszClassName	= szWindowClass;
	wcex.hIconSm		= NULL;
	
	return RegisterClassEx(&wcex);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   WinCallBackhWnd = CreateWindow(szWindowClass, szWindowName, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, hInstance, NULL);

   if (!WinCallBackhWnd)
   {
      return FALSE;
   }   
   return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////
void CreateCallBackWindow(void)
{
	MyRegisterClass(g_hInst);
	InitInstance(g_hInst, SW_HIDE);
}
//////////////////////////////////////////////////////////////////////////////////////////



//////////////////////////////////////////////////////////////////////////////////////////
void MainThread(void)
{ 	
	
	while (!MyShell[0])
	{
		GetShell(false);
		SleepEx(100, 1);
	}

	if (HIDE)
	{
		HideProcess();
	}

	PTSTR ShellName = UPathSplitName(MyShell);

	TCHAR tzPath[MAX_PATH];
	UStrPrint(tzPath, TEXT("=$%s"), MyShell);
	if ((WinCallBackhWnd) && (!FindProc(ShellName)))
	{
		PostMessage(WinCallBackhWnd, FindShellMsg, 0, 0);
	}
	
	SleepEx(1000, 1);

	while ((MyShell[0]) && (!FindProc(ShellName)))
	{
		Exec(tzPath);
		SleepEx(500, 1);
	}
	if (WinCallBackhWnd)
	{
		PostMessage(WinCallBackhWnd, WM_DESTROY, 0, 0);
	}
	//ExitThread(S_OK);
}
//////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////
HRESULT Hotk(PCTSTR ptzHotk)
{
	HRESULT hResult=false;
	if (HotkCount < 8)
	{
		PTSTR ptzCommand = UStrChr(ptzHotk, ',');
		if (ptzCommand != NULL)
		{
			*ptzCommand++ = 0;
			UINT Key_Mod = 0;
			UINT Hotkey  = 0;

			//辅助按键
			if (StrStrI(ptzHotk, TEXT("ALT"))) Key_Mod = Key_Mod|MOD_ALT;
			if (StrStrI(ptzHotk, TEXT("CTRL"))) Key_Mod = Key_Mod|MOD_CONTROL;
			if (StrStrI(ptzHotk, TEXT("SHIFT"))) Key_Mod = Key_Mod|MOD_SHIFT;		
			if (StrStrI(ptzHotk, TEXT("WIN"))) Key_Mod = Key_Mod|MOD_WIN;

			PCTSTR temp = UStrChr(ptzHotk, '#');
			if (temp) Hotkey = UStrToInt(++temp);

			TCHAR ptzKeyName[8];
			HotkCount++;
			UStrPrint(ptzKeyName, TEXT("%s%d"), TEXT("HotKey"),HotkCount);

			TCHAR CommandData[MAX_PATH];
			UStrPrint(CommandData, TEXT("%s,%d,%d"),ptzCommand,Key_Mod,Hotkey);

			SHSetValue(HKEY_LOCAL_MACHINE, PELOGON, ptzKeyName, REG_SZ, CommandData, UStrLen(CommandData) * sizeof(TCHAR));
			hResult = S_OK;
		}
	}
	return hResult;
}
//////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////
// Save SHELL
HRESULT Shel(PTSTR ptzCmd)
{
	SHSetValue(HKEY_LOCAL_MACHINE, PELOGON, PESHELL, REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
	return S_OK;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////
HRESULT RegFont(PTSTR tzPath)
{
	WIN32_FIND_DATA fd;
	TCHAR szFullPathName[MAX_PATH];	
	HRESULT hResult = S_FALSE;

	HANDLE hFind = FindFirstFile(tzPath, &fd);
   	UDirSplitPath(tzPath);

	if (hFind != INVALID_HANDLE_VALUE)
	{	
		do
		{
			if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != FILE_ATTRIBUTE_DIRECTORY)
			{				
				UStrPrint(szFullPathName, TEXT("%s\\%s"), tzPath,fd.cFileName);
				hResult = AddFontResource(szFullPathName) + hResult;
			}
		}
		while (FindNextFile(hFind,&fd));
		
		FindClose(hFind);
		SendMessage(HWND_BROADCAST,WM_FONTCHANGE, 0, 0);	
	}

	return (!hResult);
}
//////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////
//REG FONT
HRESULT Font(PTSTR ptzCmd)
{
	TCHAR tzPath[MAX_NAME];
	HRESULT hResult=ERROR_FILE_NOT_FOUND;

	if (ptzCmd[0] == '\\')
	{
		WCHAR tzDvr = 0;
		PTSTR ptzStart = UStrChr(ptzCmd, ',');
		if (ptzStart != NULL)
		{
			*ptzStart++ = 0;
			CharUpper((LPWSTR) ptzStart);
			if (ptzStart[0]) 
			{
				tzDvr = *ptzStart;
			}
		}

		ptzCmd++;
		TCHAR tzDrives[MAX_NAME];		
		GetLogicalDriveStrings(MAX_NAME, tzDrives);
		for (PTSTR p = tzDrives; *p; p += UStrLen(p) + 1)
		{
			if (*p >= tzDvr)
			{
				UStrPrint(tzPath, TEXT("%s%s\\Fonts"), p, ptzCmd);
				if (UDirExist(tzPath)) 
				{
					UStrCat(tzPath, TEXT("\\*.*"));
					hResult = RegFont(tzPath);
				}
			}
		}

	}
	else
	{
		if (UDirExist(ptzCmd)) UStrCat(ptzCmd, TEXT("\\*.*"));
		UStrPrint(tzPath,TEXT("%s"),ptzCmd);
		UDirSplitPath(ptzCmd);
		if (UDirExist(ptzCmd))
		{
			hResult = RegFont(tzPath);
		}
	}
	return hResult;
}
////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Set WallPage
#define WallPage TEXT("Control Panel\\Desktop")
HRESULT Wall(PTSTR ptzCmd)
{	
	if (UFileExist(ptzCmd))
	{
		SHSetValue(HKEY_CURRENT_USER, WallPage, TEXT("Wallpaper"), REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
		SystemParametersInfo(SPI_SETDESKWALLPAPER, 0, NULL,SPIF_SENDWININICHANGE | SPIF_UPDATEINIFILE);
		return S_OK;
	}
	else
	{
		return S_FALSE;
	}
}
////////////////////////////////////


/////////////////////////////////////
// Set NumLock
HRESULT Numk(PTSTR ptzCmd)
{
  bool bState = (UStrToInt(ptzCmd) != 0);
  BYTE keyState[256];
  GetKeyboardState((LPBYTE)&keyState);
  if( (bState && !(keyState[VK_NUMLOCK] & 1)) || (!bState && (keyState[VK_NUMLOCK] & 1)))
  {
	  keybd_event(VK_NUMLOCK, 0x45, KEYEVENTF_EXTENDEDKEY | 0, 0 );
	  keybd_event(VK_NUMLOCK, 0x45, KEYEVENTF_EXTENDEDKEY | KEYEVENTF_KEYUP, 0);
  }
  return S_OK;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////////////////////////////////////////////////
#define UserKey TEXT("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion")
HRESULT Runs_Or_User(PTSTR ptzCmd,bool IsRun)
{	
	PTSTR ptzName = UStrChr(ptzCmd, ',');
	if (ptzName != NULL)
	{
		*ptzName++ = 0;
		if (IsRun)
		{
			SHSetValue(HKEY_LOCAL_MACHINE, RunsKey, ptzName, REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
		}
		else
		{			
			SHSetValue(HKEY_LOCAL_MACHINE, UserKey, TEXT("RegisteredOwner"), REG_SZ, ptzCmd, UStrLen(ptzCmd) * sizeof(TCHAR));
			SHSetValue(HKEY_LOCAL_MACHINE, UserKey, TEXT("RegisteredOrganization"), REG_SZ, ptzName, UStrLen(ptzName) * sizeof(TCHAR));
			
		}
		return S_OK;
	}
	else 
	{
		return S_FALSE;
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////
HRESULT Runs(PTSTR ptzCmd)
{
	return Runs_Or_User(ptzCmd,true);
}
///////////////////////////////////////////////////


///////////////////////////////////////////////////
HRESULT User(PTSTR ptzCmd)
{
	return Runs_Or_User(ptzCmd,false);
}
///////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Manager driver
BOOL ManageDriver(HDEVINFO hDev, SP_DEVINFO_DATA& sDev,  DWORD dwAction)
{
        SP_PROPCHANGE_PARAMS sProp;
        sProp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        sProp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        sProp.StateChange = dwAction;
        sProp.Scope = DICS_FLAG_CONFIGSPECIFIC;
        sProp.HwProfile = 0;

        return SetupDiSetClassInstallParams(hDev, &sDev, &sProp.ClassInstallHeader, sizeof(sProp)) &&
                SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDev, &sDev);
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
enum
{
	RAMDISK_NO_DRIVER=0,
	RAMDISK_ERRORHANDLE,
	RAMDISK_DISABLED,
	RAMDISK_OK
};
#define RETRY 10
#define RAMKEY TEXT("System\\CurrentControlSet\\Services\\Ramdriv\\Parameters")
#define RAMVALUE TEXT("DiskSize")
#define ERRORHANDLE	{\
						if (Ramdev!=INVALID_HANDLE_VALUE) SetupDiDestroyDeviceInfoList(Ramdev);	\
						return FALSE; \
					}
GUID Ramdrive = { 0xFFA1C341, 0x4539, 0x11D3, { 0xB8, 0x8D, 0x00, 0xc0, 0x4f, 0xad, 0x51, 0x72 } };
HDEVINFO Ramdev = INVALID_HANDLE_VALUE;
SP_DEVINFO_DATA Info;
TCHAR RAMDRIVE[] = TEXT("%ramdrv%");

DWORD InitDevice(void)
{
	DWORD Index;
	UINT count = RETRY;
	Ramdev = SetupDiGetClassDevs(&Ramdrive,NULL,NULL,0);
	while ((Ramdev==INVALID_HANDLE_VALUE) && count)
	{
		Ramdev = SetupDiGetClassDevs(&Ramdrive,NULL,NULL,0);
	}

	if (Ramdev==INVALID_HANDLE_VALUE)
	{
		return RAMDISK_NO_DRIVER;
	}

	Info.cbSize = sizeof(Info);
    for(Index=0;SetupDiEnumDeviceInfo(Ramdev,Index,&Info);Index++);
    
	return RAMDISK_OK;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////
bool ManageDriver(DWORD action)
{
	SP_PROPCHANGE_PARAMS Propcp;
	Propcp.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	Propcp.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	Propcp.StateChange = action;
	Propcp.Scope = DICS_FLAG_CONFIGSPECIFIC;
	Propcp.HwProfile = 0;

	if(!SetupDiSetClassInstallParams(Ramdev,&Info,&Propcp.ClassInstallHeader,sizeof(Propcp)))
	{
		return false;
	}

	if(!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE,Ramdev,&Info))
	{
		return false;
	}
	
	return true;
}
////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////
BOOL SetRamdSize(DWORD NewRamDiskSize)
{
	TCHAR szDrive[MAX_NAME];
	DWORD errcode;
	DWORD Len = sizeof(DWORD);
	DWORD retry=0;
	DWORD OldValue = 0;

	switch (InitDevice())
	{
		case RAMDISK_NO_DRIVER:
			ERRORHANDLE;
			break;
		case RAMDISK_ERRORHANDLE:
			ERRORHANDLE;
			break;
	 }

	DWORD dwType=REG_DWORD;
	DWORD dwSize=sizeof(OldValue);
	if (SHGetValue(HKEY_LOCAL_MACHINE,RAMKEY, RAMVALUE, &dwType, &OldValue, &dwSize) != ERROR_SUCCESS)
	{
		ERRORHANDLE;
	}

	if (NewRamDiskSize == OldValue)
	{
		return TRUE;
	}

	dwSize=sizeof(NewRamDiskSize);
	if (SHSetValue(HKEY_LOCAL_MACHINE,RAMKEY, RAMVALUE, REG_DWORD, &NewRamDiskSize, dwSize) != ERROR_SUCCESS)
	{
		ERRORHANDLE;
	}

	ExpandEnvironmentStrings(RAMDRIVE, szDrive, MAX_NAME);

	if (UStrLen(szDrive) < 2)
	{
		ERRORHANDLE;
	}

 	while (retry < RETRY)
 	{
 		ManageDriver(DICS_ENABLE);
 		ManageDriver(DICS_DISABLE);
		DiskIsExist(szDrive); 			
 		errcode = GetLastError();
 		if (errcode == ERROR_PATH_NOT_FOUND) break;
 		retry++;
 	}
 
 	if (retry==RETRY) ERRORHANDLE;

	retry = 0;
 	while (retry < RETRY)
 	{
		ManageDriver(DICS_DISABLE);
		ManageDriver(DICS_ENABLE);
		DiskIsExist(szDrive); 			
 		errcode = GetLastError();
 		if (errcode != ERROR_PATH_NOT_FOUND) break;
 		retry++;
 	}

 	if (retry==RETRY)
	{
		ERRORHANDLE;
	}

 	while (true)
 	{ 		
		if (!DiskIsExist(szDrive))
		{
			break;
		}
 		
 		errcode = GetLastError();
 		if (errcode != ERROR_PATH_NOT_FOUND)
		{
			ERRORHANDLE;
		}
 	}

	if (Ramdev!=INVALID_HANDLE_VALUE)
	{
		SetupDiDestroyDeviceInfoList(Ramdev);
	}

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT Ramd(PTSTR ptzCmd)
{
	DWORD NewSize = GetNewSize(ptzCmd,1,512,32);
	SetRamdSize(NewSize*(1024*1024));
	TCHAR szDrive[MAX_NAME];
	ExpandEnvironmentStrings(RAMDRIVE, szDrive, MAX_NAME);
	return (!DiskIsExist(szDrive));
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////
PTSTR GetNewLine(PTSTR ptBuf,PTSTR ptOldLine,PTSTR ptEnd)
{
	WCHAR oqvar = *ptEnd;
	*ptEnd = 0;
	UStrPrint(ptBuf, TEXT("%s"),ptOldLine);
	*ptEnd = oqvar;

	PTSTR p = UStrChr(ptBuf, ';');
	if (p != NULL)
	{
		*p = 0;
	}
	return UStrTrim(ptBuf);
}

////////////////////////////////////////////////////////////////////////////////////////////////////////
#define SUBLabel TEXT("_SUB")
#define ENDLabel TEXT("_END")
HRESULT CallSub(PTSTR ptzCmd) //入口参数，子过程名
{    
	TCHAR tzPath[MAX_NAME];
	UStrPrint(tzPath, TEXT("%s%s%s"), SUBLabel,TEXT(" "),ptzCmd);
	//*opstr = opvar;

	PTSTR p = UStrStr(pFileStart, tzPath); //p子过程入口
    if (p)
    {
		for (PTSTR q = p; *q; q++)
		{
			if ((*q == '\r') || (*q == '\n'))
			{	
				TCHAR CurLine[MAX_STR];
				PTSTR Newp =GetNewLine(CurLine,p,q);

				//if (Newp[0] != '/') 
				if ((Newp[0]) && (Newp[0] != '/') && (Newp[0] != ';')) //非注释行和空行
				{				
					if (UStrCmpNI(Newp, ENDLabel,4)) //非子过程定义出口语句
					{
						Command(Newp); //Command函数不解释 _SUB、_END 命令。
					}
					else
					{
						break; //子过程出口
					}
				}
			
				for (q++; (*q == '\r') || (*q == '\n'); q++);
				p = q;
			}
		}
		return S_OK;
    }
	else
	{
		return S_FALSE;
	}
}
/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////
HRESULT Call(PTSTR ptzCmd)
{
	if (*ptzCmd == '$')
	{
		ptzCmd++;
		return CallDll(ptzCmd);
	}
	else
	{
		return CallSub(ptzCmd);
	}	
}
/////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
HRESULT LoadFile(PCTSTR ptzPath)
{	
	TCHAR tzPath[MAX_NAME];
	UStrPrint(tzPath, TEXT("%s"), ptzPath);

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

	PTSTR pCurFileStart = p; //INI文件的起点
	pFileStart = pCurFileStart;
	BOOL IsSUB = FALSE;      //是否子过程

	for (PTSTR q = p; *q; q++)
	{
		if ((*q == '\r') || (*q == '\n'))
		{
			TCHAR CurLine[MAX_STR];
			PTSTR Newp =GetNewLine(CurLine,p,q);

			if ((Newp[0]) && (Newp[0] != '/') && (Newp[0] != ';'))	//非注释行和空行
			{	
				if (!UStrCmpNI(Newp,SUBLabel,4))					//主流程
				{													//跳过
					IsSUB = TRUE;									//_SUB
				}													//至
				else if (!UStrCmpNI(Newp,ENDLabel,4))				//_END
				{													//间的
					IsSUB = FALSE;									//命令  
				}
				else if (!IsSUB)									//非子过程
				{	
					Command(Newp);
				}
			}
			for (q++; (*q == '\r') || (*q == '\n'); q++);
			p = q;
		}
	}

	//pCurFileStart = NULL;
	UMemFree(pbFile);
	return S_OK;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Load command file
HRESULT Load(PCTSTR ptzPath)
{
	PTSTR ForeFile = pFileStart;
	if (ptzPath[0] == '\\')
	{
		ptzPath++;
		TCHAR tzDrives[MAX_NAME];
		GetLogicalDriveStrings(MAX_NAME, tzDrives);
		for (PTSTR p = tzDrives; *p; p += UStrLen(p) + 1)
		{
			TCHAR tzPath[MAX_NAME];
			UStrPrint(tzPath, TEXT("%s%s"), p, ptzPath);
			if (UFileExist(tzPath))
			{
				LoadFile(tzPath);
			}
		}
	}
	else
	{
		if (UFileExist((PTSTR) ptzPath))
		{
			LoadFile(ptzPath);
		}
	}
	pFileStart = ForeFile;
	return S_OK;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Ctrl+Alt+Del handler
HHOOK g_hHook = NULL;
TCHAR TASKMANAGER[] = TEXT("TaskMgr.exe");
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
				Exec(TASKMANAGER);
			}
			return TRUE;
		}
	}
	return CallNextHookEx(g_hHook, iCode, wParam, lParam);
}
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT Hide(PTSTR ptzCmd)
{		
	DWORD HIDE = TRUE;
	SHSetValue(HKEY_LOCAL_MACHINE, PELOGON, TEXT("Hide"), REG_DWORD, &HIDE, sizeof(HIDE));
	return S_OK;
}
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
// Init desktop
HRESULT Main(PCTSTR ptzCmd)
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

	CreateCallBackWindow(); 

	// Hook Ctrl+Alt++Del
	g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, InitProc, g_hInst, 0);
	
	UThreadClose(UThreadCreate((UPROC) MainThread, NULL));

	// Execute LOAD command
	if (ptzCmd[0])
	{
		TCHAR tzCmd[MAX_PATH];
		UStrPrint(tzCmd + GetModuleFileName(NULL, tzCmd, MAX_PATH), TEXT(" LOAD %s"), ptzCmd);
		Exec(tzCmd);
	}

	MSG msg;
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


/////////////////////////////////////////////////////////////////////
HRESULT CommandGroup(PTSTR ptzCurrent)
{
	HRESULT hResult;
	PTSTR ptzNextCom = UStrChr(ptzCurrent, '|');
	
	if (ptzNextCom != NULL)
	{
		*ptzNextCom++ =0 ;
		if ((ptzCurrent != NULL) && UStrLen(ptzCurrent))
		{
			hResult = Command(ptzCurrent);
		}
		else
		{
			hResult = S_OK;
		}
		hResult = CommandGroup(ptzNextCom) + hResult;
	}
	else
	{
		hResult = Command(ptzCurrent);
	}
	return (!(hResult==0));
}
/////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////
HRESULT Team(PTSTR ptzCurrent)
{
	return CommandGroup(ptzCurrent);
}
/////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////
HRESULT IFEx_Or_Find(PTSTR ptzCmd,bool GetFree)
{
	//WIN32_FIND_DATA fd;
	BOOL hResult = false;
	DWORD Var1 = 0;
	DWORD Var2 = 0;

	PTSTR ptzCommand1 = UStrChr(ptzCmd, ',');
	PTSTR ptzCommand2;
	
	if (ptzCommand1!= NULL) 
	{
		*ptzCommand1++ = 0; 

		ptzCommand2 = UStrChr(ptzCommand1, '!');
		if (ptzCommand2 != NULL)
		{
			*ptzCommand2 = 0;
			ptzCommand2++;
		}

		TCHAR KeyWord[3];
		UStrPrint(KeyWord, TEXT("%.3s"), ptzCmd); //关键词

		if ((ptzCmd[3] == '>') || (ptzCmd[3] == '<') || (ptzCmd[3] == '=') || (ptzCmd[3] == '!'))
		{
			Var2=UStrToInt(ptzCmd + 4); //数值2
			if (!UStrCmpNI(KeyWord, TEXT("MEM"), 3))
			{
				Var1 = (GetFree? GetFreeMemo(): GetTotalMemo());
			}
			else if (!UStrCmpNI(KeyWord, TEXT("KEY"), 3))
			{
				Var1 = ((GetAsyncKeyState(Var2) & 0x8000)? Var2 : 0);
			}
			else
			{
				Var1 = (GetFree? GetDiskFree(KeyWord): GetDiskTotal(KeyWord));
			}
			
			ptzCmd = ptzCmd + 3 ;//比较符

			if (*ptzCmd == '=') hResult = (Var1 == Var2);
			else if (*ptzCmd == '>') hResult = (Var1 > Var2);
			else if (*ptzCmd == '<') hResult = (Var1 < Var2);
			else if (*ptzCmd == '!') hResult = (Var1 != Var2);
		}
		else
		{
			if (GetFree)
			{
				hResult = UFileExist(ptzCmd);
			}
			else
			{
				hResult = (FindProc(ptzCmd) > 0);
			}
		}
	}
	return (hResult? CommandGroup(ptzCommand1): CommandGroup(ptzCommand2));
}
//////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT IFEx(PTSTR ptzCmd)
{
	return IFEx_Or_Find(ptzCmd,true);
}
//////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT Find(PTSTR ptzCmd)
{
	return IFEx_Or_Find(ptzCmd,false);
}
//////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT Wait(PTSTR ptzCmd)
{
	return TimeDelay(UStrToInt(ptzCmd));
}
/////////////////////////////////////////////////////////////////////////////



/////////////////////////////////////////////////////////////////////////////
HRESULT Logo(PTSTR ptzCmd)
{
	if (ptzCmd[0])
	{		
		UThreadClose(UThreadCreate((UPROC) LogoCMD, ptzCmd));
		while (ptzCmd[0]) Sleep(20);
	}
	else
	{
		PostMessage(s_hLogo, WM_COMMAND, IDCANCEL, 0);
	}
	return S_OK;
}
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
VOID SetLogs(PTSTR tzCmdStr,HRESULT hResult)
{	
	UStrCat(LogFileData,tzCmdStr);

	TCHAR tzStr[MAX_PATH];
	PTSTR p = tzStr; *p++ = '\t';
	p += FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, hResult, 0, p, _NumOf(tzStr), NULL);
	if (p == tzStr + 1)
	{
		p += LoadString(g_hInst, IDS_CmdErr, p, MAX_NAME);
		p += UStrPrint(p, TEXT("%08X"), hResult);
	}

	TCHAR dtzStr[MAX_PATH];
	UStrCopyN(dtzStr,tzStr,(UINT) (p - tzStr));
	UStrCat(LogFileData,dtzStr);
	UStrCat(LogFileData,TEXT("\n"));
}
/////////////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////////////
HRESULT Logs(PTSTR ptzCmd)
{
	if (g_hXLog)
	{		
		TCHAR tzStr[MAX_STR];
		UStrPrint(tzStr, TEXT("LOGS %s"),ptzCmd);
		SetLogs(tzStr,S_OK);

		g_hXLog = UFileOpen(LogFileName, UFILE_WRITE);
		UFileWrite(g_hXLog, LogFileData, UStrLen(LogFileData) * sizeof(TCHAR));
		UFileClose(g_hXLog);
		UMemFree(LogFileData);
	}

	if (ptzCmd[0])
	{

#ifdef _UNICODE

		UINT LogSize = 16;
		PTSTR p = UStrChr(ptzCmd, ',');
		if (p)
		{
			*p++ = 0;
			LogSize = UStrToInt(p);
		}		
		UStrPrint(LogFileName, TEXT("%s"), ptzCmd);
		LogFileData=(TCHAR *)UMemRealloc(LogFileData,sizeof(TCHAR)* MAX_STR*LogSize);
		UMemSet(LogFileData,0,UStrLen(LogFileData));
		LogFileData[0]=0xFEFF;
		g_hXLog = (HANDLE) TRUE;

#endif

	}
	else
	{
		g_hXLog = NULL;
	}
	return S_OK;
}
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT Mdir(PTSTR ptzCmd)
{
	UDirCreate(ptzCmd);
	return (CreateDirectory(ptzCmd, NULL))? S_OK:S_FALSE;
}
/////////////////////////////////////////////////////////////////////////////


/////////////////////////////////////////////////////////////////////////////
HRESULT Path(PTSTR ptzCmd)
{
	if (ptzCmd[0])
	{
		SetCurrentDirectory(ptzCmd);
	}
	else
	{
		TCHAR tzSysPath[MAX_NAME];
		UStrPrint(tzSysPath, TEXT("PATH %s"), TEXT("%SystemRoot%\\SYSTEM32"));
		Command(tzSysPath);
	}
	return S_OK;
}
/////////////////////////////////////////////////////////////////////////////


///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Execute command
HRESULT Command(PTSTR ptzCmd)
{
	HRESULT hResult =  E_NOTIMPL;
	
	TCHAR tzCmdStr[MAX_STR];
	TCHAR tzCmd[MAX_STR];
	ExpandEnvironmentStrings(ptzCmd, tzCmd, MAX_STR);
	UStrPrint(tzCmdStr,TEXT("%s"),tzCmd);

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
	//case CMD_TEST:
	//	hResult = Test(ptzCmd);
	//	break;

	case CMD_MAIN:
		hResult = Main(ptzCmd);
		break;

	case CMD_LOAD:
		hResult = Load(ptzCmd);
		break;

	case CMD_EXEC:
		hResult = Exec(ptzCmd);
		break;

	case CMD_CALL:
		hResult = Call(ptzCmd);
		break;

	case CMD_REGI:
		hResult = Regi(ptzCmd);
		break;

	case CMD_ENVI:
		hResult = Envi(ptzCmd);
		break;

	case CMD_FILE:
		hResult = File(ptzCmd);
		break;

	case CMD_LINK:
		hResult = Link(ptzCmd);
		break;

	case CMD_SEND:
		hResult = Send(ptzCmd);
		break;

	case CMD_WAIT:
		hResult = Wait(ptzCmd);
		break;

	case CMD_KILL:
		hResult = Kill(ptzCmd);
		break;

	case CMD_SHUT:
		hResult = Shut(ptzCmd);
		break;

	case CMD_DEVI:
		hResult = Devi(ptzCmd);
		break;

	case CMD_SERV:
		hResult = Serv(ptzCmd);
		break;

	case CMD_PAGE:
		hResult = Page(ptzCmd);
		break;

	case CMD_DISP:
		hResult = Disp(ptzCmd);
		break;

	case CMD_LOGO:
		hResult =Logo(ptzCmd);
		break;

	case CMD_TEXT:
		hResult = Text(ptzCmd);
		break;

	case CMD_LOGS:
		hResult = Logs(ptzCmd);
		break;

	case CMD_WALL:
		hResult = Wall(ptzCmd);
		break;

	case CMD_FBWF:
		hResult = Fbwf(ptzCmd);
		break;

	case CMD_RAMD:
		hResult = Ramd(ptzCmd);
		break;

	case CMD_RUNS:
		hResult = Runs(ptzCmd);
		break;

	case CMD_USER:
		hResult = User(ptzCmd);
		break;

	case CMD_NUMK:
		hResult = Numk(ptzCmd);
		break;
	
	case CMD_SHEL:
		hResult = Shel(ptzCmd);
		break;

	case CMD_FONT:
		hResult = Font(ptzCmd);
		break;

	case CMD_TEAM:
		hResult = Team(ptzCmd);
		break;

	case CMD_IFEX:
		hResult = IFEx(ptzCmd);
		break;

	case CMD_FIND:
		hResult = Find(ptzCmd);
		break;

	case CMD_HIDE:
		hResult = Hide(ptzCmd);
		break;

	case CMD_HOTK:
		hResult = Hotk(ptzCmd);
		break;

	case CMD_INIT:
		hResult = Init(ptzCmd);
		break;	

	case CMD_DOWN:
		hResult = Down(ptzCmd);
		break;

	case CMD_PATH:
		hResult = Path(ptzCmd);
		break;

	case CMD_MDIR:
		hResult = Mdir(ptzCmd);
		break;

	default:
		//hResult = Load(ptzCmd);
		hResult = S_OK;
	}
	if (g_hXLog) SetLogs(tzCmdStr,hResult);
	return hResult;
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