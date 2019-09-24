


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Header
#pragma once
#include <Windows.h>

#define AFX_TARG_CHS
//#define AFX_TARG_ENU
//#define AFX_TARG_CHT
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Program information
#define STR_AppName				TEXT("XCMD")
#define STR_AppDesc				TEXT("XPE Commander")
#define STR_FileName			STR_AppName TEXT(".exe")

#define STR_Author				TEXT("Yonsm")
#define STR_Company				TEXT("Yonsm.NET")

#define STR_Mail				TEXT("Yonsm@163.com")
#define STR_Web					TEXT("WWW.Yonsm.NET")

#define STR_WebUrl				TEXT("http://") STR_Web TEXT("/") STR_AppName
#define STR_MailUrl				TEXT("mailto:") STR_Mail TEXT("?subject=") STR_AppName

#define STR_Copyright			TEXT("CopyLeft (L) 2006-20007 ") STR_Company TEXT(". All rights reserved.")
#define STR_Comments			TEXT("Powered by ") STR_Author TEXT("\n") STR_Mail TEXT("\n") STR_Web
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Version information
#define _MakeStr(v)				#v
#define _MakeVer(a, b, c, d)	_MakeStr(a.b.c.d)

#define VER_Major				2
#define VER_Minor				2
#define VER_Release				678  
#define VER_Build				2284
#define VER_Version				MAKELONG(MAKEWORD(VER_Major, VER_Minor), VER_Release)
#define STR_Version				TEXT(_MakeVer(VER_Major, VER_Minor, VER_Release, VER_Build))

#define STR_BuildDate			TEXT(__DATE__)
#define STR_BuildTime			TEXT(__TIME__)
#define STR_BuildStamp			TEXT(__DATE__) TEXT(" ") TEXT(__TIME__)

#if defined(_M_X64)
#define STR_Architecture		"amd64"
#define STR_VersionStamp		STR_Version TEXT(" X64")
#elif defined(_M_IA64)
#define STR_Architecture		"ia64"
#define STR_VersionStamp		STR_Version TEXT(" IA64")
#elif defined(WIN32_PLATFORM_WFSP)
#define STR_VersionStamp		STR_Version //TEXT(" SP")
#elif defined(WIN32_PLATFORM_PSPC)
#define STR_VersionStamp		STR_Version
#else
#define STR_Architecture		"x86"
#ifdef _UNICODE
#define STR_VersionStamp		STR_Version TEXT(" X86U")
#else
#define STR_VersionStamp		STR_Version TEXT(" X86")
#endif
#endif
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
