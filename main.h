
//? Marius Negrutiu (marius.negrutiu@protonmail.com) :: 2014/01/19

#pragma once

#ifndef _DEBUG
	#if DBG || _DEBUG
		#define _DEBUG
	#endif
#endif

#define PLUGINNAME					_T( "NScurl" )

#define COBJMACROS

#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0500
#define _WIN32_IE    0x0600
#include <windows.h>
#include <commctrl.h>
//#include <Shobjidl.h>				/// ITaskbarList
#include <stdio.h>

// --> NSIS plugin API
#include <nsis/pluginapi.h>

#undef EXDLL_INIT
#define EXDLL_INIT() {  \
        g_stringsize=string_size; \
        g_stacktop=stacktop;      \
        g_variables=variables;    \
        g_ep=extra;               \
        g_hwndparent=parent;      \
}

#define EXDLL_VALIDATE() \
	if (g_ep && g_ep->exec_flags && (g_ep->exec_flags->plugin_api_version != NSISPIAPIVER_CURR))  \
		return;

// Additional variables, not exported by NSIS API
static const int INST2_TEMP			= 25;
static const int INST2_PLUGINSDIR	= 26;
static const int INST2_EXEPATH		= 27;
static const int INST2_EXEFILE		= 28;
static const int INST2_HWNDPARENT	= 29;
static const int __INST2_LAST		= 29;
LPTSTR NSISCALL getuservariable2(const int varnum);
void   NSISCALL setuservariable2(const int varnum, LPCTSTR var);

extern extra_parameters *g_ep;		/// main.c
extern HWND g_hwndparent;			/// main.c
#define safepushstring(psz)			pushstring( (psz) ? (psz) : _T("") )
UINT_PTR __cdecl					UnloadCallback( enum NSPIM iMessage );
// <-- NSIS plugin API

extern HINSTANCE g_hInst;			/// Defined in main.c
