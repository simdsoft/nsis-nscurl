
//? Marius Negrutiu (marius.negrutiu@protonmail.com) :: 2014/01/19

#include "main.h"
#include "curl.h"
#include "utils.h"
#include "crypto.h"
#include "queue.h"
#include "gui.h"


HINSTANCE	g_hInst = NULL;
HANDLE		g_hTerm = NULL;

extra_parameters			*g_ep = NULL;
HWND						g_hwndparent = NULL;


//++ PluginInit
//?  Called at DLL_PROCESS_ATTACH
BOOL PluginInit( _In_ HINSTANCE hInst )
{
	if (!g_hInst) {

		TRACE( _T( "%hs\n" ), __FUNCTION__ );

		g_hInst = hInst;
		g_hTerm = CreateEvent( NULL, TRUE, FALSE, NULL );
		assert( g_hTerm );

		UtilsInitialize();
		CurlInitialize();
		QueueInitialize();
		GuiInitialize();

		return TRUE;
	}
	return FALSE;
}


//++ PluginUninit
//?  Called at DLL_PROCESS_DETACH
BOOL PluginUninit()
{
	if ( g_hInst ) {

		TRACE( _T( "%hs\n" ), __FUNCTION__ );
		
		SetEvent( g_hTerm );

		GuiDestroy();
		QueueDestroy();
		CurlDestroy();
		UtilsDestroy();

		CloseHandle( g_hTerm );
		g_hInst = NULL;
		return TRUE;
	}
	return FALSE;
}


//++ UnloadCallback
//+  USAGE: extra->RegisterPluginCallback( g_hInst, UnloadCallback );
//?  By registering UnloadCallback, the framework will keep the current plugin locked in memory
//?  Otherwise, unless the caller specifies the /NOUNLOAD parameter the plugin gets unloaded when the current call returns
UINT_PTR __cdecl UnloadCallback( enum NSPIM iMessage )
{
	switch ( iMessage ) {
		case NSPIM_GUIUNLOAD: {
			TRACE( _T( "%hs( NSPIM_GUIUNLOAD )\n" ), __FUNCTION__ );
			break;
		}
		case NSPIM_UNLOAD: {
			TRACE( _T( "%hs( NSPIM_UNLOAD )\n" ), __FUNCTION__ );
			PluginUninit();
			break;
		}
	}
	return 0;
}


//++ [exported] md5 <file>
EXTERN_C __declspec(dllexport)
void __cdecl md5( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[16];
		if (FileHash( psz, hash, NULL, NULL ) == ERROR_SUCCESS) {
			MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}


//++ [exported] sha1 <file>
EXTERN_C __declspec(dllexport)
void __cdecl sha1( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[20];
		if (FileHash( psz, NULL, hash, NULL ) == ERROR_SUCCESS) {
			MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}


//++ [exported] sha256 <file>
EXTERN_C __declspec(dllexport)
void __cdecl sha256( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[32];
		if (FileHash( psz, NULL, NULL, hash ) == ERROR_SUCCESS) {
			MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}


//++ [exported] echo
EXTERN_C __declspec(dllexport)
void __cdecl echo( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz, psz2;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	psz2 = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz && psz2 );

	psz[0] = 0;
	for (;;) {
		if (popstring( psz2 ) != NOERROR)
			break;

		if (*psz)
			_tcscat( psz, _T( " " ) );
		_tcscat( psz, psz2 );

		if (lstrcmpi( psz2, _T( "/END" ) ) == 0)
			break;
	}
	pushstringEx( psz );

	MyFree( psz );
	MyFree( psz2 );
}


//++ [exported] http
EXTERN_C __declspec(dllexport)
void __cdecl http( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	ULONG iRequestID = 0;
	LPTSTR psz = NULL;
	PCURL_REQUEST pReq = NULL;
	PGUI_REQUEST  pGui = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Lock the plugin in memory
	extra->RegisterPluginCallback( g_hInst, UnloadCallback );

	// Working structures
	psz = (LPTSTR)MyAlloc( string_size * sizeof(TCHAR) );
	pReq = (PCURL_REQUEST)MyAlloc( sizeof( *pReq ) );
	pGui = (PGUI_REQUEST)MyAlloc( sizeof( *pGui ) );
	if (psz && pReq && pGui) {

		ULONG i;
		CurlRequestInit( pReq );
		GuiRequestInit( pGui );

		// Parameters
		for (i = 0; ; i++) {

			if (popstring( psz ) != 0)
				break;
			if (lstrcmpi( psz, _T( "/END" ) ) == 0)
				break;

			if (!CurlParseRequestParam( i, psz, string_size, pReq ) &&
				!GuiParseRequestParam( psz, string_size, pGui ))
			{
				TRACE( _T( "  [!] Unknown parameter \"%s\"\n" ), psz );
				assert( !"Unknown parameter" );
			}
		}

		// Append to the queue
		if (QueueAdd( pReq ) == ERROR_SUCCESS) {

			// Wait for this particular ID
			pGui->iId = pReq->Queue.iId;

			// Wait
			// In /background mode the call returns immediately
			GuiWait( pGui, psz, string_size );
			pushstringEx( psz );

			// Don't destroy pReq
			pReq = NULL;
			
		} else {
			pushstringEx( _T( "Error" ) );
		}
	} else {
		pushstringEx( _T( "Error" ) );
	}

	if (pReq) {
		CurlRequestDestroy( pReq );
		MyFree( pReq );
	}
	if (pGui) {
		GuiRequestDestroy( pGui );
		MyFree( pGui );
	}
	MyFree( psz );
}


//++ [exported] wait
EXTERN_C __declspec(dllexport)
void __cdecl wait( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz = NULL;
	PGUI_REQUEST pGui = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Working structures
	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	pGui = (PGUI_REQUEST)MyAlloc( sizeof( *pGui ) );
	if (psz && pGui) {

		// Parameters
		GuiRequestInit( pGui );
		for (;;) {

			if (popstring( psz ) != NOERROR)
				break;
			if (lstrcmpi( psz, _T( "/END" ) ) == 0)
				break;

			if (lstrcmpi( psz, _T( "/ID" ) ) == 0) {
				pGui->iId = popint();
			} else if (!GuiParseRequestParam( psz, string_size, pGui )) {
				TRACE( _T( "  [!] Unknown parameter \"%s\"\n" ), psz );
				assert( !"Unknown parameter" );
			}
		}

		// Wait
		GuiWait( pGui, psz, string_size );
	}

	GuiRequestDestroy( pGui );
	MyFree( pGui );
	MyFree( psz );
}


//+ [internal] MainQueryKeywordCallback
void CALLBACK MainQueryKeywordCallback( _Inout_ LPTSTR pszKeyword, _In_ ULONG iMaxLen, _In_ PVOID pParam )
{
	assert( pszKeyword );
	if (lstrcmpi( pszKeyword, _T( "@@" ) ) == 0) {
		lstrcpyn( pszKeyword, _T( "@" ), iMaxLen );		// @@ -> @
	}
}


//++ MainQuery
LONG MainQuery( _In_opt_ ULONG iId, _Inout_ LPTSTR pszStr, _In_ LONG iStrMaxLen )
{
	LONG iStrLen = -1;
	if (pszStr && iStrMaxLen) {

		// Replace queue keywords
		QueueQuery( iId, pszStr, iStrMaxLen );

		// Replace global keywords
		iStrLen = MyReplaceKeywords( pszStr, iStrMaxLen, _T( '@' ), _T( '@' ), MainQueryKeywordCallback, NULL );
	}
	return iStrLen;
}


//++ [exported] query
EXTERN_C __declspec(dllexport)
void __cdecl query( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	ULONG iId = QUEUE_NO_ID;
	LPTSTR psz = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Working buffer
	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	if (psz) {

		const ULONG OPTIONAL_PARAMS = 1;
		ULONG i, e = NOERROR;
		for (i = 0; (i <= OPTIONAL_PARAMS) && (e == NOERROR); i++) {
			if ((e = popstring( psz )) == NOERROR) {
				if (lstrcmpi( psz, _T( "/ID" ) ) == 0) {
					iId = (ULONG)popintptr();
				} else {
					break;		/// Done reading optional parameters. Continue reading mandatory parameters
				}
			}
		}
		if (e == NOERROR) {
			MainQuery( iId, psz, string_size );
			pushstringEx( psz );
		}
	}

	MyFree( psz );
}


//++ [exported] enumerate
EXTERN_C __declspec(dllexport)
void __cdecl enumerate( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	if ((psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) )) != NULL) {

		BOOLEAN bWaiting = FALSE, bRunning = FALSE, bComplete = FALSE;
		struct curl_slist *sl = NULL;

		for (;;)
		{
			if (popstring( psz ) != NOERROR)
				break;
			if (lstrcmpi( psz, _T( "/END" ) ) == 0)
				break;

			if (lstrcmpi( psz, _T( "/STATUS" ) ) == 0) {
				if (popstring( psz ) == NOERROR) {
					if (lstrcmpi( psz, _T( "Waiting" ) ) == 0) {
						bWaiting = TRUE;
					} else if (lstrcmpi( psz, _T( "Running" ) ) == 0) {
						bRunning = TRUE;
					} else if (lstrcmpi( psz, _T( "Complete" ) ) == 0) {
						bComplete = TRUE;
					}
				}
			}
		}

		if (!bWaiting && !bRunning && !bComplete)
			bWaiting = bRunning = bComplete = TRUE;		/// All by default

		// Enumerate ID-s
		sl = QueueEnumerate( bWaiting, bRunning, bComplete );

		// Empty string marks the end of enumeration
		pushstringEx( _T( "" ) );

		// Push them on the stack in reversed order
		{
			int i, j, n;
			struct curl_slist *s;
			for (n = 0, s = sl; s; n++, s = s->next);	/// List length
			for (i = n - 1; i >= 0; i--) {
				for (j = 0, s = sl; j < i; j++, s = s->next);
				PushStringA( s->data );
			}
		}

		curl_slist_free_all( sl );
		MyFree( psz );
	}
}


//++ [exported] escape
EXTERN_C __declspec(dllexport)
void __cdecl escape( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof(TCHAR) );
	assert( psz );

	if (popstring( psz ) == NOERROR) {
		LPSTR pszA = MyStrDup( eT2A, psz );
		if (pszA) {
			LPSTR pszOut = curl_easy_escape( NULL, pszA, 0 );
			if (pszOut) {
				PushStringA( pszOut );
				curl_free( pszOut );
			}
			MyFree( pszA );
		}
	}

	MyFree( psz );
}


//++ [exported] unescape
EXTERN_C __declspec(dllexport)
void __cdecl unescape( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof(TCHAR) );
	assert( psz );

	if (popstring( psz ) == NOERROR) {
		LPSTR pszA = MyStrDup( eT2A, psz );
		if (pszA) {
			LPSTR pszOut = curl_easy_unescape( NULL, pszA, 0, NULL );
			if (pszOut) {
				PushStringA( pszOut );
				curl_free( pszOut );
			}
			MyFree( pszA );
		}
	}

	MyFree( psz );
}


//++ DllMain
EXTERN_C
BOOL WINAPI DllMain( HMODULE hInst, UINT iReason, LPVOID lpReserved )
{
	if ( iReason == DLL_PROCESS_ATTACH ) {
		PluginInit( hInst );
	} else if ( iReason == DLL_PROCESS_DETACH ) {
		PluginUninit();
	}
	return TRUE;
}
