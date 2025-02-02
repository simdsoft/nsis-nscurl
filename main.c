
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

#if defined(_DEBUG)
		MessageBox(NULL, TEXT("Waiting debugger to attach..."), TEXT("Waiting debugger to attach..."), MB_OK | MB_ICONEXCLAMATION);
#endif

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

#if !defined(NO_HASH_EXPORTS)
//++ [exported] md5 [(string|file|memory)] <data>
EXTERN_C __declspec(dllexport)
void __cdecl md5( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;
	IDATA data;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[16];
		if (IDataParseParam( psz, string_size, &data )) {
			if (Hash( &data, hash, NULL, NULL ) == ERROR_SUCCESS) {
				MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
			} else {
				psz[0] = 0;
			}
			IDataDestroy( &data );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}


//++ [exported] sha1 [(string|file|memory)] <data>
EXTERN_C __declspec(dllexport)
void __cdecl sha1( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;
	IDATA data;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[20];
		if (IDataParseParam( psz, string_size, &data )) {
			if (Hash( &data, NULL, hash, NULL ) == ERROR_SUCCESS) {
				MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
			} else {
				psz[0] = 0;
			}
			IDataDestroy( &data );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}


//++ [exported] sha256 [(string|file|memory)] <data>
EXTERN_C __declspec(dllexport)
void __cdecl sha256( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz;
	IDATA data;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	psz[0] = 0;

	if (popstring( psz ) == NOERROR) {
		UCHAR hash[32];
		if (IDataParseParam( psz, string_size, &data )) {
			if (Hash( &data, NULL, NULL, hash ) == ERROR_SUCCESS) {
				MyFormatBinaryHex( hash, sizeof( hash ), psz, string_size );
			} else {
				psz[0] = 0;
			}
			IDataDestroy( &data );
		} else {
			psz[0] = 0;
		}
	}

	pushstringEx( psz );
	MyFree( psz );
}
#endif

#if !defined(NO_COMPAT)
//++ [exported] echo [param1]..[paramN]
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
#endif

//++ [exported] http <parameters> /END
EXTERN_C __declspec(dllexport)
#if defined(NO_COMPAT)
void __cdecl perform( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
#else
void __cdecl http( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
#endif
{
	LPTSTR psz = NULL;
	PCURL_REQUEST pReq = NULL;
	PGUI_REQUEST  pGui = NULL;

	EXDLL_INIT();
	EXDLL_VALIDATE();
	if (!extra) return;

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Lock the plugin in memory (against NSIS framework trying to unload it)
	extra->RegisterPluginCallback( g_hInst, UnloadCallback );

	// Lock the plugin in memory (against Windows itself trying to FreeLibrary it)
	// Once curl_global_init gets called, the current module must never unload
	CurlInitializeLibcurl();

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
			pGui->qsel.iId = pReq->Queue.iId;
			pGui->qsel.pszTag = NULL;

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

#if !defined(NO_MISC)
//++ [exported] wait [/ID id] [/TAG tag] parameters /END
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
				pGui->qsel.iId = (ULONG)popintptr();
				if (pGui->qsel.iId == 0)
					pGui->qsel.iId = 0xffffffff;		// id=0 would match all IDs. We want no match
			} else if (lstrcmpi( psz, _T( "/TAG" ) ) == 0) {
				if (popstring( psz ) == NOERROR) {
					MyFree( pGui->qsel.pszTag );
					pGui->qsel.pszTag = MyStrDup( eT2A, psz );
				}
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


//++ [exported] query [/ID id] [/TAG tag] "query_string"
EXTERN_C __declspec(dllexport)
void __cdecl query( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	ULONG e;
	LPTSTR psz = NULL;
	QUEUE_SELECTION qsel = {0};

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Working buffer
	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	if (psz) {

		while ((e = popstring( psz )) == NOERROR) {
			if (e == NOERROR && lstrcmpi( psz, _T( "/ID" ) ) == 0) {
				qsel.iId = (ULONG)popintptr();
				if (qsel.iId == 0)
					qsel.iId = 0xffffffff;			// id=0 would match all IDs. We want no match
			} else if (e == NOERROR && lstrcmpi( psz, _T( "/TAG" ) ) == 0) {
				if ((e = popstring( psz )) == NOERROR) {
					MyFree( qsel.pszTag );
					qsel.pszTag = MyStrDup( eT2A, psz );
				}
			} else {
				break;
			}
		}

		if (e == NOERROR) {
			QueueQuery( &qsel, psz, string_size );
			pushstringEx( psz );
		} else {
			pushstringEx( _T( "" ) );
		}
	}

	MyFree( psz );
	MyFree( qsel.pszTag );
}


//++ [exported] cancel [/ID id] [/TAG tag] [/REMOVE]
EXTERN_C __declspec(dllexport)
void __cdecl cancel( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	ULONG e;
	LPTSTR psz = NULL;
	QUEUE_SELECTION qsel = {0};
	BOOLEAN bRemove = FALSE;

	EXDLL_INIT();
	EXDLL_VALIDATE();

	TRACE( _T( "%s!%hs\n" ), PLUGINNAME, __FUNCTION__ );

	// Working buffer
	psz = (LPTSTR)MyAlloc( string_size * sizeof( TCHAR ) );
	assert( psz );
	if (psz) {

		while ((e = popstring( psz )) == NOERROR) {
			if (e == NOERROR && lstrcmpi( psz, _T( "/ID" ) ) == 0) {
				qsel.iId = (ULONG)popintptr();
				if (qsel.iId == 0)
					qsel.iId = 0xffffffff;			// id=0 would match all IDs. We want no match
			} else if (e == NOERROR && lstrcmpi( psz, _T( "/TAG" ) ) == 0) {
				if ((e = popstring( psz )) == NOERROR) {
					MyFree( qsel.pszTag );
					qsel.pszTag = MyStrDup( eT2A, psz );
				}
			} else if (e == NOERROR && lstrcmpi( psz, _T( "/REMOVE" ) ) == 0) {
				bRemove = TRUE;
			} else {
				break;
			}
		}

		if (bRemove) {
			// Abort + Wait + Remove
			QueueRemove( &qsel );
		} else {
			// Abort only
			QueueAbort( &qsel );
		}
	}

	MyFree( psz );
	MyFree( qsel.pszTag );
}


//++ [exported] enumerate [/STATUS s1]..[/STATUS sN] [/TAG tag] /END
EXTERN_C __declspec(dllexport)
void __cdecl enumerate( HWND parent, int string_size, TCHAR *variables, stack_t **stacktop, extra_parameters *extra )
{
	LPTSTR psz = NULL;
	QUEUE_SELECTION qsel = {0};

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
			} else if (lstrcmpi( psz, _T( "/TAG" ) ) == 0) {
				if (popstring( psz ) == NOERROR) {
					MyFree( qsel.pszTag );
					qsel.pszTag = MyStrDup( eT2A, psz );
				}
			}
		}

		if (!bWaiting && !bRunning && !bComplete)
			bWaiting = bRunning = bComplete = TRUE;		/// All by default

		// Enumerate ID-s
		sl = QueueEnumerate( &qsel, bWaiting, bRunning, bComplete );

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
		MyFree( qsel.pszTag );
	}
}


//++ [exported] escape <string>
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


//++ [exported] unescape <string>
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
#endif

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
