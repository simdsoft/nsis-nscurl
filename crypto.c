
//? Marius Negrutiu (mailto:marius.negrutiu@protonmail.com) :: 2019/11/20
//? Compute hashes using our embedded cryptographic engine

#include "main.h"
#include "crypto.h"

#if !defined(NO_HASH_EXPORTS)
#include <openssl/crypto/evp.h>

//++ Hash
ULONG Hash( _In_ IDATA *pData, _Out_opt_ PUCHAR md5, _Out_opt_ PUCHAR sha1, _Out_opt_ PUCHAR sha256 )
{
	if (!pData)
		return ERROR_INVALID_PARAMETER;

	if (pData->Type == IDATA_TYPE_FILE) {
		return HashFile( pData->File, md5, sha1, sha256 );
	} else if (pData->Type == IDATA_TYPE_MEM) {
		return HashMem( pData->Mem, (size_t)pData->Size, md5, sha1, sha256 );
	} else if (pData->Type == IDATA_TYPE_STRING) {
		assert( lstrlenA( pData->Str ) == pData->Size );
		return HashMem( pData->Str, (size_t)pData->Size, md5, sha1, sha256 );
	}

	return ERROR_NOT_SUPPORTED;
}


//++ HashFile
ULONG HashFile( _In_ LPCTSTR pszFile, _Out_opt_ PUCHAR md5, _Out_opt_ PUCHAR sha1, _Out_opt_ PUCHAR sha256 )
{
	ULONG e = ERROR_SUCCESS;
	HANDLE h;

	if (!pszFile || !*pszFile || (!md5 && !sha1 && !sha256))
		return ERROR_INVALID_PARAMETER;

	h = CreateFile( pszFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL );
	if (h != INVALID_HANDLE_VALUE) {
		ULONG bufsize = 1024 * 1024;
		PUCHAR buf = (PUCHAR)HeapAlloc( GetProcessHeap(), 0, bufsize );
		if (buf) {

			ULONG l;
			EVP_MD_CTX *md5ctx  = EVP_MD_CTX_new();
			EVP_MD_CTX *sha1ctx = EVP_MD_CTX_new();
			EVP_MD_CTX *sha2ctx = EVP_MD_CTX_new();
			if (md5ctx && sha1ctx && sha2ctx) {
				if (md5) EVP_DigestInit( md5ctx, EVP_md5() );
				if (sha1) EVP_DigestInit( sha1ctx, EVP_sha1() );
				if (sha256) EVP_DigestInit( sha2ctx, EVP_sha256() );
				while ((e = ReadFile( h, buf, bufsize, &l, NULL ) ? ERROR_SUCCESS : GetLastError()) == ERROR_SUCCESS && (l > 0)) {
					if (md5) EVP_DigestUpdate( md5ctx, buf, l );
					if (sha1) EVP_DigestUpdate( sha1ctx, buf, l );
					if (sha256) EVP_DigestUpdate( sha2ctx, buf, l );
				}
				if (md5) EVP_DigestFinal( md5ctx, md5, NULL );
				if (sha1) EVP_DigestFinal( sha1ctx, sha1, NULL );
				if (sha256) EVP_DigestFinal( sha2ctx, sha256, NULL );
			}
			if (md5ctx)  EVP_MD_CTX_free( md5ctx );
			if (sha1ctx) EVP_MD_CTX_free( sha1ctx );
			if (sha2ctx) EVP_MD_CTX_free( sha2ctx );

			HeapFree( GetProcessHeap(), 0, buf );

		} else {
			e = ERROR_OUTOFMEMORY;
		}
		CloseHandle( h );
	} else {
		e = GetLastError();
	}

	return e;
}


//++ HashMem
ULONG HashMem( _In_ LPCVOID pPtr, _In_ size_t iSize, _Out_opt_ PUCHAR md5, _Out_opt_ PUCHAR sha1, _Out_opt_ PUCHAR sha256 )
{
	if (!pPtr || !iSize || (!md5 && !sha1 && !sha256))
		return ERROR_INVALID_PARAMETER;

	if (md5) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (ctx) {
			EVP_DigestInit( ctx, EVP_md5() );
			EVP_DigestUpdate( ctx, pPtr, iSize );
			EVP_DigestFinal( ctx, md5, NULL );
			EVP_MD_CTX_free( ctx );
		}
	}

	if (sha1) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (ctx) {
			EVP_DigestInit( ctx, EVP_sha1() );
			EVP_DigestUpdate( ctx, pPtr, iSize );
			EVP_DigestFinal( ctx, sha1, NULL );
			EVP_MD_CTX_free( ctx );
		}
	}

	if (sha256) {
		EVP_MD_CTX *ctx = EVP_MD_CTX_new();
		if (ctx) {
			EVP_DigestInit( ctx, EVP_sha256() );
			EVP_DigestUpdate( ctx, pPtr, iSize );
			EVP_DigestFinal( ctx, sha256, NULL );
			EVP_MD_CTX_free( ctx );
		}
	}

	return ERROR_SUCCESS;
}


//++ EncBase64
LPSTR EncBase64( _In_ LPCVOID pPtr, _In_ size_t iSize )
{
	LPSTR pszBase64 = NULL;
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	if (ctx) {
		int lOut = 4 * ((iSize + 2) / 3) + 1;
		if ((pszBase64 = (LPSTR)MyAlloc( lOut )) != NULL) {
			LPSTR psz = pszBase64;
			int len;
			EVP_EncodeInit( ctx );
			evp_encode_ctx_set_flags( ctx, EVP_ENCODE_CTX_NO_NEWLINES );
			EVP_EncodeUpdate( ctx, psz, &len, pPtr, (int)iSize );
			EVP_EncodeFinal( ctx, (psz += len), &len );
		}
		EVP_ENCODE_CTX_free( ctx );
	}
	return pszBase64;
}


//++ DecBase64
PVOID DecBase64( _In_ LPCSTR pszBase64, _Out_opt_ size_t *piSize )
{
	LPSTR pPtr = NULL;
	EVP_ENCODE_CTX *ctx = EVP_ENCODE_CTX_new();
	if (piSize) *piSize = 0;
	if (ctx) {
		int lIn = lstrlenA( pszBase64 );
		int lOut = (3 * lIn) / 4;
		if ((pPtr = (LPSTR)MyAlloc( lOut )) != NULL) {
			LPSTR psz = pPtr;
			int len1 = 0, len2 = 0;
			EVP_DecodeInit( ctx );
			if (EVP_DecodeUpdate( ctx, psz, &len1, pszBase64, lIn ) != -1 &&
				EVP_DecodeFinal( ctx, (psz += len1), &len2 ) != -1)
			{
				if (piSize) *piSize += len1 + len2;
			} else {
				MyFree( pPtr );
			}
		}
		EVP_ENCODE_CTX_free( ctx );
	}

	return (PVOID)pPtr;
}

#else

static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int alphabet_len = sizeof("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");
static void _base64Encode(const unsigned char* input, unsigned int input_len, char* output)
{
    unsigned int char_count;
    unsigned int bits;
    unsigned int input_idx = 0;
    unsigned int output_idx = 0;

    char_count = 0;
    bits = 0;
    for (input_idx = 0; input_idx < input_len; input_idx++)
    {
        bits |= input[input_idx];

        char_count++;
        if (char_count == 3)
        {
            output[output_idx++] = alphabet[(bits >> 18) & 0x3f];
            output[output_idx++] = alphabet[(bits >> 12) & 0x3f];
            output[output_idx++] = alphabet[(bits >> 6) & 0x3f];
            output[output_idx++] = alphabet[bits & 0x3f];
            bits = 0;
            char_count = 0;
        }
        else
        {
            bits <<= 8;
        }
    }

    if (char_count)
    {
        if (char_count == 1)
        {
            bits <<= 8;
        }

        output[output_idx++] = alphabet[(bits >> 18) & 0x3f];
        output[output_idx++] = alphabet[(bits >> 12) & 0x3f];
        if (char_count > 1)
        {
            output[output_idx++] = alphabet[(bits >> 6) & 0x3f];
        }
        else
        {
            output[output_idx++] = '=';
        }
        output[output_idx++] = '=';
    }

    output[output_idx++] = 0;
}

static int _base64Decode(const unsigned char* input, unsigned int input_len, unsigned char* output, unsigned int* output_len)
{
    static char inalphabet[256], decoder[256];
    int c = 0, char_count, errors = 0;
    unsigned int input_idx = 0;
    unsigned int output_idx = 0;
    int bits = 0;

    for (int i = 0; i < alphabet_len; i++)
    {
        inalphabet[alphabet[i]] = 1;
        decoder[alphabet[i]] = i;
    }

    char_count = 0;
    for (input_idx = 0; input_idx < input_len; input_idx++)
    {
        c = input[input_idx];
        if (c == '=')
            break;
        if (c > 255 || !inalphabet[c])
            continue;
        bits += decoder[c];
        char_count++;
        if (char_count == 4)
        {
            output[output_idx++] = (bits >> 16);
            output[output_idx++] = ((bits >> 8) & 0xff);
            output[output_idx++] = (bits & 0xff);
            bits = 0;
            char_count = 0;
        }
        else
        {
            bits <<= 6;
        }
    }

    if (c == '=')
    {
        switch (char_count)
        {
        case 1:
            errors++;
            break;
        case 2:
            output[output_idx++] = (bits >> 10);
            break;
        case 3:
            output[output_idx++] = (bits >> 16);
            output[output_idx++] = ((bits >> 8) & 0xff);
            break;
        }
    }
    else if (input_idx < input_len)
    {
        if (char_count)
        {
            errors++;
        }
    }

    *output_len = output_idx;
    return errors;
}


LPSTR EncBase64(_In_ LPCVOID pPtr, _In_ size_t iSize)
{
    unsigned int outLength = (iSize + 2) / 3 * 4;

    // should be enough to store 8-bit buffers in 6-bit buffers
    char* out = (char*)malloc(outLength + 1);
    if (out)
        _base64Encode(pPtr, iSize, out);
    return out;
}

PVOID DecBase64(_In_ LPCSTR pszBase64, _Out_opt_ size_t* piSize)
{
    unsigned int outLength = 0;

    // should be enough to store 6-bit buffers in 8-bit buffers
    char* out = (unsigned char*)malloc(*piSize / 4 * 3 + 1);
    if (out)
    {
        int ret = _base64Decode(pszBase64, *piSize, out, &outLength);

        if (ret > 0)
        {
            free(out);
            out = NULL;
            outLength = 0;
        }
    }
    *piSize = outLength;
    return out;
}

#endif
