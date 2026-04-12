#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>

using namespace std;

// Manuel Map için gerekli en temel yapı
struct MM_DATA {
    LPVOID pLoadLib;
    LPVOID pGetProc;
    LPVOID pBase;
};

// Shellcode: DLL'i hedef süreç içinde yapılandırır
void __stdcall Shellcode(MM_DATA* pData) {
    if (!pData) return;
    BYTE* b = (BYTE*)pData->pBase;
    auto* nt = &((IMAGE_NT_HEADERS*)(b + ((IMAGE_DOS_HEADER*)b)->e_lfanew))->OptionalHeader;
    auto _L = (decltype(LoadLibraryA)*)pData->pLoadLib;
    auto _G = (decltype(GetProcAddress)*)pData->pGetProc;

    // Relocation: Adresleri düzelt
    auto* rel = &nt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (rel->Size) {
        auto* block = (IMAGE_BASE_RELOCATION*)(b + rel->VirtualAddress);
        while (block->VirtualAddress) {
            UINT_PTR delta = (UINT_PTR)b - (UINT_PTR)nt->ImageBase;
            WORD* info = (WORD*)(block + 1);
            for (DWORD i = 0; i < (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
                if ((info[i] >> 12) == 10 || (info[i] >> 12) == 3) {
                    UINT_PTR* patch = (UINT_PTR*)(b + block->VirtualAddress + (info[i] & 0xFFF));
                    *patch += delta;
                }
            }
            block = (IMAGE_BASE_RELOCATION*)((BYTE*)block + block->SizeOfBlock);
        }
    }

    // Import: Gerekli kütüphaneleri bağla
    auto* imp = &nt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp->Size) {
        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(b + imp->VirtualAddress);
        while (desc->Name) {
            HINSTANCE h = _L((char*)(b + desc->Name));
            auto* t = (IMAGE_THUNK_DATA*)(b + desc->FirstThunk);
            auto* o = (IMAGE_THUNK_DATA*)(b + desc->OriginalFirstThunk);
            while (o->u1.AddressOfData) {
                char* fn = (o->u1.Ordinal & IMAGE_ORDINAL_FLAG) ? (char*)(o->u1.Ordinal & 0xFFFF) : ((IMAGE_IMPORT_BY_NAME*)(b + o->u1.AddressOfData))->Name;
                t->u1.Function = (UINT_PTR)_G(h, fn);
                t++; o++;
            }
            desc++;
        }
    }
    ((BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID))(b + nt->AddressOfEntryPoint))((HINSTANCE)b, 1, 0);
}

void __stdcall Shellcode_End() {}

int main() {
    printf("Bekleniyor: cs2.exe\n");
    DWORD pid = 0;
    while (!pid) {
        HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32 pe = { sizeof(pe) };
        if (Process32First(s, &pe)) {
            do { if (!strcmp(pe.szExeFile, "cs2.exe")) pid = pe.th32ProcessID; } while (Process32Next(s, &pe));
        }
        CloseHandle(s); Sleep(500);
    }

    ifstream f("hile.dll", ios::binary | ios::ate);
    if (!f.is_open()) { printf("Hata: hile.dll bulunamadi!\n"); return 1; }
    size_t sz = f.tellg();
    vector<char> buf(sz);
    f.seekg(0); f.read(buf.data(), sz); f.close();

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(buf.data() + ((PIMAGE_DOS_HEADER)buf.data())->e_lfanew);
    LPVOID b = VirtualAllocEx(h, 0, nt->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    WriteProcessMemory(h, b, buf.data(), nt->OptionalHeader.SizeOfHeaders, 0);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(h, (LPVOID)((uintptr_t)b + sec[i].VirtualAddress), (LPVOID)((uintptr_t)buf.data() + sec[i].PointerToRawData), sec[i].SizeOfRawData, 0);
    }

    MM_DATA d = { (LPVOID)LoadLibraryA, (LPVOID)GetProcAddress, b };
    LPVOID rd = VirtualAllocEx(h, 0, sizeof(d), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(h, rd, &d, sizeof(d), 0);

    size_t scSz = (uintptr_t)Shellcode_End - (uintptr_t)Shellcode;
    LPVOID rs = VirtualAllocEx(h, 0, scSz, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(h, rs, (LPVOID)Shellcode, scSz, 0);

    CreateRemoteThread(h, 0, 0, (LPTHREAD_START_ROUTINE)rs, rd, 0, 0);
    printf("Enjeksiyon basarili. Iyi oyunlar!\n");
    Sleep(2000);
    return 0;
}

