#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h> 
#include <fstream>
#include <limits>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Comdlg32.lib")

// Statik imza taramalarını engellemek için veri bölümlerini birleştirme direktifleri
#pragma comment(linker, "/MERGE:.rdata=.text")
#pragma comment(linker, "/MERGE:.pdata=.text")

// 64-bit mimari için haritalama verileri yapısı
struct MAPPING_DATA {
    PVOID pLoadLibraryA;
    PVOID pGetProcAddress;
    PVOID pBaseAddress;
};

// Dinamik API çağrıları için fonksiyon şablonları (Fonksiyon İşaretçileri)
typedef HANDLE(WINAPI* f_OpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* f_VirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* f_WriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef BOOL(WINAPI* f_VirtualProtectEx)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* f_CreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* f_VirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

#pragma optimize("", off)
static DWORD WINAPI Shellcode(MAPPING_DATA* pData) {
    if (!pData) return 0;

    typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
    typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
    typedef BOOL(WINAPI* tDllMain)(HINSTANCE, DWORD, LPVOID);

    tLoadLibraryA _LoadLibraryA = (tLoadLibraryA)pData->pLoadLibraryA;
    tGetProcAddress _GetProcAddress = (tGetProcAddress)pData->pGetProcAddress;

    PBYTE pBase = (PBYTE)pData->pBaseAddress;
    auto* pOpt = &((PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew))->OptionalHeader;

    // 1. IAT (Import Address Table) Çözümlemesi
    auto* pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        while (pImportDesc->Name) {
            HMODULE hMod = _LoadLibraryA((LPCSTR)(pBase + pImportDesc->Name));
            if (!hMod) return 0;

            auto* pThunkRef = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->FirstThunk);
            auto* pFuncRef = (PIMAGE_THUNK_DATA)(pBase + pImportDesc->OriginalFirstThunk);
            if (!pFuncRef) pFuncRef = pThunkRef;

            while (pFuncRef->u1.AddressOfData) {
                if (IMAGE_SNAP_BY_ORDINAL(pFuncRef->u1.Ordinal)) {
                    *(FARPROC*)&pThunkRef->u1.Function = _GetProcAddress(hMod, (LPCSTR)(pFuncRef->u1.Ordinal & 0xFFFF));
                } else {
                    auto* pImportByName = (PIMAGE_IMPORT_BY_NAME)(pBase + pFuncRef->u1.AddressOfData);
                    *(FARPROC*)&pThunkRef->u1.Function = _GetProcAddress(hMod, (LPCSTR)pImportByName->Name);
                }
                pThunkRef++;
                pFuncRef++;
            }
            pImportDesc++;
        }
    }

    // 2. Base Relocation (Adres Yeniden Konumlandırma) - 64-bit Uyumlu
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pReloc = (PIMAGE_BASE_RELOCATION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ULONGLONG delta = (ULONGLONG)((PBYTE)pBase - pOpt->ImageBase);

        while (pReloc->VirtualAddress) {
            UINT size = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD pRelativeInfo = (PWORD)(pReloc + 1);

            for (UINT i = 0; i < size; ++i) {
                int type = pRelativeInfo[i] >> 12;
                int offset = pRelativeInfo[i] & 0xFFF;

                if (type == IMAGE_REL_BASED_DIR64) {
                    ULONGLONG* pPatch = (ULONGLONG*)(pBase + pReloc->VirtualAddress + offset);
                    *pPatch += delta;
                }
            }
            pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
        }
    }

    // 3. DllMain Giriş Noktasının Tetiklenmesi
    if (pOpt->AddressOfEntryPoint) {
        tDllMain _DllMain = (tDllMain)(pBase + pOpt->AddressOfEntryPoint);
        return _DllMain((HINSTANCE)pBase, DLL_PROCESS_ATTACH, nullptr);
    }

    return 1;
}
static void __stdcall ShellcodeEnd() {}
#pragma optimize("", on)

// İşlem adından PID bulma fonksiyonu
DWORD IslemAdindanPidBul(const std::wstring& islemAdi) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (islemAdi == std::wstring(pe32.szExeFile)) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// Dosya seçme penceresi
std::wstring DllSecmePenceresi() {
    OPENFILENAMEW ofn;
    wchar_t dosyaYolu[MAX_PATH] = L"";

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = dosyaYolu;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"Dynamic Link Library (*.dll)\0*.dll\0Tum Dosyalar (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) return std::wstring(dosyaYolu);
    return L"";
}

int main() {
    SetConsoleTitleA("X64 Universal Manual Mapper - Meşru Sürüm");

    // Kernel32.dll kütüphanesini dinamik olarak çağırıp fonksiyonları hafızadan çekiyoruz (IAT Gizleme)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    f_OpenProcess DinamikOpenProcess = (f_OpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    f_VirtualAllocEx DinamikVirtualAllocEx = (f_VirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    f_WriteProcessMemory DinamikWriteProcessMemory = (f_WriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    f_VirtualProtectEx DinamikVirtualProtectEx = (f_VirtualProtectEx)GetProcAddress(hKernel32, "VirtualProtectEx");
    f_CreateRemoteThread DinamikCreateRemoteThread = (f_CreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    f_VirtualFreeEx DinamikVirtualFreeEx = (f_VirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    std::wstring dllYolu = L"";
    std::wstring hedefIslem = L"";
    DWORD targetPID = 0;

    std::cout << "========================================\n";
    std::cout << "      1. ADIM: ENJEKTE EDILECEK DLL      \n";
    std::cout << "========================================\n";
    std::cout << "[+] Lutfen yuklemek istediginiz DLL dosyasini secin...\n";
    
    dllYolu = DllSecmePenceresi();
    if (dllYolu.empty()) {
        std::cout << "[-] DLL secilmedi. Program sonlandiriliyor.\n";
        system("pause");
        return 0;
    }
    std::wcout << L"[+] Secilen DLL: " << dllYolu << L"\n\n";

    std::cout << "========================================\n";
    std::cout << "      2. ADIM: HEDEF SUREC BELIRLEME    \n";
    std::cout << "========================================\n";
    std::cout << "Oyunun exe adini girin (SonOyuncu icin sonoyuncu.exe veya javaw.exe):\n";
    std::wcout << L"Giris: ";
    std::getline(std::wcin, hedefIslem);

    if (hedefIslem.empty()) {
        std::cout << "[-] Gecersiz islem adi.\n";
        system("pause");
        return 0;
    }

    std::wcout << L"\n[+] '" << hedefIslem << L"' bekleniyor... Lutfen oyunu baslatin.\n";
    while (targetPID == 0) {
        targetPID = IslemAdindanPidBul(hedefIslem);
        Sleep(300);
    }
    std::wcout << L"[+] Hedef oyun bulundu! PID: " << targetPID << L"\n\n";

    std::ifstream file(dllYolu, std::ios::binary | std::ios::ate);
    if (file.fail()) {
        std::cout << "[-] DLL dosyasi okunamadi.\n";
        system("pause");
        return 0;
    }

    auto fileSize = file.tellg();
    auto* pSrcData = new BYTE[(UINT_PTR)fileSize];
    file.seekg(0, std::ios::beg);
    file.read((char*)pSrcData, fileSize);
    file.close();

    auto* pDosHeader = (PIMAGE_DOS_HEADER)pSrcData;
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(pSrcData + pDosHeader->e_lfanew);

    HANDLE hProcess = DinamikOpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::cout << "[-] Oyuna baglanilamadi! Enjektoru 'Yonetici Olarak' calistirin.\n";
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    LPVOID pTargetBase = DinamikVirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pTargetBase) {
        std::cout << "[-] Hedef oyun surecinde sanal bellek tahsis edilemedi.\n";
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    // PE Başlıklarını yaz
    DinamikWriteProcessMemory(hProcess, pTargetBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // Bölümleri (Sections) yaz
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i != pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            DinamikWriteProcessMemory(hProcess, (LPVOID)((PBYTE)pTargetBase + pSectionHeader->VirtualAddress), pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr);
        }
    }

    MAPPING_DATA data;
    data.pLoadLibraryA = (PVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    data.pGetProcAddress = (PVOID)GetProcAddress(hKernel32, "GetProcAddress");
    data.pBaseAddress = pTargetBase;

    LPVOID pMappingDataTarget = DinamikVirtualAllocEx(hProcess, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DinamikWriteProcessMemory(hProcess, pMappingDataTarget, &data, sizeof(MAPPING_DATA), nullptr);

    DWORD shellcodeSize = (DWORD)((PBYTE)ShellcodeEnd - (PBYTE)Shellcode);
    if (shellcodeSize == 0 || shellcodeSize > 0xFFFF) { 
        shellcodeSize = 0x1000;
    }

    LPVOID pShellcodeTarget = DinamikVirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DinamikWriteProcessMemory(hProcess, pShellcodeTarget, (LPCVOID)Shellcode, shellcodeSize, nullptr);

    DWORD oldProtect;
    DinamikVirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);
    DinamikVirtualProtectEx(hProcess, pShellcodeTarget, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Uzak iş parçacığını tetikle
    HANDLE hThread = DinamikCreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcodeTarget, pMappingDataTarget, 0, nullptr);
    if (!hThread) {
        std::cout << "[-] İş parçacığı başlatılamadı.\n";
        DinamikVirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        DinamikVirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
        DinamikVirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    std::cout << "[+] Veriler haritalandirildi. Enjeksiyon bekleniyor...\n";
    WaitForSingleObject(hThread, 5000);

    // =======================================================================
    // GELİŞMİŞ ADIM: HAFIZADAKİ PE BAŞLIKLARINI SIFIRLAMA (GİZLEME)
    // =======================================================================
    DWORD baslikKorumasi;
    // Başlıkların olduğu bölgeyi geçici olarak yazılabilir yapıyoruz
    DinamikVirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READWRITE, &baslikKorumasi);
    
    // Sıfırlarla dolu geçici bir bellek bloğu oluşturuyoruz
    BYTE* temizleyiciBlok = new BYTE[pNtHeaders->OptionalHeader.SizeOfHeaders];
    ZeroMemory(temizleyiciBlok, pNtHeaders->OptionalHeader.SizeOfHeaders);
    
    // Hedef sürecin RAM'indeki MZ ve PE imzalarını sıfırlıyoruz
    DinamikWriteProcessMemory(hProcess, pTargetBase, temizleyiciBlok, pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);
    delete[] temizleyiciBlok;

    // Bellek korumasını eski haline getiriyoruz (Bellek tarayıcıları artık MZ göremez)
    DinamikVirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfHeaders, baslikKorumasi, &baslikKorumasi);
    // =======================================================================

    // Temizlik işlemleri
    DinamikVirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
    DinamikVirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    delete[] pSrcData;

    std::cout << "[+] İşlem başarıyla tamamlandı ve izler temizlendi!\n";
    Sleep(2000);
    return 0;
}
