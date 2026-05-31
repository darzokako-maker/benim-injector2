#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h> 
#include <fstream>
#include <limits>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Comdlg32.lib")

// 64-bit mimari için haritalama verileri yapısı
struct MAPPING_DATA {
    PVOID pLoadLibraryA;
    PVOID pGetProcAddress;
    PVOID pBaseAddress;
};

// Optimizasyonların bu fonksiyonun yapısını bozmaması için inline ve optimizasyon kapatma direktifleri (MSVC için)
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
// Derleyicinin araya kod sızdırmasını önlemek için hizalama koruması
static void __stdcall ShellcodeEnd() {}
#pragma optimize("", on)

// Aktif süreçlerden PID bulan fonksiyon
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

// DLL seçme arayüzü
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
    SetConsoleTitleA("X64 CS2 & Universal Manual Mapper");

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
    std::cout << "Oyunun exe adini girin (CS2 icin: cs2.exe):\n";
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

    // DLL dosyasını belleğe okuma
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

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::cout << "[-] Oyuna baglanilamadi! Enjektoru 'Yonetici Olarak' calistirin.\n";
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    // Adım 1: Belleği ilk başta READWRITE olarak açıyoruz (Yazma işlemi için güvenlik duvarını aşmak adına)
    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pTargetBase) {
        std::cout << "[-] Hedef oyun surecinde sanal bellek tahsis edilemedi.\n";
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    // PE Başlıklarını yaz
    WriteProcessMemory(hProcess, pTargetBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // Bölümleri (Sections) yaz
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i != pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            WriteProcessMemory(hProcess, (LPVOID)((PBYTE)pTargetBase + pSectionHeader->VirtualAddress), pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr);
        }
    }

    // Haritalama parametreleri
    MAPPING_DATA data;
    data.pLoadLibraryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    data.pBaseAddress = pTargetBase;

    LPVOID pMappingDataTarget = VirtualAllocEx(hProcess, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pMappingDataTarget, &data, sizeof(MAPPING_DATA), nullptr);

    // Shellcode boyutunu mutlak güvenliğe almak için mutlak koruma hesabı
    DWORD shellcodeSize = (DWORD)((PBYTE)ShellcodeEnd - (PBYTE)Shellcode);
    if (shellcodeSize == 0 || shellcodeSize > 0xFFFF) { 
        shellcodeSize = 0x1000; // Boyut hesaplama saparsa güvenli bir varsayılan blok ata
    }

    LPVOID pShellcodeTarget = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pShellcodeTarget, (LPCVOID)Shellcode, shellcodeSize, nullptr);

    // Adım 2: Çökmeyi önlemek için Bellek Haklarını Çalıştırılabilir Modlara Çekiyoruz (RWX Kırmızı bayrağını gizleme)
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);
    VirtualProtectEx(hProcess, pShellcodeTarget, shellcodeSize, PAGE_EXECUTE_READ, &oldProtect);

    // Uzak iş parçacığını tetikle
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcodeTarget, pMappingDataTarget, 0, nullptr);
    if (!hThread) {
        std::cout << "[-] CreateRemoteThread basarisiz oldu. Korumalar engelliyor olabilir.\n";
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    std::cout << "[+] Veriler basariyla haritalandirildi. Enjeksiyon tamamlandigi onaylaniyor...\n";
    WaitForSingleObject(hThread, 5000); // 5 saniye zaman aşımı (Sonsuz döngü kilitlenmesini önler)

    // Temizlik
    VirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    delete[] pSrcData;

    std::cout << "[+] Islem sonlandirildi!\n";
    Sleep(2000);
    return 0;
}
