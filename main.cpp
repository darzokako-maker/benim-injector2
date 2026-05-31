#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h> 
#include <fstream>
#include <limits>

#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Comdlg32.lib")

// 64-bit (x64) mimari için kritik haritalama verileri yapısı
struct MAPPING_DATA {
    PVOID pLoadLibraryA;
    PVOID pGetProcAddress;
    PVOID pBaseAddress;
};

// Uzak süreçte yürütülecek 64-bit uyumlu kabuk kod (Shellcode)
static DWORD WINAPI Shellcode(MAPPING_DATA* pData) {
    if (!pData) return 0;

    typedef HMODULE(WINAPI* tLoadLibraryA)(LPCSTR);
    typedef FARPROC(WINAPI* tGetProcAddress)(HMODULE, LPCSTR);
    typedef BOOL(WINAPI* tDllMain)(HINSTANCE, DWORD, LPVOID);

    tLoadLibraryA _LoadLibraryA = (tLoadLibraryA)pData->pLoadLibraryA;
    tGetProcAddress _GetProcAddress = (tGetProcAddress)pData->pGetProcAddress;

    PBYTE pBase = (PBYTE)pData->pBaseAddress;

    auto* pOpt = &((PIMAGE_NT_HEADERS)(pBase + ((PIMAGE_DOS_HEADER)pBase)->e_lfanew))->OptionalHeader;

    // 1. IAT (Import Address Table) Çözümlemesi - Bağımlı kütüphanelerin yüklenmesi
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
                    * (FARPROC*)&pThunkRef->u1.Function = _GetProcAddress(hMod, (LPCSTR)(pFuncRef->u1.Ordinal & 0xFFFF));
                } else {
                    auto* pImportByName = (PIMAGE_IMPORT_BY_NAME)(pBase + pFuncRef->u1.AddressOfData);
                    * (FARPROC*)&pThunkRef->u1.Function = _GetProcAddress(hMod, (LPCSTR)pImportByName->Name);
                }
                pThunkRef++;
                pFuncRef++;
            }
            pImportDesc++;
        }
    }

    // 2. 64-Bit Base Relocation (Adres Yeniden Konumlandırma) İşlemleri
    // Delta ve kaydırma işlemleri tamamen 64-bit (ULONGLONG) adres genişliğindedir.
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pReloc = (PIMAGE_BASE_RELOCATION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ULONGLONG delta = (ULONGLONG)((PBYTE)pBase - pOpt->ImageBase);

        while (pReloc->VirtualAddress) {
            UINT size = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD pRelativeInfo = (PWORD)(pReloc + 1);

            for (UINT i = 0; i < size; ++i) {
                int type = pRelativeInfo[i] >> 12;
                int offset = pRelativeInfo[i] & 0xFFF;

                // 64-bit kütüphanelerde yeniden konumlandırma tipi IMAGE_REL_BASED_DIR64'tür.
                if (type == IMAGE_REL_BASED_DIR64 || type == IMAGE_REL_BASED_HIGHLOW) {
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
// Kabuk kodunun bellekte bittiği sınırı belirleyen boş fonksiyon
static void __stdcall ShellcodeEnd() {}

// Çalışan aktif süreçler listesinden isim eşleşmesine göre PID dönen fonksiyon
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

// Windows yerleşik dosya gezgini üzerinden DLL seçtiren görsel arayüz fonksiyonu
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
    SetConsoleTitleA("X64 Pro Soccer Online Manual Mapper");

    std::wstring dllYolu = L"";
    std::wstring hedefIslem = L"";
    DWORD targetPID = 0;

    // 1. ADIM: DLL SEÇİM PENCERESİNİN OTOMATİK AÇILMASI
    std::cout << "========================================\n";
    std::cout << "      1. ADIM: ENJEKTE EDILECEK DLL      \n";
    std::cout << "========================================\n";
    std::cout << "[+] Lutfen yuklemek istediginiz DLL dosyasini secin...\n";
    
    dllYolu = DllSecmePenceresi();
    if (dllYolu.empty()) {
        std::cout << "[-] DLL secilmedi veya pencere kapatildi. Program sonlandiriliyor.\n";
        system("pause");
        return 0;
    }
    std::wcout << L"[+] Secilen DLL: " << dllYolu << L"\n\n";

    // 2. ADIM: MANUEL PRO SOCCER ONLINE İŞLEM ADI GİRİŞİ
    std::cout << "========================================\n";
    std::cout << "      2. ADIM: HEDEF SUREC BELIRLEME    \n";
    std::cout << "========================================\n";
    std::cout << "Oyunun exe adini girin (Ornek: ProSoccerOnline.exe veya ProSoccerOnline-Win64-Shipping.exe):\n";
    std::wcout << L"Giris: ";
    std::getline(std::wcin, hedefIslem);

    if (hedefIslem.empty()) {
        std::cout << "[-] Gecersiz veya bos islem adi girildi.\n";
        system("pause");
        return 0;
    }

    std::wcout << L"\n[+] '" << hedefIslem << L"' sureci aranıyor... Lutfen oyunu baslatin.\n";
    while (targetPID == 0) {
        targetPID = IslemAdindanPidBul(hedefIslem);
        Sleep(300); // Sürekli döngünün CPU'yu şişirmemesi için gecikme
    }
    std::wcout << L"[+] Hedef oyun bulundu! PID: " << targetPID << L"\n\n";

    // 3. ADIM: MANUAL MAPPING PROSEDÜRÜ
    // DLL dosyasının binary olarak belleğe okunması
    std::ifstream file(dllYolu, std::ios::binary | std::ios::ate);
    if (file.fail()) {
        std::cout << "[-] Belirtilen DLL dosyasi okunmak icin acilamadi.\n";
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

    // Hedef sürece bellek yönetim haklarıyla bağlanma
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::cout << "[-] Oyuna baglanilamadi! Lutfen enjektoru 'Yonetici Olarak' calistirin.\n";
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    // Pro Soccer Online sanal bellek alanında DLL imaj boyutu kadar yer açılması
    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pTargetBase) {
        std::cout << "[-] Hedef oyun surecinde sanal bellek tahsis edilemedi.\n";
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    // PE (Portable Executable) başlıklarının yazılması
    WriteProcessMemory(hProcess, pTargetBase, pSrcData, pNtHeaders->OptionalHeader.SizeOfHeaders, nullptr);

    // DLL bölümlerinin (Sections) hedef bellek adreslerine hizalanarak yazılması
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (UINT i = 0; i != pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            WriteProcessMemory(hProcess, (LPVOID)((PBYTE)pTargetBase + pSectionHeader->VirtualAddress), pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr);
        }
    }

    // Haritalama parametrelerinin hazırlanması
    MAPPING_DATA data;
    data.pLoadLibraryA = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    data.pGetProcAddress = (PVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
    data.pBaseAddress = pTargetBase;

    // Argümanların ve Shellcode'un hedef sürece transfer edilmesi
    LPVOID pMappingDataTarget = VirtualAllocEx(hProcess, nullptr, sizeof(MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    WriteProcessMemory(hProcess, pMappingDataTarget, &data, sizeof(MAPPING_DATA), nullptr);

    DWORD shellcodeSize = (DWORD)((PBYTE)ShellcodeEnd - (PBYTE)Shellcode);
    LPVOID pShellcodeTarget = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, pShellcodeTarget, (LPCVOID)Shellcode, shellcodeSize, nullptr);

    // Uzak iş parçacığı (Remote Thread) vasıtasıyla yükleyici kabuk kodun koşturulması
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcodeTarget, pMappingDataTarget, 0, nullptr);
    if (!hThread) {
        std::cout << "[-] CreateRemoteThread basarisiz oldu. Korumalar enjeksiyonu engelliyor olabilir.\n";
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        delete[] pSrcData;
        system("pause");
        return 0;
    }

    std::cout << "[+] Veriler haritalandirildi. DllMain tetiklenmesi bekleniyor...\n";
    WaitForSingleObject(hThread, INFINITE);

    // Çalıştırılan geçici Shellcode ve yapı verilerinin temizlenmesi (DLL imajı korunur)
    VirtualFreeEx(hProcess, pMappingDataTarget, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pShellcodeTarget, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    delete[] pSrcData;

    std::cout << "[+] Manual Mapping enjeksiyonu basariyla sonlandirildi!\n";
    Sleep(2000);
    return 0;
}
