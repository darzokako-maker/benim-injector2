#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>

// Dinamik çağrılar için fonksiyon işaretçileri tanımları
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// İşlem ismine göre PID bulma fonksiyonu
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

int main() {
    SetConsoleTitleA("Dinamik Manuel DLL Injector");

    std::wstring hedefIslem = L"";
    std::wstring dllYolu = L"";
    DWORD targetPID = 0;
    int secim = 0;

    // 1. ADIM: HEDEF İŞLEM SEÇİMİ
    std::cout << "=== HEDEF ISLEM SECIMI ===\n";
    std::cout << "1. Islem Adi ile Hedefle (Ornek: oyunadi.exe)\n";
    std::cout << "2. Doğrudan PID ile Hedefle (Ornek: 4321)\n";
    std::cout << "Seciminiz: ";
    std::cin >> secim;
    std::cin.ignore(); // Tamponu temizle

    if (secim == 1) {
        std::wcout << L"Hedef Islem Adini Giriniz (Uzantisiyla birlikte): ";
        std::getline(std::wcin, hedefIslem);
        
        std::wcout << L"[+] " << hedefIslem << L" bekleniyor...\n";
        while (targetPID == 0) {
            targetPID = IslemAdindanPidBul(hedefIslem);
            Sleep(500); // İşlemciyi yormamak için bekleme süresi
        }
    } 
    else if (secim == 2) {
        std::cout << "Hedef Islem PID degerini giriniz: ";
        std::cin >> targetPID;
        std::cin.ignore();
    } 
    else {
        std::cout << "[-] Gecersiz secim yapildi. Program kapatiliyor.\n";
        return 0;
    }

    std::wcout << L"[+] Hedef Belirlendi! PID: " << targetPID << L"\n\n";

    // 2. ADIM: DLL DOSYASI SEÇİMİ
    std::wcout << L"=== DLL SECIMI ===\n";
    std::wcout << L"Yuklemek istediginiz DLL dosyasinin tam yolunu veya adini girin: ";
    std::getline(std::wcin, dllYolu);

    // DLL dosyasının varlık kontrolü ve tam yol çözümlemesi
    wchar_t tamYol[MAX_PATH];
    GetFullPathNameW(dllYolu.c_str(), MAX_PATH, tamYol, nullptr);
    std::wstring dogrulanmisDllYolu(tamYol);

    DWORD fileAttr = GetFileAttributesW(dogrulanmisDllYolu.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::wcout << L"[-] Hata: Belirtilen yolda '" << dogrulanmisDllYolu << L"' dosyasi bulunamadi!\n";
        system("pause");
        return 0;
    }

    std::wcout << L"[+] Enjeksiyon islemi baslatiliyor...\n";

    // 3. ADIM: ENJEKSİYON İŞLEMLERİ (Dinamik API Çözümleme)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 0;

    pOpenProcess _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    pVirtualFreeEx _VirtualFreeEx = (pVirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    // Süreç bağlantısını açma
    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::wcout << L"[-] Hedef surece baglanilamadi! Yönetici olarak calistirmayi deneyin.\n";
        system("pause");
        return 0;
    }

    size_t dllPathSize = (dogrulanmisDllYolu.length() + 1) * sizeof(wchar_t);

    // Hedef süreç hafızasında yer ayırma
    LPVOID ayrilanAlan = _VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        std::wcout << L"[-] Hedef hafizada alan tahsis edilemedi.\n";
        CloseHandle(hProcess);
        return 0;
    }

    // DLL yolunu hedef hafızaya yazma
    if (!_WriteProcessMemory(hProcess, ayrilanAlan, (LPCVOID)dogrulanmisDllYolu.c_str(), dllPathSize, nullptr)) {
        std::wcout << L"[-] Hedef hafizasina veri yazilamadi.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    // LoadLibraryW adresini alma
    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    // Uzak iş parçacığı (Thread) oluşturarak tetikleme
    HANDLE hThread = _CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAdresi, ayrilanAlan, 0, nullptr);
    if (!hThread) {
        std::wcout << L"[-] CreateRemoteThread basarisiz oldu. Yetki yetersizligi veya koruma mevcut.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    std::wcout << L"[+] DLL basariyla tetiklendi. Yuklenmesi bekleniyor...\n";
    WaitForSingleObject(hThread, INFINITE);

    // Temizlik işlemleri
    _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] Islemler basariyla tamamlandi!\n";
    Sleep(2000);
    return 0;
}
