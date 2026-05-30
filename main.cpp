#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h> // Dosya seçme penceresi (OpenFileName) için gerekli

// Kütüphaneyi bağlama
#pragma comment(lib, "Comdlg32.lib")

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

// Windows Dosya Seçme Penceresini açan fonksiyon
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
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn)) {
        return std::wstring(dosyaYolu);
    }
    return L"";
}

int main() {
    SetConsoleTitleA("Gorsel Secimli Manuel DLL Injector");

    std::wstring hedefIslem = L"";
    std::wstring dllYolu = L"";
    DWORD targetPID = 0;
    int secim = 0;

    // 1. ADIM: HEDEF İŞLEM SEÇİMİ
    std::cout << "=== HEDEF ISLEM SECIMI ===\n";
    std::cout << "1. Islem Adi ile Hedefle (Ornek: oyunadi.exe)\n";
    std::cout << "2. Dogrudan PID ile Hedefle (Ornek: 4321)\n";
    std::cout << "Seciminiz: ";
    std::cin >> secim;
    std::cin.ignore();

    if (secim == 1) {
        std::wcout << L"Hedef Islem Adini Giriniz (Uzantisiyla birlikte): ";
        std::getline(std::wcin, hedefIslem);
        
        std::wcout << L"[+] " << hedefIslem << L" bekleniyor...\n";
        while (targetPID == 0) {
            targetPID = IslemAdindanPidBul(hedefIslem);
            Sleep(500);
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

    // 2. ADIM: GÖRSEL DLL SEÇİMİ
    std::cout << "=== DLL SECIMI ===\n";
    std::cout << "[+] DLL secmek icin acilan pencereyi kullanin...\n";
    
    dllYolu = DllSecmePenceresi();

    if (dllYolu.empty()) {
        std::cout << "[-] Herhangi bir DLL secilmedi veya islem iptal edildi.\n";
        system("pause");
        return 0;
    }

    std::wcout << L"[+] Secilen DLL: " << dllYolu << L"\n";
    std::wcout << L"[+] Enjeksiyon islemi baslatiliyor...\n";

    // 3. ADIM: ENJEKSİYON İŞLEMLERİ
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 0;

    pOpenProcess _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    pVirtualFreeEx _VirtualFreeEx = (pVirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::wcout << L"[-] Hedef surece baglanilamadi! Yonetici olarak calistirmayi deneyin.\n";
        system("pause");
        return 0;
    }

    size_t dllPathSize = (dllYolu.length() + 1) * sizeof(wchar_t);

    LPVOID ayrilanAlan = _VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        std::wcout << L"[-] Hedef hafizada alan tahsis edilemedi.\n";
        CloseHandle(hProcess);
        return 0;
    }

    if (!_WriteProcessMemory(hProcess, ayrilanAlan, (LPCVOID)dllYolu.c_str(), dllPathSize, nullptr)) {
        std::wcout << L"[-] Hedef hafizasina veri yazilamadi.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    HANDLE hThread = _CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAdresi, ayrilanAlan, 0, nullptr);
    if (!hThread) {
        std::wcout << L"[-] CreateRemoteThread basarisiz oldu.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    std::wcout << L"[+] DLL basariyla tetiklendi. Yuklenmesi bekleniyor...\n";
    WaitForSingleObject(hThread, INFINITE);

    _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] Islemler basariyla tamamlandi!\n";
    Sleep(2000);
    return 0;
}
