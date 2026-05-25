#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>

// IAT taramalarını ve anti-cheat analizlerini atlatmak için fonksiyon işaretçileri
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// Arka planda CS2'nin açılmasını bekleyen ve PID değerini dönen fonksiyon
DWORD CsGOProcessBul() {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Doğrudan Counter-Strike 2 sürecini arıyoruz
            if (L"cs2.exe" == std::wstring(pe32.szExeFile)) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

int main() {
    SetConsoleTitleA("Axion Otomatik CS2 Injector");
    
    std::wcout << L"[+] Axion.dll enjeksiyonu icin Counter-Strike 2 bekleniyor...\\n";

    // CS2 açılana kadar injector arka planda bekler
    DWORD targetPID = 0;
    while (targetPID == 0) {
        targetPID = CsGOProcessBul();
        Sleep(500); // İşlemciyi yormamak için yarım saniye bekle
    }

    std::wcout << L"[+] CS2 Bulundu! PID: " << targetPID << L"\\n";
    std::wcout << L"[+] Enjeksiyon islemi baslatiliyor...\\n";

    // Dinamik IAT Çözümlemesi ile API çağrıları (Orijinal kodundaki gizlilik yapısı)
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 0;

    pOpenProcess _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    pVirtualFreeEx _VirtualFreeEx = (pVirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    // Süreç bağlantısı açma
    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::wcout << L"[-] CS2 surecine baglanilamadi! Yonetici olarak calistirmayi deneyin.\\n";
        system("pause");
        return 0;
    }

    // Aynı klasörde yer alması gereken Axion.dll dosyasının adını tam yol olarak alıyoruz
    std::wstring dllName = L"Axion.dll";
    wchar_t fullPath[MAX_PATH];
    GetFullPathNameW(dllName.c_str(), MAX_PATH, fullPath, nullptr);
    std::wstring dllYolu(fullPath);

    // DLL dosyasının klasörde var olup olmadığını kontrol etme
    DWORD fileAttr = GetFileAttributesW(dllYolu.c_str());
    if (fileAttr == INVALID_FILE_ATTRIBUTES || (fileAttr & FILE_ATTRIBUTE_DIRECTORY)) {
        std::wcout << L"[-] Hata: Injector ile ayni klasorde 'Axion.dll' bulunamadi!\\n";
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    size_t dllPathSize = (dllYolu.length() + 1) * sizeof(wchar_t);

    // Oyun hafızasında DLL yolunu yazmak için alan ayırma
    LPVOID ayrilanAlan = _VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        std::wcout << L"[-] Oyun hafizasinda alan tahsis edilemedi.\\n";
        CloseHandle(hProcess);
        return 0;
    }

    // DLL yolunu oyunun hafızasına yazma
    if (!_WriteProcessMemory(hProcess, ayrilanAlan, (LPCVOID)dllYolu.c_str(), dllPathSize, nullptr)) {
        std::wcout << L"[-] Oyun hafizasina veri yazilamadi.\\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    // LoadLibraryW fonksiyon adresini alıyoruz
    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    // Enjeksiyonu uzak thread oluşturarak tetikleme
    HANDLE hThread = _CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAdresi, ayrilanAlan, 0, nullptr);
    if (!hThread) {
        std::wcout << L"[-] CreateRemoteThread basarisiz oldu. Anti-cheat engellemis olabilir.\\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    std::wcout << L"[+] Axion.dll basariyla tetiklendi. Yuklenmesi bekleniyor...\\n";

    // DLL'in oyuna yüklenmesini bekle
    WaitForSingleObject(hThread, INFINITE);

    // BELLEK TEMİZLİĞİ: RAM'e yazılan string izini güvenle silme
    _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] Enjeksiyon basarili! Kapatiliyor...\\n";
    Sleep(2000);
    return 0;
}
