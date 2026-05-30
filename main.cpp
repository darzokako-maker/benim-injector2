#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h> 
#include <limits>

// Gerekli sistem kütüphanelerini bağlayıcıya (Linker) tanıtıyoruz
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Comdlg32.lib")

// API Gizleme ve Dinamik Çözümleme için Fonksiyon İşaretçileri
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// Çalışan işlemler arasından girilen isme göre PID bulan fonksiyon
DWORD IslemAdindanPidBul(const std::wstring& islemAdi) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            // Küçük/büyük harf duyarlılığını azaltmak veya tam eşleşme sağlamak için doğrudan kontrol
            if (islemAdi == std::wstring(pe32.szExeFile)) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pid;
}

// Windows Dosya Gezginini açarak DLL seçtiren fonksiyon
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
    // Konsol Başlığı ayarı
    SetConsoleTitleA("Ride Otomatik DLL Injector");

    std::wstring dllYolu = L"";
    // İşlem adı uzantısıyla birlikte "Ride.exe" olarak tanımlandı
    std::wstring hedefIslem = L"Ride.exe"; 
    DWORD targetPID = 0;

    // 1. ADIM: OTOMATİK DLL SEÇİMİ
    std::cout << "========================================\n";
    std::cout << "       1. ADIM: DLL DOSYASI SECIN       \n";
    std::cout << "========================================\n";
    std::cout << "[+] Dosya secme penceresi aciliyor...\n";
    
    dllYolu = DllSecmePenceresi();

    if (dllYolu.empty()) {
        std::cout << "[-] DLL secilmedi veya iptal edildi. Program kapatiliyor.\n";
        system("pause");
        return 0;
    }

    std::wcout << L"[+] Secilen DLL: " << dllYolu << L"\n\n";

    // 2. ADIM: OTOMATİK İŞLEM TAKİBİ (Ride.exe bekleniyor)
    std::cout << "========================================\n";
    std::cout << "       2. ADIM: ISLEM BEKLENIYOR        \n";
    std::cout << "========================================\n";
    std::wcout << L"[+] '" << hedefIslem << L"' araniyor ve bekleniyor...\n";
    std::cout << "[+] Lutfen oyunu/uygulamayi baslatin.\n";

    // Ride.exe bulunana kadar döngü çalışır
    while (targetPID == 0) {
        targetPID = IslemAdindanPidBul(hedefIslem);
        Sleep(300); // İşlemciyi gereksiz yormamak için kısa bekleme süresi
    }

    std::wcout << L"\n[+] Hedef Yakalandi! PID: " << targetPID << L"\n";
    std::wcout << L"[+] Enjeksiyon islemleri baslatiliyor...\n\n";

    // 3. ADIM: ENJEKSİYON VE BELLEK YÖNETİMİ
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) {
        std::cout << "[-] kernel32.dll adresi alinamadi.\n";
        system("pause");
        return 0;
    }

    // Dinamik API adreslerinin çözümlenmesi
    pOpenProcess _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    pVirtualFreeEx _VirtualFreeEx = (pVirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    // Hedef sürece tam erişim yetkisiyle bağlanma
    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (!hProcess) {
        std::cout << "[-] Hedef surece baglanilamadi! Enjektoru 'Yonetici Olarak' calistirmayi deneyin.\n";
        system("pause");
        return 0;
    }

    // Unicode (wchar_t) boyut hesaplaması
    size_t dllPathSize = (dllYolu.length() + 1) * sizeof(wchar_t);

    // Hedef sürecin hafızasında yer açma
    LPVOID ayrilanAlan = _VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        std::cout << "[-] Hedef bellek alaninda yer tahsis edilemedi.\n";
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    // DLL yolunu açılan hafıza alanına yazma
    if (!_WriteProcessMemory(hProcess, ayrilanAlan, (LPCVOID)dllYolu.c_str(), dllPathSize, nullptr)) {
        std::cout << "[-] Hedef bellege veri yazma islemi basarisiz.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    // LoadLibraryW fonksiyonunun adresini alma
    PTHREAD_START_ROUTINE loadLibraryAdresi = (PTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

    // Uzak thread (iş parçacığı) oluşturarak DLL'i yükletme
    HANDLE hThread = _CreateRemoteThread(hProcess, nullptr, 0, loadLibraryAdresi, ayrilanAlan, 0, nullptr);
    if (!hThread) {
        std::cout << "[-] Uzak is parcacigi olusturulamadi. Yetki veya koruma engeli olabilir.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    std::cout << "[+] Modul enjekte edildi. Yukleme senkronizasyonu bekleniyor...\n";
    WaitForSingleObject(hThread, INFINITE);

    // Temizlik ve kapatma adımları
    _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::cout << "[+] Enjeksiyon basariyla tamamlandi! Program kapatiliyor.\n";
    Sleep(2000);
    return 0;
}
