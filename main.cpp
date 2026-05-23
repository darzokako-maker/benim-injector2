#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h>

// IAT taramalarını ve anti-cheat analizlerini atlatmak için fonksiyon işaretçileri
typedef HANDLE(WINAPI* pOpenProcess)(DWORD, BOOL, DWORD);
typedef LPVOID(WINAPI* pVirtualAllocEx)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pWriteProcessMemory)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
typedef HANDLE(WINAPI* pCreateRemoteThread)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(WINAPI* pVirtualFreeEx)(HANDLE, LPVOID, SIZE_T, DWORD);

// Klasörden manuel DLL seçmek için Unicode pencere açar
std::wstring KlasordenDllSec() {
    OPENFILENAMEW ofn;
    wchar_t szFile[260] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = L"Dynamic Link Library (*.dll)\0*.dll\0Tum Dosyalar (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameW(&ofn) == TRUE) {
        return std::wstring(ofn.lpstrFile);
    }
    return L"";
}

// Oyunun Süreç (Process) ID'sini bulan fonksiyon
DWORD OyunIdBul(const wchar_t* uygulamaIsmi) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(hSnap, &pe)) {
            do {
                if (!_wcsicmp(pe.szExeFile, uygulamaIsmi)) {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }
    return processId;
}

int main() {
    // Konsol başlığı standart kalıyor
    SetConsoleTitleW(L"Universal DLL Injector");

    std::wcout << L"[*] Lutfen enjekte edilecek DLL dosyasini secin...\n";
    std::wstring dllYolu = KlasordenDllSec();

    if (dllYolu.empty()) {
        std::wcout << L"[-] Dosya secilmedi. Cikis yapiliyor.\n";
        Sleep(2000);
        return 0;
    }

    // Hedef oyun ismi
    const wchar_t* hedefOyun = L"ProSoccerOnline-Win64-Shipping.exe";
    std::wcout << L"[*] Oyun bekleniyor...\n";

    // Oyun açılana kadar döngüde bekle
    DWORD pID = 0;
    while (pID == 0) {
        pID = OyunIdBul(hedefOyun);
        Sleep(500);
    }

    std::wcout << L"[+] Oyun Bulundu! PID: " << pID << L"\n";

    // Windows API fonksiyonlarını kernel32.dll içinden gizlice dinamik olarak çekiyoruz
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (!hKernel32) return 0;

    pOpenProcess _OpenProcess = (pOpenProcess)GetProcAddress(hKernel32, "OpenProcess");
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)GetProcAddress(hKernel32, "VirtualAllocEx");
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)GetProcAddress(hKernel32, "WriteProcessMemory");
    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)GetProcAddress(hKernel32, "CreateRemoteThread");
    pVirtualFreeEx _VirtualFreeEx = (pVirtualFreeEx)GetProcAddress(hKernel32, "VirtualFreeEx");

    // Oyuna tam yetkiyle bağlan
    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!hProcess) {
        std::wcout << L"[-] Oyuna baglanilamadi. Yonetici olarak calistirin.\n";
        system("pause");
        return 0;
    }

    // Bellek boyutunu Unicode karakter yapısına göre hesapla
    SIZE_T dllPathSize = (dllYolu.length() + 1) * sizeof(wchar_t);

    // Oyun hafızasında yer aç
    void* ayrilanAlan = _VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        CloseHandle(hProcess);
        return 0;
    }

    // Seçilen DLL yolunu oyunun hafızasına yaz (Tür dönüşümü hatası düzeltildi)
    _WriteProcessMemory(hProcess, ayrilanAlan, (LPCVOID)dllYolu.c_str(), dllPathSize, nullptr);

    // Yükleyici olarak Unicode destekli LoadLibraryW fonksiyon adresini alıyoruz
    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryW");

    // Enjeksiyonu stabil CreateRemoteThread ile tetikle
    HANDLE hThread = _CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAdresi, ayrilanAlan, 0, nullptr);
    if (!hThread) {
        std::wcout << L"[-] Enjeksiyon basarisiz oldu.\n";
        _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        system("pause");
        return 0;
    }

    std::wcout << L"[+] Enjeksiyon baslatildi! Oyunun hafizasi taranirken donmasini bekleyin...\n";

    // DLL'in oyuna tamamen yüklenmesini bekle
    WaitForSingleObject(hThread, INFINITE);

    // BELLEK TEMİZLİĞİ: DLL başarıyla yüklendi, artık arkada bıraktığımız izleri silme zamanı.
    // Oyun RAM'ine yazdığımız DLL yolunu tamamen boşaltıyoruz.
    _VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);

    CloseHandle(hThread);
    CloseHandle(hProcess);

    std::wcout << L"[+] Islem tamamlandi. Oyunun donmasi gectikten sonra klasorunuzu kontrol edin.\n";
    Sleep(3000);
    return 0;
}
