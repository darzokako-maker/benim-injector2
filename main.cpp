#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h>

// Klasörden DLL seçme penceresi (Unicode / Wide Char Uyumlu hale getirildi)
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

// Hedef sürecin ID'sini ve ilk geçerli Thread ID'sini bulan fonksiyon (Unicode)
DWORD OyunVeThreadIdBul(const wchar_t* uygulamaIsmi, DWORD& threadId) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; // Unicode yapısı
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

    if (processId != 0) {
        HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            if (Thread32First(hThreadSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == processId) {
                        threadId = te.th32ThreadID;
                        break;
                    }
                } while (Thread32Next(hThreadSnap, &te));
            }
            CloseHandle(hThreadSnap);
        }
    }
    return processId;
}

int main() {
    SetConsoleTitleW(L"Universal DLL Injector");

    std::wcout << L"[*] Lutfen enjekte edilecek DLL dosyasini secin...\n";
    std::wstring dllYolu = KlasordenDllSec();

    if (dllYolu.empty()) {
        std::wcout << L"[-] Dosya secilmedi. Cikis yapiliyor.\n";
        Sleep(2000);
        return 0;
    }

    const wchar_t* hedefOyun = L"ProSoccerOnline-Win64-Shipping.exe";
    std::wcout << L"[*] Oyun ve yasal is parcacigi (Thread) bekleniyor...\n";

    DWORD pID = 0;
    DWORD tID = 0;
    while (pID == 0 || tID == 0) {
        pID = OyunVeThreadIdBul(hedefOyun, tID);
        Sleep(500);
    }

    std::wcout << L"[+] Oyun Bulundu! PID: " << pID << L" | Thread ID: " << tID << L"\n";

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!hProcess) {
        std::wcout << L"[-] Oyuna baglanilamadi. Yonetici olarak calistirin.\n";
        system("pause");
        return 0;
    }

    // Bellek boyutu wchar_t cinsinden hesaplanıyor (byte boyutu için * sizeof(wchar_t))
    SIZE_t dllPathSize = (dllYolu.length() + 1) * sizeof(wchar_t);

    // Bellek alanı açılıyor
    void* ayrilanAlan = VirtualAllocEx(hProcess, nullptr, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        CloseHandle(hProcess);
        return 0;
    }

    // DLL yolu belleğe yazılıyor
    WriteProcessMemory(hProcess, ayrilanAlan, dllYolu.c_str(), dllPathSize, nullptr);

    // GİZLİLİK: LoadLibraryA yerine Unicode destekleyen LoadLibraryW fonksiyonunu çağırıyoruz
    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW");

    // THREAD HIJACKING işlemleri
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tID);
    if (hThread) {
        SuspendThread(hThread);

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, &ctx);

        #ifdef _WIN64
        ctx.Rip = (DWORD64)loadLibraryAdresi;
        #else
        ctx.Eip = (DWORD)loadLibraryAdresi;
        #endif

        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread);
        CloseHandle(hThread);
        
        std::wcout << L"[+] Is parcacigi basariyla manipule edildi.\n";
    } else {
        std::wcout << L"[-] Istek basarisiz oldu.\n";
        VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    std::wcout << L"[+] Enjeksiyon tamamlandi.\n";

    // BELLEK GİZLEME: İş bitti, alanı erişime kapatıyoruz
    DWORD eskiKoruma;
    VirtualProtectEx(hProcess, ayrilanAlan, dllPathSize, PAGE_NOACCESS, &eskiKoruma);

    CloseHandle(hProcess);
    Sleep(2000);
    return 0;
}
