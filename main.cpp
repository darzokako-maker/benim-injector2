#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <commdlg.h>

// Klasörden DLL seçme penceresi
std::string KlasordenDllSec() {
    OPENFILENAMEA ofn;
    char szFile[260] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "Dynamic Link Library (*.dll)\0*.dll\0Tum Dosyalar (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileNameA(&ofn) == TRUE) {
        return std::string(ofn.lpstrFile);
    }
    return "";
}

// Hedef sürecin ID'sini ve ilk geçerli Thread ID'sini bulan fonksiyon
DWORD OyunVeThreadIdBul(const char* uygulamaIsmi, DWORD& threadId) {
    DWORD processId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(hSnap, &pe)) {
            do {
                if (!_strcmpi(pe.szExeFile, uygulamaIsmi)) {
                    processId = pe.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe));
        }
        CloseHandle(hSnap);
    }

    // Sürece ait yasal bir Thread buluyoruz (Hijacking için)
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
    SetConsoleTitleA("Universal DLL Injector");

    std::cout << "[*] Lutfen enjekte edilecek DLL dosyasini secin...\n";
    std::string dllYolu = KlasordenDllSec();

    if (dllYolu.empty()) {
        std::cout << "[-] Dosya secilmedi. Cikis yapiliyor.\n";
        Sleep(2000);
        return 0;
    }

    const char* hedefOyun = "ProSoccerOnline-Win64-Shipping.exe";
    std::cout << "[*] Oyun ve yasal is parcacigi (Thread) bekleniyor...\n";

    DWORD pID = 0;
    DWORD tID = 0;
    while (pID == 0 || tID == 0) {
        pID = OyunVeThreadIdBul(hedefOyun, tID);
        Sleep(500);
    }

    std::cout << "[+] Oyun Bulundu! PID: " << pID << " | Thread ID: " << tID << "\n";

    // Süreci açıyoruz
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
    if (!hProcess) {
        std::cout << "[-] Oyuna baglanilamadi. Yonetici olarak calistirin.\n";
        system("pause");
        return 0;
    }

    // 1. BELLEK GİZLİLİĞİ: Alanı ilk başta sadece Okuma/Yazma olarak açıyoruz (Çalıştırılabilir değil)
    void* ayrilanAlan = VirtualAllocEx(hProcess, nullptr, dllYolu.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!ayrilanAlan) {
        CloseHandle(hProcess);
        return 0;
    }

    // DLL yolunu yazıyoruz
    WriteProcessMemory(hProcess, ayrilanAlan, dllYolu.c_str(), dllYolu.length() + 1, nullptr);

    // LoadLibraryA adresini alıyoruz
    LPVOID loadLibraryAdresi = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

    // 2. THREAD HIJACKING: Yeni thread açmak yerine mevcut olanı ele geçiriyoruz
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tID);
    if (hThread) {
        SuspendThread(hThread); // Thread'i geçici olarak durdur

        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, &ctx);

        // RIP (Instruction Pointer) kaydını LoadLibraryA adresine yönlendiriyoruz
        // Bu işlem thread devam ettiğinde bizim kodumuzu çalıştırmasını sağlar
        #ifdef _WIN64
        ctx.Rip = (DWORD64)loadLibraryAdresi;
        #else
        ctx.Eip = (DWORD)loadLibraryAdresi;
        #endif

        SetThreadContext(hThread, &ctx);
        ResumeThread(hThread); // Thread'i normal düzenine geri döndür
        CloseHandle(hThread);
        
        std::cout << "[+] Is parcacigi basariyla manipule edildi.\n";
    } else {
        std::cout << "[-] Istek basarisiz oldu.\n";
        VirtualFreeEx(hProcess, ayrilanAlan, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 0;
    }

    std::cout << "[+] Enjeksiyon tamamlandi.\n";

    // 3. BELLEK KORUMASI: İşlem bittikten sonra bu bellek alanının izinlerini tamamen kapatıyoruz
    // Böylece bellek taramalarında "boş/erişilemez" alan olarak görünür ve analiz edilemez.
    DWORD eskiKoruma;
    VirtualProtectEx(hProcess, ayrilanAlan, dllYolu.length() + 1, PAGE_NOACCESS, &eskiKoruma);

    CloseHandle(hProcess);
    Sleep(2000);
    return 0;
}

