#include <windows.h>
#include <iostream>

// DLL yüklendiğinde çalışacak ana fonksiyon
void MainThread(HMODULE hModule) {
    // Konsol penceresi aç (Takip edebilmen için)
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    printf("==============================\n");
    printf(" Sorozaza Ultimate DLL Yuklendi\n");
    printf("==============================\n");
    printf("[+] Manuel Mapping Basarili!\n");
    printf("[+] CS2 Icinde Kod Calisiyor.\n");
    printf("[!] Cikis yapmak icin 'END' tusuna bas.\n");

    // Hile döngüsü buraya gelir
    while (true) {
        Sleep(100);

        // Örnek: END tuşuna basıldığında hileyi kapat
        if (GetAsyncKeyState(VK_END) & 0x8000) {
            break;
        }
    }

    // Kapatma işlemleri
    printf("[-] DLL Kapatiliyor...\n");
    if (f) fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
}

// DLL'in giriş noktası
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        // Oyunun ana akışını bozmamak için yeni bir iş parçacığı (thread) açıyoruz
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

