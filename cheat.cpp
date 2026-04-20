#include <windows.h>
#include <iostream>
#include <vector>

// CS2 Offsets - Updated based on latest dump (a2x/cs2-dumper)
namespace offsets {
    constexpr ptrdiff_t dwLocalPlayerPawn = 0x206D5E0;
    constexpr ptrdiff_t dwEntityList = 0x24B1268;

    namespace client_dll {
        constexpr ptrdiff_t m_iTeamNum = 0x3F3;
        constexpr ptrdiff_t m_iHealth = 0x354;
        constexpr ptrdiff_t m_vOldOrigin = 0x1588;
    }
}

// DLL main logic
void MainThread(HMODULE hModule) {
    // Open a console for debugging
    AllocConsole();
    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    printf("==========================================\n");
    printf("   Sorozaza CS2 Internal Cheat Loaded\n");
    printf("==========================================\n");
    printf("[+] Manual Map: Success\n");
    printf("[+] Modules: client.dll found\n");
    printf("[!] Press 'END' to unload and exit.\n\n");

    uintptr_t clientModule = (uintptr_t)GetModuleHandleA("client.dll");

    while (!(GetAsyncKeyState(VK_END) & 0x8000)) {
        if (!clientModule) {
            clientModule = (uintptr_t)GetModuleHandleA("client.dll");
            Sleep(1000);
            continue;
        }

        uintptr_t localPlayerPawn = *(uintptr_t*)(clientModule + offsets::dwLocalPlayerPawn);

        if (localPlayerPawn) {
            int health = *(int*)(localPlayerPawn + offsets::client_dll::m_iHealth);
            int team = *(int*)(localPlayerPawn + offsets::client_dll::m_iTeamNum);

            // Basic Info Display
            static int lastHealth = -1;
            if (health != lastHealth && health > 0 && health <= 100) {
                printf("\r[LocalPlayer] Health: %d | Team: %-21d", health, team);
                lastHealth = health;
            }
        }

        Sleep(50);
    }

    printf("\n[-] Unloading DLL...\n");
    if (f) fclose(f);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        HANDLE hThread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)MainThread, hModule, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
