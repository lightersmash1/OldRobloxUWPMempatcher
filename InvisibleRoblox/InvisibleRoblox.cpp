#define Roblox32BIT 1 // change to 1 if you want it to use UWP app

#include "Memory.h"

int main()
{
    opbn();gbns();
    if (!Base) {
        cout << "Roblox Not Found" << endl;
        while (1) {}
        return 0;
    }
    cout << "Placing Roblox Memory into Program Memory for scanning" << endl;
    RobloxMemory = new BYTE[SizeOfR];
    ReadProcessMemory(RobloxInstance, (LPVOID)Base, RobloxMemory, SizeOfR, new size_t);
    cout << "Done placing memory." << endl;
    cout << "---------------------------" << endl;
    cout << "Performing AOB Scans" << endl;
    vector<const char*> AOBList = {
            "8B 4F 38 85 C9 74 12 E8 ?? ?? ?? ?? 89 45 E8 85 C0 0F ?? ?? ?? 00 00 EB 05 8B C7 89 7D E8 8B 70 0C E8 ?? ?? ?? ?? 0F ?? ?? ?? ?? 00 00 0F ?? ?? ?? ?? 00 00 0F ?? ?? ?? ?? 00 00 2B D1 3B D0 0F ?? ?? ?? ?? ?? 8B 45 E8",
            "85 D2 74 36 8B 01 83 F8 09",
            "?? ?? ?? ?? 00 8D 93 C8 00",
            "E8 ? ? ? ? 8B 77 14 8B 86 ? ? ? ? 05 ? ? ? ? 89 85",
    };
    map<DWORD00, BYTE> oldaobs1;
    map<DWORD00, DWORD> oldaobs2;
    vector<vector<DWORD00>> AOBs = FindSignature4_2(
        AOBList
    );
    vector<vector<BYTE*>> AOBOriginals = ReadMemoryByLengths(AOBs, AOBList);
    DWORD00 TeleportLOL = AOBs[0][0] - (0x65); // C3
    DWORD00 CurIdenBypass = AOBs[1][0]; // 0xB0, 0x01, 0xC3
    DWORD00 Iden2Bypass = ReadMemory<DWORD00>(AOBs[2][0]); // 0x01
    DWORD00 physicsasm = AOBs[3][0];
    cout << "---------------------------" << endl;
    cout << "Done with AOB Scans" << endl;
    cout << "Welcome to the exploit, type in cmds to find options on what you want to do." << endl;
    string command;
    while (1) {
        cout << ">";
        cin >> command;
        if (command == "cmds") {
            cout << "noteleport - stops :Teleport requests coming from the server from working" << endl;
            cout << "identitybypass - bypasses identity checks done by the client, so you can run exploits with more freedom" << endl;
            cout << "disablephysics - makes movement not work anymore for all other clients, but the server can work. (credits: reestart)" << endl;
            cout << "restoreaobs - fixes all changes done to AOBs" << endl;
        }
        if (command == "noteleport") {
            WriteMemory<BYTE>(TeleportLOL, 0xC3);
        }
        if (command == "identitybypass") {
            oldaobs2[TeleportLOL] = WriteMemory<DWORD>(CurIdenBypass, 0xC301B0);
            WriteMemory<BYTE>(Iden2Bypass, 1);
        }
        if (command == "disablephysics") {
            oldaobs2[physicsasm + 1] = WriteMemory<DWORD>(physicsasm + 1, 0x90909090);
            WriteMemory<BYTE>(physicsasm, 0x90);
        }
        if (command == "restoreaobs") {
            for (auto const& x : oldaobs1)
            {
                WriteMemory<BYTE>(x.first, x.second);
            }
            for (auto const& x : oldaobs2)
            {
                WriteMemory<DWORD>(x.first, x.second);
            }
            WriteMemory<BYTE>(TeleportLOL, 0x8B);
            WriteMemory<BYTE>(Iden2Bypass, 0);
            WriteMemory<BYTE>(physicsasm, 0xE8);
            cout << "Restored all AOBs" << endl;
        }
    }
}