/*
 * shim_test.c  —  Shim Validation Tool
 * ======================================
 * Loads packet_shim.dll, installs hooks, then replays the exact
 * sequence FLS30.exe uses to talk to the packet driver.
 *
 * Build (x86):
 *   cl /nologo /W4 /O2 /DUNICODE /D_UNICODE shim_test.c ^
 *      /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
 *      kernel32.lib advapi32.lib /OUT:shim_test.exe
 *
 * Run as Administrator (needs Npcap + SCM access).
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <winsvc.h>
#include <stdio.h>
#include <strsafe.h>

#define IOCTL_ENUM_ADAPTERS     0x8000000CUL
#define IOCTL_GET_MAC           0x00170002UL
#define ENUM_BUF_SIZE           0xA00

static int tests_run  = 0;
static int tests_pass = 0;

#define TEST(name, expr) do { \
    tests_run++; \
    if (expr) { wprintf(L"  [PASS] %s\n", name); tests_pass++; } \
    else       { wprintf(L"  [FAIL] %s  (err=%u)\n", name, GetLastError()); } \
} while(0)

int wmain(void)
{
    wprintf(L"\n FLS30 Shim Test\n");
    wprintf(L" ===============\n\n");

    /* ── Step 0: Load shim and install IAT hooks in this process ── */
    wprintf(L"[0] Loading packet_shim.dll\n");
    HMODULE hShim = LoadLibraryW(L"packet_shim.dll");
    TEST(L"LoadLibraryW(packet_shim.dll)", hShim != NULL);

    if (!hShim) {
        wprintf(L"  Cannot continue without shim — ensure packet_shim.dll\n"
                L"  and fls30_shim.ini are in the same directory.\n\n");
        return 1;
    }

    typedef BOOL (WINAPI *PfnInit)(void);
    PfnInit pfnInit = (PfnInit)GetProcAddress(hShim, "PacketShimInit");
    TEST(L"GetProcAddress(PacketShimInit)", pfnInit != NULL);
    if (pfnInit) {
        BOOL ok = pfnInit();
        TEST(L"PacketShimInit() succeeded", ok);
    }

    /* ── Step 1: SCM hooks (mirrors FUN_004735ee in FLS30) ─────────
     * FLS30 calls OpenServiceW("Packet") → StartServiceW.
     * Shim intercepts and fakes SERVICE_RUNNING.
     */
    wprintf(L"\n[1] SCM hook — \"Packet\" service\n");
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    TEST(L"OpenSCManager", scm != NULL);

    if (scm) {
        SC_HANDLE svcPacket = OpenServiceW(scm, L"Packet", SERVICE_QUERY_STATUS | SERVICE_START);
        TEST(L"OpenServiceW(Packet) returns handle (shim intercept)", svcPacket != NULL);

        if (svcPacket) {
            /* StartServiceW should return FALSE with ERROR_SERVICE_ALREADY_RUNNING */
            SetLastError(0);
            BOOL started = StartServiceW(svcPacket, 0, NULL);
            DWORD err = GetLastError();
            TEST(L"StartServiceW → ERROR_SERVICE_ALREADY_RUNNING (1056)",
                 !started && err == ERROR_SERVICE_ALREADY_RUNNING);

            SERVICE_STATUS ss = {0};
            BOOL qok = QueryServiceStatus(svcPacket, &ss);
            TEST(L"QueryServiceStatus returns TRUE",  qok);
            TEST(L"dwCurrentState == SERVICE_RUNNING", ss.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(svcPacket);
        }

        /* Also verify real Npcap service is running */
        SC_HANDLE svcNpcap = OpenServiceW(scm, L"npcap", SERVICE_QUERY_STATUS);
        if (!svcNpcap) svcNpcap = OpenServiceW(scm, L"NPF", SERVICE_QUERY_STATUS);
        TEST(L"Npcap service exists", svcNpcap != NULL);
        if (svcNpcap) {
            SERVICE_STATUS ss2;
            QueryServiceStatus(svcNpcap, &ss2);
            TEST(L"Npcap service RUNNING", ss2.dwCurrentState == SERVICE_RUNNING);
            CloseServiceHandle(svcNpcap);
        }
        CloseServiceHandle(scm);
    }

    /* ── Step 2: GetAdapterList (mirrors GetAdapterList in FLS30)
     * CreateFileW("\\.\Packet") → shim returns fake control handle
     * DeviceIoControl(IOCTL_ENUM_ADAPTERS) → shim returns synthetic list
     */
    wprintf(L"\n[2] Adapter enumeration (IOCTL 0x8000000C)\n");

    HANDLE hControl = CreateFileW(
        L"\\\\.\\Packet",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    TEST(L"CreateFileW(\\\\.\\Packet) control device", hControl != INVALID_HANDLE_VALUE);

    /* adapterName is filled from ENUM_ADAPTERS and used for steps 3 & 4 */
    WCHAR adapterName[256] = {0};
    WCHAR adapterDevPath[MAX_PATH] = {0};

    if (hControl != INVALID_HANDLE_VALUE) {
        BYTE  buf[ENUM_BUF_SIZE] = {0};
        DWORD ret = 0;

        BOOL ok = DeviceIoControl(hControl, IOCTL_ENUM_ADAPTERS,
                                  NULL, 0, buf, sizeof(buf), &ret, NULL);
        TEST(L"IOCTL_ENUM_ADAPTERS succeeded", ok);

        if (ok) {
            DWORD count = *(DWORD*)buf;
            TEST(L"Adapter count >= 1", count >= 1);
            wprintf(L"         count = %u\n", count);

            WCHAR *p = (WCHAR*)(buf + sizeof(DWORD));
            for (DWORD i = 0; i < count && *p; i++) {
                WCHAR *name = p;
                while (*p) p++; p++;
                WCHAR *desc = p;
                while (*p) p++; p++;
                wprintf(L"         [%u] name='%s'  desc='%s'\n", i, name, desc);
                if (i == 0 && adapterName[0] == L'\0')
                    StringCchCopyW(adapterName, 256, name);
            }
        }
        CloseHandle(hControl);
    }

    /* Device path = "\\.\<name>" — FLS30 uses this format directly */
    if (adapterName[0])
        StringCchPrintfW(adapterDevPath, MAX_PATH, L"\\\\.\\%s", adapterName);
    else
        StringCchCopyW(adapterDevPath, MAX_PATH, L"\\\\.\\NPF_UNKNOWN");

    wprintf(L"\n     Adapter device path: %s\n", adapterDevPath);

    /* ── Step 3: GetMacAddress (mirrors FUN_00473262)
     * FLS30 opens "\\.\<name>" from ENUM_ADAPTERS with access=0.
     * Shim now returns the real NPF_{GUID} name so this goes straight to Npcap.
     */
    wprintf(L"\n[3] MAC address query (IOCTL 0x170002)\n");

    HANDLE hMac = CreateFileW(
        adapterDevPath,
        0,              /* access=0 — IOCTL only, matches FUN_00473262 */
        1,              /* FILE_SHARE_READ */
        NULL,
        OPEN_EXISTING,
        0,
        INVALID_HANDLE_VALUE);

    TEST(L"CreateFileW(adapter, access=0)", hMac != INVALID_HANDLE_VALUE);

    if (hMac != INVALID_HANDLE_VALUE) {
        DWORD magic    = 0x01010102;
        BYTE  mac[6]   = {0};
        DWORD ret      = 0;

        BOOL ok = DeviceIoControl(hMac, IOCTL_GET_MAC,
                                  &magic, sizeof(magic),
                                  mac, sizeof(mac),
                                  &ret, NULL);
        TEST(L"IOCTL_GET_MAC succeeded", ok);
        TEST(L"MAC returned 6 bytes", ret == 6);

        if (ok)
            wprintf(L"         MAC = %02X:%02X:%02X:%02X:%02X:%02X\n",
                    mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

        CloseHandle(hMac);
    }

    /* ── Step 4: Open adapter for R/W (mirrors FUN_004731c8) ───────
     * Same path from ENUM_ADAPTERS — NPF_{GUID} device, opened by FLS30 directly.
     */
    wprintf(L"\n[4] Adapter R/W open (SendPacket path)\n");

    HANDLE hRW = CreateFileW(
        adapterDevPath,
        GENERIC_READ | GENERIC_WRITE,
        0, NULL,
        OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED,
        NULL);

    TEST(L"CreateFileW(adapter, GENERIC_RW, OVERLAPPED)", hRW != INVALID_HANDLE_VALUE);

    if (hRW != INVALID_HANDLE_VALUE) {
        /* Minimal valid Ethernet frame for FLS30 DAU protocol:
         *   dst MAC:   FF:FF:FF:FF:FF:FF  (broadcast)
         *   src MAC:   02:00:46:4C:53:30  (ascii "FLS0")
         *   EtherType: AA:55  (confirmed from packet.sys FUN_00010f10)
         *   payload:   0x42 * 46 bytes
         */
        BYTE frame[60] = {0};
        memset(frame + 0x00, 0xFF, 6);
        frame[0x06] = 0x02; frame[0x07] = 0x00;
        frame[0x08] = 0x46; frame[0x09] = 0x4C;
        frame[0x0A] = 0x53; frame[0x0B] = 0x30;
        frame[0x0C] = 0xAA; frame[0x0D] = 0x55;
        memset(frame + 0x0E, 0x42, sizeof(frame) - 0x0E);

        OVERLAPPED ov  = {0};
        ov.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
        DWORD written  = 0;

        BOOL ok = WriteFile(hRW, frame, sizeof(frame), &written, &ov);
        if (!ok && GetLastError() == ERROR_IO_PENDING)
            ok = GetOverlappedResult(hRW, &ov, &written, TRUE);

        TEST(L"WriteFile (EtherType 0xAA55 frame, 60 bytes)", ok && written == 60);
        wprintf(L"         %u bytes sent\n", written);

        CloseHandle(ov.hEvent);
        CloseHandle(hRW);
    }

    /* ── Results ──────────────────────────────────────────────────── */
    wprintf(L"\n ================================\n");
    wprintf(L"  %d / %d tests passed\n", tests_pass, tests_run);
    wprintf(L" ================================\n\n");

    if (tests_pass == tests_run) {
        wprintf(L"  All tests passed — FLS30.exe should work.\n\n");
        return 0;
    } else {
        wprintf(L"  Some tests failed — check Npcap installation and\n");
        wprintf(L"  fls30_shim.ini AdapterGUID setting.\n\n");
        return 1;
    }
}
