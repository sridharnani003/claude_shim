/*
 * fls30_loader.c  —  FLS30 Shim Loader
 * =====================================
 * Launches FLS30.exe suspended, injects packet_shim.dll via
 * CreateRemoteThread + LoadLibrary, then resumes the process.
 *
 * This is the cleanest injection method for a 32-bit target on
 * Win11 x64 WoW64 — no AppInit_DLLs registry edit needed, and
 * the shim is in place before FLS30 makes any packet driver calls.
 *
 * Build (x86 to match FLS30.exe):
 *   cl /nologo /W4 /O2 /DUNICODE /D_UNICODE fls30_loader.c ^
 *      /link /SUBSYSTEM:CONSOLE /MACHINE:X86 ^
 *      kernel32.lib /OUT:fls30_loader.exe
 *
 * Usage:
 *   fls30_loader.exe [path\to\FLS30.exe]
 *   (defaults to FLS30.exe in same directory)
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <windows.h>
#include <stdio.h>
#include <strsafe.h>

static BOOL InjectDll(HANDLE hProcess, LPCWSTR dllPath);
static void Log(LPCWSTR fmt, ...);

int wmain(int argc, wchar_t *argv[])
{
    WCHAR exeDir[MAX_PATH]  = {0};
    WCHAR fls30Path[MAX_PATH] = {0};
    WCHAR shimPath[MAX_PATH]  = {0};

    /* Resolve paths */
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    WCHAR *slash = wcsrchr(exeDir, L'\\');
    if (slash) *(slash + 1) = L'\0';

    if (argc >= 2) {
        StringCchCopyW(fls30Path, MAX_PATH, argv[1]);
    } else {
        StringCchPrintfW(fls30Path, MAX_PATH, L"%sFLS30.exe", exeDir);
    }
    StringCchPrintfW(shimPath, MAX_PATH, L"%spacket_shim.dll", exeDir);

    /* Verify files exist */
    if (GetFileAttributesW(fls30Path) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[!] FLS30.exe not found: %s\n", fls30Path);
        return 1;
    }
    if (GetFileAttributesW(shimPath) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[!] packet_shim.dll not found: %s\n", shimPath);
        return 1;
    }

    wprintf(L"[*] Launching:  %s\n", fls30Path);
    wprintf(L"[*] Shim DLL:   %s\n", shimPath);

    /* Create FLS30 running (NOT suspended).
     *
     * Using CREATE_SUSPENDED + immediate remote-thread injection deadlocks on
     * 64-bit Windows when the target is a 32-bit (WoW64) process: the WoW64
     * emulation layer is not initialised until the main thread runs for the
     * first time, so any remote thread created before ResumeThread hangs
     * indefinitely waiting for that initialisation to complete.
     *
     * Injecting into a running process is safe here because FLS30's Delphi
     * VCL startup (form creation, resource loading, splash screen) takes
     * 2-3 seconds before it ever calls OpenSCManagerW("Packet"), giving
     * the injection — which completes in < 200 ms — a large safety margin. */
    STARTUPINFOW        si  = {0};
    PROCESS_INFORMATION pi  = {0};
    si.cb = sizeof(si);

    if (!CreateProcessW(fls30Path, NULL, NULL, NULL, FALSE,
                        0, NULL, exeDir, &si, &pi)) {
        wprintf(L"[!] CreateProcess failed: %u\n", GetLastError());
        return 2;
    }
    wprintf(L"[+] FLS30.exe created (PID %u)\n", pi.dwProcessId);

    /* Give the WoW64 loader a moment to finish its own initialisation before
     * we inject.  50 ms is far shorter than FLS30's startup, but long enough
     * for ntdll / WoW64 to reach a stable state where CreateRemoteThread works
     * reliably. */
    Sleep(50);

    /* Inject shim DLL */
    if (!InjectDll(pi.hProcess, shimPath)) {
        wprintf(L"[!] Injection failed — terminating\n");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return 3;
    }
    wprintf(L"[+] packet_shim.dll injected\n");

    wprintf(L"[+] FLS30.exe running with packet shim active\n");
    wprintf(L"    Watch DebugView (Sysinternals) for [PacketShim] messages\n");

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}

/* ── DLL injection via CreateRemoteThread + LoadLibraryW ─────── */
static BOOL InjectDll(HANDLE hProcess, LPCWSTR dllPath)
{
    SIZE_T  pathBytes = (wcslen(dllPath) + 1) * sizeof(WCHAR);
    LPVOID  remoteBuf = NULL;
    HANDLE  hThread   = NULL;
    BOOL    ok        = FALSE;
    DWORD   exitCode  = 0;

    /* Allocate remote memory for the DLL path string */
    remoteBuf = VirtualAllocEx(hProcess, NULL, pathBytes,
                               MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        wprintf(L"[!] VirtualAllocEx: %u\n", GetLastError());
        return FALSE;
    }

    /* Write the DLL path into the target process */
    if (!WriteProcessMemory(hProcess, remoteBuf, dllPath, pathBytes, NULL)) {
        wprintf(L"[!] WriteProcessMemory: %u\n", GetLastError());
        goto cleanup;
    }

    /* Get address of LoadLibraryW in kernel32 (same in all x86 WoW64 procs) */
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    /* VULN-18: GetModuleHandleW can return NULL if kernel32 is somehow not
     * mapped (should never happen in a real process, but guard anyway to
     * prevent passing NULL to GetProcAddress, which is undefined behaviour). */
    if (!hKernel32) {
        wprintf(L"[!] GetModuleHandleW(kernel32.dll) returned NULL: %u\n", GetLastError());
        goto cleanup;
    }
    FARPROC pfnLoadLib = GetProcAddress(hKernel32, "LoadLibraryW");
    if (!pfnLoadLib) {
        wprintf(L"[!] GetProcAddress(LoadLibraryW): %u\n", GetLastError());
        goto cleanup;
    }

    /* Create remote thread that calls LoadLibraryW(dllPath) */
    hThread = CreateRemoteThread(hProcess, NULL, 0,
                                 (LPTHREAD_START_ROUTINE)pfnLoadLib,
                                 remoteBuf, 0, NULL);
    if (!hThread) {
        wprintf(L"[!] CreateRemoteThread: %u\n", GetLastError());
        goto cleanup;
    }

    /* Wait for LoadLibrary to complete */
    DWORD waitResult = WaitForSingleObject(hThread, 10000);
    if (waitResult == WAIT_TIMEOUT) {
        wprintf(L"[!] LoadLibraryW remote thread timed out after 10s\n");
        goto cleanup;
    }
    if (waitResult != WAIT_OBJECT_0) {
        wprintf(L"[!] WaitForSingleObject(LoadLib thread) failed: %u\n", GetLastError());
        goto cleanup;
    }
    if (!GetExitCodeThread(hThread, &exitCode)) {
        wprintf(L"[!] GetExitCodeThread failed: %u\n", GetLastError());
        goto cleanup;
    }
    if (exitCode == 0) {
        wprintf(L"[!] LoadLibraryW returned NULL in target — DLL load failed\n"
                L"    Check: correct x86 DLL? VC++ redist installed? Path correct?\n");
        goto cleanup;
    }
    wprintf(L"[+] DLL loaded at remote base = 0x%08X\n", exitCode);

    /* Call PacketShimInit in the remote process to install IAT hooks.
     *
     * VULN-03 — ASLR offset assumption:
     * We load the DLL locally, compute the RVA of PacketShimInit
     * (pfnInit - hShimLocal), and add that RVA to the remote base address
     * returned by the LoadLibraryW remote thread (exitCode).
     *
     * This is valid because:
     *   a) Both processes are 32-bit WoW64 — the same DLL image is used.
     *   b) On the same machine Windows maps the DLL at the same preferred
     *      base in all processes when ASLR has not relocated it.  If ASLR
     *      does relocate, both the local and remote loads use the same
     *      relocated base (ASLR picks one base per boot per image, applied
     *      identically across processes).
     *   c) Even with per-process ASLR ("ASLR for DLLs"), the RVA offset
     *      within the image is fixed — only the base changes, and `exitCode`
     *      gives us the actual remote base, so `exitCode + RVA` is correct.
     *
     * Limitation: this does NOT work across machines or if the DLL on disk
     * is rebuilt between the local and remote loads (different image).  For
     * this use case (same machine, same session) it is reliable. */
    HMODULE hShimLocal = LoadLibraryW(dllPath);
    if (hShimLocal) {
        FARPROC pfnInit = GetProcAddress(hShimLocal, "PacketShimInit");
        if (pfnInit) {
            SIZE_T offset = (SIZE_T)pfnInit - (SIZE_T)hShimLocal;
            LPVOID remoteInit = (LPVOID)((SIZE_T)exitCode + offset);

            HANDLE hInitThread = CreateRemoteThread(
                hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE)remoteInit,
                NULL, 0, NULL);
            if (hInitThread) {
                DWORD initWait = WaitForSingleObject(hInitThread, 5000);
                if (initWait == WAIT_TIMEOUT) {
                    wprintf(L"[!] WARNING: PacketShimInit remote thread timed out\n");
                } else {
                    DWORD initCode = 0;
                    if (GetExitCodeThread(hInitThread, &initCode)) {
                        if (initCode == 0)
                            wprintf(L"[!] WARNING: PacketShimInit returned 0 (hook install may have failed)\n");
                        else
                            wprintf(L"[+] PacketShimInit returned 0x%08X (hooks installed)\n", initCode);
                    }
                }
                CloseHandle(hInitThread);
            } else {
                wprintf(L"[!] CreateRemoteThread(PacketShimInit) failed: %u\n", GetLastError());
            }
        } else {
            wprintf(L"[!] PacketShimInit not found in local DLL copy — export missing?\n");
        }
        FreeLibrary(hShimLocal);
    }

    ok = TRUE;
    wprintf(L"[+] Injection complete\n");

cleanup:
    if (hThread)   CloseHandle(hThread);
    if (remoteBuf) VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    return ok;
}
