/*
 * packet_shim.c  —  FLS30 Packet Driver Shim  (wpcap edition)
 * =============================================================
 * Intercepts FLS30's Win32 calls to \\.\Packet* and routes them
 * through Npcap's wpcap.dll (pcap_open_live / pcap_sendpacket /
 * pcap_next_ex), which is the only usermode path that works on
 * Windows 11 — NtCreateFile on \Device\NPF_* returns
 * STATUS_OBJECT_NAME_NOT_FOUND (Npcap uses its own IPC, not named
 * NT objects).
 *
 * Build (x86 to match FLS30.exe WoW64):
 *   cl /nologo /LD /W4 /WX /O2 /DUNICODE /D_UNICODE ^
 *      packet_shim.c ^
 *      /link /DLL /SUBSYSTEM:WINDOWS /MACHINE:X86 ^
 *      kernel32.lib advapi32.lib iphlpapi.lib ws2_32.lib ^
 *      /OUT:packet_shim.dll /DEF:packet_shim.def
 */

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winsvc.h>
/* iphlpapi.h included for types only — GetAdaptersAddresses loaded dynamically
 * to avoid IPHLPAPI.DLL appearing in our static import table (it causes a
 * ~10-second DllMain stall when injected into FLS30 via remote thread). */
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>

/* ── pcap declarations (dynamic load — no pcap.h needed) ─────── */
typedef struct pcap pcap_t;
struct pcap_pkthdr { DWORD tv_sec; DWORD tv_usec; DWORD caplen; DWORD len; };
struct bpf_program  { unsigned int bf_len; void *bf_insns; };

typedef pcap_t*      (*PfnPcapOpenLive)(const char*, int, int, int, char*);
typedef int          (*PfnPcapSendPacket)(pcap_t*, const unsigned char*, int);
typedef int          (*PfnPcapNextEx)(pcap_t*, struct pcap_pkthdr**, const unsigned char**);
typedef void         (*PfnPcapClose)(pcap_t*);
typedef const char*  (*PfnPcapGeterr)(pcap_t*);
typedef int          (*PfnPcapCompile)(pcap_t*, struct bpf_program*, const char*, int, unsigned int);
typedef int          (*PfnPcapSetFilter)(pcap_t*, struct bpf_program*);
typedef void         (*PfnPcapFreeCode)(struct bpf_program*);

/* pcap adapter enumeration */
typedef struct pcap_addr {
    struct pcap_addr *next;
    struct sockaddr  *addr;
    struct sockaddr  *netmask;
    struct sockaddr  *broadaddr;
    struct sockaddr  *dstaddr;
} pcap_addr_t;
typedef struct pcap_if {
    struct pcap_if *next;
    char           *name;        /* e.g. "\\Device\\NPF_{GUID}" */
    char           *description; /* human-readable NIC name     */
    pcap_addr_t    *addresses;
    DWORD           flags;
} pcap_if_t;
typedef int  (*PfnPcapFindAllDevs)(pcap_if_t**, char*);
typedef void (*PfnPcapFreeAllDevs)(pcap_if_t*);
typedef void (*PfnPcapBreakloop)(pcap_t*);   /* interrupts pcap_next_ex safely */

static HMODULE           g_hWpcap           = NULL;
static PfnPcapOpenLive   g_pcapOpenLive     = NULL;
static PfnPcapSendPacket g_pcapSendPkt      = NULL;
static PfnPcapNextEx     g_pcapNextEx       = NULL;
static PfnPcapClose      g_pcapClose        = NULL;
static PfnPcapGeterr     g_pcapGeterr       = NULL;
static PfnPcapCompile    g_pcapCompile      = NULL;
static PfnPcapSetFilter  g_pcapSetFilter    = NULL;
static PfnPcapFreeCode   g_pcapFreeCode     = NULL;
static PfnPcapFindAllDevs g_pcapFindAllDevs = NULL;
static PfnPcapFreeAllDevs g_pcapFreeAllDevs = NULL;
static PfnPcapBreakloop   g_pcapBreakloop   = NULL;

static HINSTANCE         g_hDll             = NULL; /* set in DllMain */

/* ── IOCTL codes ──────────────────────────────────────────────── */
#define IOCTL_ENUM_ADAPTERS      0x8000000CUL
#define IOCTL_GET_MAC            0x00170002UL
#define IOCTL_NDIS_SEND_LOOPBACK 0x80000000UL
#define IOCTL_NDIS_SEND          0x80000004UL
#define IOCTL_NDIS_RESET         0x80000008UL

/* ── Config / limits ─────────────────────────────────────────── */
#define CONFIG_FILE     L"fls30_shim.ini"
#define MAX_GUID_LEN    64
#define MAX_ADP         4

/* ── Fake handle sentinels ──────────────────────────────────────
 * Must not collide with real HANDLEs (kernel guarantees 4-byte
 * aligned handles; we use odd low-bytes to be safe).
 */
#define FAKE_CONTROL_HANDLE     ((HANDLE)(ULONG_PTR)0xFACE0001)
#define FAKE_SERVICE_HANDLE     ((SC_HANDLE)(ULONG_PTR)0xFACE0002)
#define FAKE_MAC_HANDLE         ((HANDLE)(ULONG_PTR)0xFACE0003)
#define FAKE_ADP_BASE           ((ULONG_PTR)0xFACE0010)
/* pcap adapter handles: FAKE_ADP_BASE + slot index (0..MAX_ADP-1) */

/* ── Pending async ReadFile request ──────────────────────────────
 * FLS30 pipelines multiple overlapped ReadFile calls under sustained
 * download load.  We keep a small circular queue per adapter so no
 * IRP is ever silently overwritten.
 */
#define IRP_QUEUE_DEPTH  8   /* max outstanding async ReadFiles per adapter */
typedef struct {
    LPVOID       buf;
    DWORD        bufSz;
    LPOVERLAPPED ov;
} RecvReq;

/* ── Per-adapter slot ─────────────────────────────────────────── */
#define INVALID_SEQ  0xFFFFFFFFUL   /* sentinel: no chunk seen yet */

typedef struct {
    BOOL         inUse;
    pcap_t      *pcap;
    /* async ReadFile IRP queue
     * irpLock guards irpHead/irpTail between FLS30's calling thread
     * (producer) and RecvThread (consumer). */
    CRITICAL_SECTION irpLock;
    RecvReq      irpQueue[IRP_QUEUE_DEPTH];
    int          irpHead;    /* producer writes here   (Hook_ReadFile) */
    int          irpTail;    /* consumer reads here    (RecvThread)    */
    HANDLE       thread;
    volatile BOOL stopThread;
    HANDLE       startEvt;   /* Hook_ReadFile signals → RecvThread wakes */
    /* per-window sequence tracking for FILE-ACK patch (Option A fix)
     * Only ever touched by this adapter's own RecvThread — no locking needed */
    DWORD        windowMinSeq;  /* lowest  seq# seen in current window  */
    DWORD        windowMaxSeq;  /* highest seq# seen in current window  */
} AdpEntry;

static AdpEntry g_Adp[MAX_ADP];

/* ── Global state ─────────────────────────────────────────────── */
static WCHAR g_NpcapGuid[MAX_GUID_LEN]    = {0};
static WCHAR g_AdapterName[128]           = L"FLS30DAU";
static BYTE  g_Mac[6]                     = {0};
static BOOL  g_Initialised                = FALSE;
static BOOL  g_TestMode                   = FALSE;
static CRITICAL_SECTION g_Lock;

/* ── TestMode: one-slot synthetic reply queue ─────────────────── */
static CRITICAL_SECTION g_ReplyLock;
static BYTE  g_ReplyFrame[60]             = {0};
static BOOL  g_ReplyReady                 = FALSE;
/* Fake DAU source MAC used in TestMode injected frames */
static const BYTE k_FakeDauMac[6]         = {0x00,0xDE,0xAD,0xDA,0x7F,0x00};


/* ── Forward declarations ─────────────────────────────────────── */
static BOOL      ShimInit(void);
static BOOL      FindNpcapAdapter(void);
static void      ShowAdapterPicker(LPCWSTR iniPath);
static void      FetchMac(void);
static HANDLE    OpenPcapHandle(DWORD acc, DWORD share, DWORD flags);
static AdpEntry* LookupAdp(HANDLE h);
static DWORD WINAPI RecvThread(LPVOID param);
static BOOL      BuildEnumResponse(PVOID buf, ULONG len, PULONG written);
static BOOL      IsControlDev(LPCWSTR p);
static BOOL      IsAdapterDev(LPCWSTR p);
static void      Log(LPCWSTR fmt, ...);

/* ══════════════════════════════════════════════════════════════
 * Logging
 * ══════════════════════════════════════════════════════════════ */
static void Log(LPCWSTR fmt, ...)
{
    WCHAR buf[512];
    va_list a;
    va_start(a, fmt);
    StringCchVPrintfW(buf, 512, fmt, a);
    va_end(a);
    OutputDebugStringW(buf);
}

/* ══════════════════════════════════════════════════════════════
 * DllMain
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    UNREFERENCED_PARAMETER(reserved);
    if (reason == DLL_PROCESS_ATTACH) {
        g_hDll = hInst;
        DisableThreadLibraryCalls(hInst);
        InitializeCriticalSection(&g_Lock);
        InitializeCriticalSection(&g_ReplyLock);
        ShimInit();
    } else if (reason == DLL_PROCESS_DETACH) {
        for (int i = 0; i < MAX_ADP; i++) {
            if (!g_Adp[i].inUse) continue;
            g_Adp[i].stopThread = TRUE;
            if (g_Adp[i].pcap && g_pcapBreakloop) g_pcapBreakloop(g_Adp[i].pcap);
            if (g_Adp[i].startEvt) SetEvent(g_Adp[i].startEvt);
            if (g_Adp[i].thread) {
                WaitForSingleObject(g_Adp[i].thread, 5000);
                CloseHandle(g_Adp[i].thread);
            }
            if (g_Adp[i].startEvt) CloseHandle(g_Adp[i].startEvt);
            if (g_Adp[i].pcap && g_pcapClose) g_pcapClose(g_Adp[i].pcap);
            DeleteCriticalSection(&g_Adp[i].irpLock);
        }
        if (g_hWpcap) FreeLibrary(g_hWpcap);
        DeleteCriticalSection(&g_Lock);
        DeleteCriticalSection(&g_ReplyLock);
    }
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════
 * ShimInit
 * ══════════════════════════════════════════════════════════════ */
static BOOL ShimInit(void)
{
    /* Load wpcap.dll — Npcap installs 32-bit copy in SysWOW64\Npcap
     * and adds its directory to PATH, so the short name usually works. */
    g_hWpcap = LoadLibraryW(L"wpcap.dll");
    if (!g_hWpcap)
        g_hWpcap = LoadLibraryW(L"C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll");
    if (g_hWpcap) {
        g_pcapOpenLive = (PfnPcapOpenLive) GetProcAddress(g_hWpcap, "pcap_open_live");
        g_pcapSendPkt  = (PfnPcapSendPacket)GetProcAddress(g_hWpcap, "pcap_sendpacket");
        g_pcapNextEx   = (PfnPcapNextEx)    GetProcAddress(g_hWpcap, "pcap_next_ex");
        g_pcapClose     = (PfnPcapClose)    GetProcAddress(g_hWpcap, "pcap_close");
        g_pcapGeterr    = (PfnPcapGeterr)   GetProcAddress(g_hWpcap, "pcap_geterr");
        g_pcapCompile    = (PfnPcapCompile)   GetProcAddress(g_hWpcap, "pcap_compile");
        g_pcapSetFilter  = (PfnPcapSetFilter) GetProcAddress(g_hWpcap, "pcap_setfilter");
        g_pcapFreeCode   = (PfnPcapFreeCode)  GetProcAddress(g_hWpcap, "pcap_freecode");
        g_pcapFindAllDevs= (PfnPcapFindAllDevs)GetProcAddress(g_hWpcap, "pcap_findalldevs");
        g_pcapFreeAllDevs= (PfnPcapFreeAllDevs)GetProcAddress(g_hWpcap, "pcap_freealldevs");
        g_pcapBreakloop  = (PfnPcapBreakloop)  GetProcAddress(g_hWpcap, "pcap_breakloop");
        Log(L"[PacketShim] wpcap.dll loaded OK\n");
    } else {
        Log(L"[PacketShim] WARNING: wpcap.dll not found\n");
    }

    /* Read ini from same dir as executable */
    WCHAR exeDir[MAX_PATH], iniPath[MAX_PATH];
    GetModuleFileNameW(NULL, exeDir, MAX_PATH);
    WCHAR *sl = wcsrchr(exeDir, L'\\');
    if (sl) *(sl + 1) = L'\0';
    StringCchPrintfW(iniPath, MAX_PATH, L"%s%s", exeDir, CONFIG_FILE);

    WCHAR guidBuf[MAX_GUID_LEN] = {0};
    GetPrivateProfileStringW(L"Npcap", L"AdapterGUID", L"",
                             guidBuf, MAX_GUID_LEN, iniPath);
    if (guidBuf[0]) {
        StringCchCopyW(g_NpcapGuid, MAX_GUID_LEN, guidBuf);
    } else {
        /* No adapter saved yet — show the picker so the user can choose.
         * Falls back to registry auto-detect if wpcap isn't available. */
        if (g_pcapFindAllDevs)
            ShowAdapterPicker(iniPath);
        if (!g_NpcapGuid[0] && !FindNpcapAdapter())
            Log(L"[PacketShim] WARNING: no Npcap adapter found\n");
    }

    GetPrivateProfileStringW(L"Adapter", L"FriendlyName", L"FLS30DAU",
                             g_AdapterName, 128, iniPath);
    g_TestMode = (GetPrivateProfileIntW(L"Debug", L"TestMode", 0, iniPath) != 0);
    if (g_TestMode) Log(L"[PacketShim] *** TEST MODE ENABLED — synthetic DAU frames ***\n");
    FetchMac();

    g_Initialised = TRUE;
    Log(L"[PacketShim] Ready: GUID=%s Name=%s MAC=%02X:%02X:%02X:%02X:%02X:%02X\n",
        g_NpcapGuid, g_AdapterName,
        g_Mac[0], g_Mac[1], g_Mac[2], g_Mac[3], g_Mac[4], g_Mac[5]);
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════
 * Adapter picker — shown once when fls30_shim.ini has no GUID.
 *
 * Creates a top-level window with a list-box of all Npcap adapters.
 * The user picks the NIC that connects to the DAU; the GUID is
 * written to [Npcap] AdapterGUID in fls30_shim.ini so it is
 * remembered on every subsequent launch.
 *
 * Uses PeekMessage + WaitMessage instead of PostQuitMessage so we
 * never post WM_QUIT into FLS30's thread message queue.
 * ══════════════════════════════════════════════════════════════ */
#define ADPPICK_LB      2001
#define ADPPICK_OK      2002
#define ADPPICK_CANCEL  2003
#define ADPPICK_CLSNAME L"FLS30ShimAdpPick"

typedef struct {
    pcap_if_t **devs;
    int         count;
    int         chosen; /* -1 = cancelled, >=0 = index into devs[] */
    BOOL        done;
} AdpPickCtx;

static LRESULT CALLBACK AdpPickWndProc(HWND hwnd, UINT msg,
                                        WPARAM wp, LPARAM lp)
{
    AdpPickCtx *ctx = (AdpPickCtx *)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
    case WM_CREATE: {
        CREATESTRUCTW *cs = (CREATESTRUCTW *)lp;
        ctx = (AdpPickCtx *)cs->lpCreateParams;
        SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)ctx);

        /* Instruction label */
        CreateWindowExW(0, L"STATIC",
            L"FLS30 DAU first-run setup\r\n"
            L"Select the Ethernet adapter that connects to the DAU.\r\n"
            L"Your choice is saved to fls30_shim.ini and won't be asked again.",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            10, 10, 464, 52, hwnd, NULL, g_hDll, NULL);

        /* Adapter list box */
        HWND lb = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOTIFY | LBS_NOINTEGRALHEIGHT,
            10, 70, 464, 170, hwnd,
            (HMENU)(ULONG_PTR)ADPPICK_LB, g_hDll, NULL);

        for (int i = 0; i < ctx->count; i++) {
            pcap_if_t *d = ctx->devs[i];
            WCHAR line[300] = {0};
            if (d->description && d->description[0]) {
                MultiByteToWideChar(CP_ACP, 0, d->description, -1, line, 300);
            } else {
                MultiByteToWideChar(CP_ACP, 0, d->name, -1, line, 300);
            }
            SendMessageW(lb, LB_ADDSTRING, 0, (LPARAM)line);
        }
        SendMessageW(lb, LB_SETCURSEL, 0, 0); /* pre-select first entry */

        /* Buttons */
        CreateWindowExW(0, L"BUTTON", L"Save && Continue",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
            274, 254, 120, 28, hwnd,
            (HMENU)(ULONG_PTR)ADPPICK_OK, g_hDll, NULL);
        CreateWindowExW(0, L"BUTTON", L"Cancel",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            404, 254, 70, 28, hwnd,
            (HMENU)(ULONG_PTR)ADPPICK_CANCEL, g_hDll, NULL);
        return 0;
    }

    case WM_COMMAND:
        if (LOWORD(wp) == ADPPICK_OK) {
            HWND lb = GetDlgItem(hwnd, ADPPICK_LB);
            int sel = (int)SendMessageW(lb, LB_GETCURSEL, 0, 0);
            ctx->chosen = (sel == LB_ERR) ? 0 : sel;
            ctx->done   = TRUE;
            DestroyWindow(hwnd);
        } else if (LOWORD(wp) == ADPPICK_CANCEL) {
            ctx->chosen = -1;
            ctx->done   = TRUE;
            DestroyWindow(hwnd);
        } else if (HIWORD(wp) == LBN_DBLCLK && LOWORD(wp) == ADPPICK_LB) {
            /* Double-click = select */
            HWND lb = GetDlgItem(hwnd, ADPPICK_LB);
            int sel = (int)SendMessageW(lb, LB_GETCURSEL, 0, 0);
            ctx->chosen = (sel == LB_ERR) ? 0 : sel;
            ctx->done   = TRUE;
            DestroyWindow(hwnd);
        }
        return 0;

    case WM_CLOSE:
        ctx->chosen = -1;
        ctx->done   = TRUE;
        DestroyWindow(hwnd);
        return 0;

    case WM_DESTROY:
        /* Wake the message loop WITHOUT posting WM_QUIT (which would
         * be picked up by FLS30's own message pump later). */
        PostThreadMessageW(GetCurrentThreadId(), WM_NULL, 0, 0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static int RunAdpPickWindow(pcap_if_t **devs, int count)
{
    WNDCLASSEXW wc = {0};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = AdpPickWndProc;
    wc.hInstance     = g_hDll;
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = ADPPICK_CLSNAME;
    wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
    RegisterClassExW(&wc); /* ignore error — may already be registered */

    AdpPickCtx ctx = { devs, count, -1, FALSE };
    HWND hwnd = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        ADPPICK_CLSNAME,
        L"FLS30 DAU — Select Network Adapter",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 320,
        NULL, NULL, g_hDll, &ctx);
    if (!hwnd) return -1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* Pump messages until the window signals done.
     * We never call PostQuitMessage so FLS30's pump is unaffected. */
    MSG m;
    while (!ctx.done) {
        if (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            /* If the app posted WM_QUIT before us, re-post and stop */
            if (m.message == WM_QUIT) {
                PostQuitMessage((int)m.wParam);
                break;
            }
            TranslateMessage(&m);
            DispatchMessageW(&m);
        } else {
            WaitMessage(); /* block until next message */
        }
    }
    return ctx.chosen;
}

static void ShowAdapterPicker(LPCWSTR iniPath)
{
    char errbuf[256] = {0};
    pcap_if_t *alldevs = NULL;
    if (g_pcapFindAllDevs(&alldevs, errbuf) != 0 || !alldevs) {
        Log(L"[PacketShim] pcap_findalldevs failed: %S\n", errbuf);
        return;
    }

    /* Build list, skipping Npcap's pseudo-loopback adapter */
    pcap_if_t *devPtrs[32];
    int count = 0;
    for (pcap_if_t *d = alldevs; d && count < 32; d = d->next) {
        if (d->name && strstr(d->name, "Loopback")) continue;
        devPtrs[count++] = d;
    }

    if (count == 0) {
        MessageBoxW(NULL,
            L"No Ethernet adapters found via Npcap.\r\n"
            L"Check that Npcap is installed and try again.",
            L"FLS30 DAU — No Adapters",
            MB_OK | MB_ICONWARNING | MB_TOPMOST);
        g_pcapFreeAllDevs(alldevs);
        return;
    }

    int chosen = RunAdpPickWindow(devPtrs, count);
    if (chosen < 0) {
        Log(L"[PacketShim] Adapter picker: cancelled\n");
        g_pcapFreeAllDevs(alldevs);
        return;
    }

    /* Extract "{GUID}" from the Npcap device name
     * "\Device\NPF_{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" */
    const char *brace = strchr(devPtrs[chosen]->name, '{');
    if (!brace) {
        Log(L"[PacketShim] Cannot extract GUID from name: %S\n",
            devPtrs[chosen]->name);
        g_pcapFreeAllDevs(alldevs);
        return;
    }
    WCHAR guidW[MAX_GUID_LEN] = {0};
    MultiByteToWideChar(CP_ACP, 0, brace, -1, guidW, MAX_GUID_LEN);
    /* Ensure it ends right after the closing brace */
    WCHAR *end = wcschr(guidW, L'}');
    if (end) *(end + 1) = L'\0';

    StringCchCopyW(g_NpcapGuid, MAX_GUID_LEN, guidW);
    WritePrivateProfileStringW(L"Npcap", L"AdapterGUID", guidW, iniPath);
    Log(L"[PacketShim] Adapter saved to INI: %s\n", guidW);

    g_pcapFreeAllDevs(alldevs);
}

/* ══════════════════════════════════════════════════════════════
 * FindNpcapAdapter — registry scan (no NtCreateFile)
 * ══════════════════════════════════════════════════════════════ */
static BOOL FindNpcapAdapter(void)
{
    static const WCHAR *paths[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\NPF\\Adapters",
        L"SYSTEM\\CurrentControlSet\\Services\\npcap\\Adapters",
        L"SOFTWARE\\Npcap\\Adapters",
    };
    for (int i = 0; i < 3; i++) {
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, paths[i], 0, KEY_READ, &hk) != ERROR_SUCCESS)
            continue;
        WCHAR name[MAX_GUID_LEN]; DWORD nlen = MAX_GUID_LEN; DWORD idx = 0;
        while (RegEnumKeyExW(hk, idx++, name, &nlen, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
            if (name[0] == L'{') {
                StringCchCopyW(g_NpcapGuid, MAX_GUID_LEN, name);
                RegCloseKey(hk);
                Log(L"[PacketShim] Auto-detected: %s\n", g_NpcapGuid);
                return TRUE;
            }
            nlen = MAX_GUID_LEN;
        }
        RegCloseKey(hk);
    }
    return FALSE;
}

/* ══════════════════════════════════════════════════════════════
 * FetchMac — GetAdaptersAddresses (always works; no IOCTL needed)
 * Loaded dynamically so IPHLPAPI.DLL is NOT in our static import table.
 * ══════════════════════════════════════════════════════════════ */
typedef ULONG (WINAPI *PfnGetAdaptersAddresses)(ULONG, ULONG, PVOID,
                                                PIP_ADAPTER_ADDRESSES, PULONG);
static void FetchMac(void)
{
    HMODULE hIPHlp = LoadLibraryA("iphlpapi.dll");
    if (!hIPHlp) return;
    PfnGetAdaptersAddresses pfnGAA =
        (PfnGetAdaptersAddresses)GetProcAddress(hIPHlp, "GetAdaptersAddresses");
    if (!pfnGAA) { FreeLibrary(hIPHlp); return; }

    ULONG bufLen = 16384;
    PIP_ADAPTER_ADDRESSES p0 = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!p0) { FreeLibrary(hIPHlp); return; }

    if (pfnGAA(AF_UNSPEC,
               GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
               GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
               NULL, p0, &bufLen) == ERROR_SUCCESS) {
        /* g_NpcapGuid is like {GUID}; AdapterName is like GUID (no braces) */
        LPCWSTR cmp = g_NpcapGuid;
        if (cmp[0] == L'{') cmp++;          /* skip leading brace   */
        for (PIP_ADAPTER_ADDRESSES p = p0; p; p = p->Next) {
            WCHAR guidW[MAX_GUID_LEN];
            MultiByteToWideChar(CP_ACP, 0, p->AdapterName, -1, guidW, MAX_GUID_LEN);
            if (_wcsicmp(guidW, cmp) == 0 || _wcsicmp(guidW, g_NpcapGuid) == 0) {
                if (p->PhysicalAddressLength >= 6)
                    CopyMemory(g_Mac, p->PhysicalAddress, 6);
                break;
            }
        }
    }
    free(p0);
    FreeLibrary(hIPHlp);
}

/* ══════════════════════════════════════════════════════════════
 * OpenPcapHandle
 * Opens the NIC via pcap_open_live and returns a fake HANDLE.
 * to_ms=1 → pcap_next_ex returns after 1 ms if no packet arrives.
 * ══════════════════════════════════════════════════════════════ */
static HANDLE OpenPcapHandle(DWORD acc, DWORD share, DWORD flags)
{
    UNREFERENCED_PARAMETER(share);
    UNREFERENCED_PARAMETER(flags);

    if (!g_pcapOpenLive) {
        Log(L"[PacketShim] pcap_open_live not available\n");
        SetLastError(ERROR_NOT_SUPPORTED);
        return INVALID_HANDLE_VALUE;
    }

    /* Build device name:  \Device\NPF_{GUID} */
    char devName[256], guidA[MAX_GUID_LEN];
    WideCharToMultiByte(CP_ACP, 0, g_NpcapGuid, -1, guidA, MAX_GUID_LEN, NULL, NULL);
    _snprintf_s(devName, sizeof(devName), _TRUNCATE, "\\Device\\NPF_%s", guidA);

    char errbuf[256] = {0};
    pcap_t *pcap = g_pcapOpenLive(devName, 65535, 1 /*promisc*/, 1 /*ms*/, errbuf);
    if (!pcap) {
        Log(L"[PacketShim] pcap_open_live(%S) failed: %S\n", devName, errbuf);
        SetLastError(ERROR_OPEN_FAILED);
        return INVALID_HANDLE_VALUE;
    }

    /* Apply BPF filter:
     *   - Only pass EtherType 0xAA55 frames
     *   - Exclude frames whose SOURCE MAC is our own NIC (Npcap loopback
     *     of our outbound TX frames — FLS30 must never see its own frames
     *     echoed back or its state machine confuses them for DAU replies).
     */
    if (g_pcapCompile && g_pcapSetFilter && g_pcapFreeCode) {
        char bpfStr[128];
        _snprintf_s(bpfStr, sizeof(bpfStr), _TRUNCATE,
            "ether proto 0xaa55 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
            g_Mac[0], g_Mac[1], g_Mac[2], g_Mac[3], g_Mac[4], g_Mac[5]);
        struct bpf_program fp = {0};
        if (g_pcapCompile(pcap, &fp, bpfStr, 1, 0) == 0) {
            g_pcapSetFilter(pcap, &fp);
            g_pcapFreeCode(&fp);
            Log(L"[PacketShim] BPF filter applied: %S\n", bpfStr);
        } else {
            Log(L"[PacketShim] WARNING: pcap_compile failed — no filter\n");
        }
    }

    EnterCriticalSection(&g_Lock);
    for (int i = 0; i < MAX_ADP; i++) {
        if (g_Adp[i].inUse) continue;
        ZeroMemory(&g_Adp[i], sizeof(AdpEntry));
        g_Adp[i].inUse        = TRUE;
        g_Adp[i].pcap         = pcap;
        g_Adp[i].windowMinSeq = INVALID_SEQ;
        g_Adp[i].windowMaxSeq = 0;
        g_Adp[i].irpHead      = 0;
        g_Adp[i].irpTail      = 0;
        InitializeCriticalSection(&g_Adp[i].irpLock);
        g_Adp[i].startEvt = CreateEventW(NULL, FALSE, FALSE, NULL);
        g_Adp[i].thread   = CreateThread(NULL, 0, RecvThread, &g_Adp[i], 0, NULL);
        LeaveCriticalSection(&g_Lock);
        HANDLE fh = (HANDLE)(FAKE_ADP_BASE + (ULONG_PTR)i);
        Log(L"[PacketShim] pcap_open_live OK → slot %d acc=0x%08X\n", i, acc);
        return fh;
    }
    LeaveCriticalSection(&g_Lock);
    g_pcapClose(pcap);
    SetLastError(ERROR_TOO_MANY_OPEN_FILES);
    return INVALID_HANDLE_VALUE;
}

/* ══════════════════════════════════════════════════════════════
 * LookupAdp — decode fake HANDLE to AdpEntry slot
 * ══════════════════════════════════════════════════════════════ */
static AdpEntry* LookupAdp(HANDLE h)
{
    ULONG_PTR v = (ULONG_PTR)h;
    if (v < FAKE_ADP_BASE || v >= FAKE_ADP_BASE + MAX_ADP) return NULL;
    int i = (int)(v - FAKE_ADP_BASE);
    return g_Adp[i].inUse ? &g_Adp[i] : NULL;
}

/* ══════════════════════════════════════════════════════════════
 * DeliverFrame — copy frame into one pending ReadFile IRP buffer
 * ══════════════════════════════════════════════════════════════ */
static void DeliverFrame(const RecvReq *req, const BYTE *frame, DWORD frameLen)
{
    DWORD copyLen = frameLen < req->bufSz ? frameLen : req->bufSz;
    CopyMemory(req->buf, frame, copyLen);
    if (req->ov) {
        req->ov->InternalHigh = copyLen;
        req->ov->Internal     = 0; /* STATUS_SUCCESS */
        if (req->ov->hEvent) SetEvent(req->ov->hEvent);
    }
}

/* ── Build a minimal synthetic Ethernet frame ─────────────────
 * dst[6], src[6], EtherType AA55, payload[payLen], zero-pad to 60
 * ─────────────────────────────────────────────────────────────── */
static void BuildSynthFrame(BYTE *out60, const BYTE *dst, const BYTE *src,
                             const BYTE *payload, DWORD payLen)
{
    ZeroMemory(out60, 60);
    CopyMemory(out60,      dst, 6);
    CopyMemory(out60 + 6,  src, 6);
    out60[12] = 0xAA; out60[13] = 0x55;
    if (payLen > 46) payLen = 46;
    CopyMemory(out60 + 14, payload, payLen);
}

/* ══════════════════════════════════════════════════════════════
 * RecvThread — background loop that drains pcap for async ReadFile
 * In TestMode: generates synthetic DAU frames instead of real pcap.
 * ══════════════════════════════════════════════════════════════ */
static DWORD WINAPI RecvThread(LPVOID param)
{
    AdpEntry *a = (AdpEntry*)param;
    Log(L"[PacketShim] RecvThread started (TestMode=%d)\n", g_TestMode);

    /* ── TEST MODE ────────────────────────────────────────────── */
    if (g_TestMode) {
        static const BYTE bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        DWORD lastData  = 0;   /* tick of last 0x03 0x03 frame sent    */
        DWORD lastPing  = 0;   /* tick of last 0x01 0x01 reply sent    */

        while (!a->stopThread) {
            DWORD now = GetTickCount();
            BOOL  wantData  = (now - lastData)  >= 100; /* 10 Hz data stream */
            BOOL  wantPing  = FALSE;

            /* Check if a 0x01 0x01 reply has been queued by WriteFile hook */
            BYTE replyFrame[60];
            EnterCriticalSection(&g_ReplyLock);
            if (g_ReplyReady) {
                CopyMemory(replyFrame, g_ReplyFrame, 60);
                g_ReplyReady = FALSE;
                wantPing = TRUE;
            }
            LeaveCriticalSection(&g_ReplyLock);

            if (!wantData && !wantPing) { Sleep(10); continue; }

            /* Wait up to 50 ms for FLS30 to post a ReadFile */
            if (WaitForSingleObject(a->startEvt, 50) != WAIT_OBJECT_0)
                continue;
            if (a->stopThread) continue;

            /* Pop one IRP from the queue */
            EnterCriticalSection(&a->irpLock);
            if (a->irpHead == a->irpTail) {
                LeaveCriticalSection(&a->irpLock);
                continue; /* spurious wake — no IRP ready */
            }
            RecvReq req    = a->irpQueue[a->irpTail];
            a->irpTail     = (a->irpTail + 1) % IRP_QUEUE_DEPTH;
            BOOL moreIrps  = (a->irpHead != a->irpTail);
            LeaveCriticalSection(&a->irpLock);
            if (moreIrps) SetEvent(a->startEvt); /* wake again for the next IRP */

            if (wantPing) {
                /* Priority: deliver 0x01 0x01 reply first */
                DeliverFrame(&req, replyFrame, 60);
                lastPing = now;
                Log(L"[PacketShim] TestMode → 0x01 0x01 reply delivered\n");
            } else {
                /* Synthetic 0x03 0x03 live-data frame */
                BYTE pay[46] = {0x03,0x03,0x00,0x00,0x00,0x00};
                BYTE synthFrame[60];
                BuildSynthFrame(synthFrame, bcast, k_FakeDauMac, pay, sizeof(pay));
                DeliverFrame(&req, synthFrame, 60);
                lastData = now;
                Log(L"[PacketShim] TestMode → 0x03 0x03 data frame delivered\n");
            }
        }
        Log(L"[PacketShim] RecvThread (TestMode) exiting\n");
        return 0;
    }

    /* ── NORMAL MODE (real pcap) ──────────────────────────────── */
    while (!a->stopThread) {
        /* Wait for Hook_ReadFile to post a pending IRP */
        if (WaitForSingleObject(a->startEvt, 200) != WAIT_OBJECT_0)
            continue;
        if (a->stopThread) break;

        /* Pop one IRP from the queue */
        EnterCriticalSection(&a->irpLock);
        if (a->irpHead == a->irpTail) {
            LeaveCriticalSection(&a->irpLock);
            continue; /* spurious wake */
        }
        RecvReq req   = a->irpQueue[a->irpTail];
        a->irpTail    = (a->irpTail + 1) % IRP_QUEUE_DEPTH;
        BOOL moreIrps = (a->irpHead != a->irpTail);
        LeaveCriticalSection(&a->irpLock);
        if (moreIrps) SetEvent(a->startEvt); /* re-signal for remaining IRPs */

        /* Drain pcap until one frame arrives or we are stopped */
        while (!a->stopThread) {
            struct pcap_pkthdr *hdr = NULL;
            const unsigned char *pkt = NULL;
            int r = g_pcapNextEx(a->pcap, &hdr, &pkt);
            if (r == 1) {
                /* Belt-and-braces: drop any frame whose source MAC == our own.
                 * Npcap promiscuous mode echoes our outbound TX frames back as
                 * received frames; the BPF filter blocks them, but guard here too. */
                if (hdr->caplen >= 12 &&
                    memcmp(pkt + 6, g_Mac, 6) == 0) {
                    /* silently skip — it's our own TX loopback */
                    continue;
                }

                /* Classify the frame for easier reading */
                LPCWSTR ftype = L"?";
                BYTE rxT0 = 0, rxT1 = 0;
                if (hdr->caplen >= 16) {
                    rxT0 = pkt[14]; rxT1 = pkt[15];
                    if      (rxT0==0x01 && rxT1==0x01) ftype = L"PING";
                    else if (rxT0==0x01 && rxT1==0x02) ftype = L"FILE-LIST";  /* DAU→FLS30: file list resp    */
                    else if (rxT0==0x01 && rxT1==0x05) ftype = L"FILE-SCAN";  /* DAU→FLS30: file meta resp    */
                    else if (rxT0==0x01 && rxT1==0x06) ftype = L"FILE-META";  /* DAU→FLS30: download meta     */
                    else if (rxT0==0x01 && rxT1==0x07) ftype = L"LIVE-CTRL";
                    else if (rxT0==0x01 && rxT1==0x0B) ftype = L"LIVE-CTRL2";
                    else if (rxT0==0x01 && rxT1==0x0C) ftype = L"DAU-POLL";   /* DAU→FLS30: next-win ready?   */
                    else if (rxT0==0x02 && rxT1==0x01) ftype = L"FILE-CHUNK"; /* DAU→FLS30: file data chunk   */
                    else if (rxT0==0x02 && rxT1==0x02) ftype = L"FILE-ACK";   /* DAU→FLS30: window boundary   */
                    else if (rxT0==0x02 && rxT1==0x03) ftype = L"FILE-DONE";  /* DAU→FLS30: transfer complete */
                    else if (rxT0==0x02 && rxT1==0x05) ftype = L"FILE-ERR";   /* DAU→FLS30: download error    */
                    else if (rxT0==0x03 && rxT1==0x03) ftype = L"LIVE-DATA";
                }

                /* ── Track window sequence range (for FILE-ACK patch) ─────
                 *
                 * FILE-CHUNK (02 01) frames carry a 32-bit LE sequence number
                 * at Ethernet frame bytes [16..19] (payload[2..5] after the
                 * 2-byte type field).
                 *
                 * Because each AdpEntry has exactly one RecvThread that drains
                 * frames sequentially, windowMinSeq/windowMaxSeq are only ever
                 * touched by this thread — no locking or atomics needed.
                 */
                if (rxT0==0x02 && rxT1==0x01 && hdr->caplen >= 20) {
                    DWORD seq = (DWORD)(pkt[16])         |
                                ((DWORD)(pkt[17]) << 8)  |
                                ((DWORD)(pkt[18]) << 16) |
                                ((DWORD)(pkt[19]) << 24);
                    if (a->windowMinSeq == INVALID_SEQ || seq < a->windowMinSeq)
                        a->windowMinSeq = seq;
                    if (seq > a->windowMaxSeq)
                        a->windowMaxSeq = seq;
                }

                /* ── Option-A fix: patch FILE-ACK window-count field ───────
                 *
                 * FLS30's case-0xe handler calls FUN_004379b8(obj, uStack_1ae)
                 * where uStack_1ae is read from the 02 02 frame at byte offset
                 * FILE_ACK_WINCOUNT_OFFSET (little-endian WORD).
                 *
                 * If the DAU's 02 02 is a minimum-padded 60-byte frame, that
                 * field is zero.  FUN_004379b8(x, 0) skips its bitmap loop and
                 * returns "complete", so FLS30 never sends NEXT-WIN → stall.
                 *
                 * Fix: compute ExpectedCount = (max_seq - min_seq + 1) from
                 * the observed chunk sequence numbers, which correctly handles
                 * mid-burst drops (a missing seq still shows as a gap in the
                 * bitmap).  Only a dropped last chunk is still under-counted,
                 * which is an inherent limitation without the DAU's count.
                 *
                 * Byte layout of the 02 02 frame (offsets from frame start):
                 *   [14..15] = 02 02 (type)
                 *   [16..17] = window seq number  (uStack_1b0, USHORT)
                 *   [18..19] = secondary field     (uStack_1b2, USHORT)
                 *   [20..21] = window chunk count  (uStack_1ae, USHORT) ← PATCH
                 *   [22..59] = zero padding
                 */
#define FILE_ACK_WINCOUNT_OFFSET  20   /* byte index in Ethernet frame */

                /* Delivery pointer — normally the raw pcap frame.
                 * For the FILE-ACK patch we switch to a local mutable copy. */
                BYTE        patchBuf[1518];
                const BYTE *deliverPkt = pkt;
                DWORD        deliverLen = hdr->caplen;

                if (rxT0==0x02 && rxT1==0x02) {
                    /* Snapshot and reset — no atomics needed (single thread) */
                    DWORD minSeq = a->windowMinSeq;
                    DWORD maxSeq = a->windowMaxSeq;
                    a->windowMinSeq = INVALID_SEQ;
                    a->windowMaxSeq = 0;

                    if (minSeq != INVALID_SEQ && maxSeq >= minSeq) {
                        DWORD expectedCount = (maxSeq - minSeq) + 1;
                        Log(L"[PacketShim] *** Window boundary: seq %lu..%lu → expected %lu chunks ***\n",
                            minSeq, maxSeq, expectedCount);

                        if (hdr->caplen >= FILE_ACK_WINCOUNT_OFFSET + 2) {
                            WORD existing =
                                (WORD)(pkt[FILE_ACK_WINCOUNT_OFFSET]) |
                                ((WORD)(pkt[FILE_ACK_WINCOUNT_OFFSET + 1]) << 8);

                            if (existing == 0) {
                                /* Overflow guard: only copy if the frame fits */
                                if (hdr->caplen > sizeof(patchBuf)) {
                                    Log(L"[PacketShim] FILE-ACK frame too large (%u bytes) for patchBuf, skipping patch\n",
                                        hdr->caplen);
                                } else {
                                    /* Zero-padded count field — patch with seq-derived count */
                                    WORD cnt = (expectedCount > 0xFFFF) ? 0xFFFF : (WORD)expectedCount;
                                    CopyMemory(patchBuf, pkt, hdr->caplen);
                                    patchBuf[FILE_ACK_WINCOUNT_OFFSET]     = (BYTE)(cnt & 0xFF);
                                    patchBuf[FILE_ACK_WINCOUNT_OFFSET + 1] = (BYTE)(cnt >> 8);
                                    deliverPkt = patchBuf;
                                    Log(L"[PacketShim] *** FILE-ACK PATCHED: offset[%d..%d] 0x0000 → 0x%04X (%lu chunks) ***\n",
                                        FILE_ACK_WINCOUNT_OFFSET, FILE_ACK_WINCOUNT_OFFSET + 1,
                                        (DWORD)cnt, expectedCount);
                                }
                            } else {
                                Log(L"[PacketShim] FILE-ACK offset[%d..%d] = 0x%04X (non-zero, not patched)\n",
                                    FILE_ACK_WINCOUNT_OFFSET, FILE_ACK_WINCOUNT_OFFSET + 1,
                                    (DWORD)existing);
                            }
                        }
                    } else {
                        Log(L"[PacketShim] FILE-ACK: no chunks this window (minSeq=INVALID), skipping patch\n");
                    }
                }

                /* ── Build hex dump (from deliverPkt so patched bytes show) ── */
                BOOL fullDump = (rxT0==0x02 && rxT1==0x02) ||  /* FILE-ACK  */
                                (rxT0==0x01 && rxT1==0x0C);    /* DAU-POLL  */
                DWORD logLen = fullDump ? deliverLen :
                               (deliverLen < 20 ? deliverLen : 20);
                /* 3 chars/byte + NUL; 60 bytes max → 181 chars */
                WCHAR hexBuf[200] = {0};
                WCHAR *wp = hexBuf;
                for (DWORD bi = 0; bi < logLen; bi++) {
                    StringCchPrintfW(wp, 6, L"%02X ", deliverPkt[bi]);
                    wp += 3;
                }

                if (req.bufSz > 0 && hdr->caplen > req.bufSz) {
                    Log(L"[PacketShim] RX %u bytes [%s] TRUNCATED to buf=%u  %s\n",
                        hdr->caplen, ftype, req.bufSz, hexBuf);
                } else {
                    Log(L"[PacketShim] RX %u bytes [%s] buf=%u  %s\n",
                        hdr->caplen, ftype, req.bufSz, hexBuf);
                }
                DeliverFrame(&req, deliverPkt, deliverLen);
                break;
            } else if (r == 0) {
                continue;   /* 1 ms timeout — retry */
            } else {
                Log(L"[PacketShim] RecvThread: pcap_next_ex error %d\n", r);
                /* pcap error — fail the pending IRP */
                if (req.ov) {
                    req.ov->InternalHigh = 0;
                    req.ov->Internal     = (ULONG_PTR)0xC0000001UL;
                    if (req.ov->hEvent) SetEvent(req.ov->hEvent);
                }
                break;
            }
        }
    }
    Log(L"[PacketShim] RecvThread exiting\n");
    return 0;
}

/* ══════════════════════════════════════════════════════════════
 * BuildEnumResponse
 * Format: [DWORD count] [WCHAR name\0] [WCHAR desc\0] [\0]
 *
 * FLS30's FUN_004731c8 builds the device path as:
 *   wsprintfW(buf, L"\\.\%s", desc_ptr + 0x18)
 * i.e. it skips the first 12 WCHARs (24 bytes) of the desc string.
 * We prefix the desc with "\Device\NPF_" (exactly 12 chars) so
 * that desc_ptr+12 = g_AdapterName → FLS30 opens "\\.\FLS30DAU"
 * which our IsAdapterDev hook intercepts.
 * ══════════════════════════════════════════════════════════════ */
static BOOL BuildEnumResponse(PVOID buf, ULONG len, PULONG written)
{
    /* Desc = "\Device\NPF_" (12 chars) + g_AdapterName */
    WCHAR descStr[256];
    StringCchPrintfW(descStr, 256, L"\\Device\\NPF_%s", g_AdapterName);

    ULONG nw     = (ULONG)(wcslen(g_AdapterName) + 1) * sizeof(WCHAR);
    ULONG dw     = (ULONG)(wcslen(descStr)      + 1) * sizeof(WCHAR);
    ULONG needed = sizeof(ULONG) + nw + dw + sizeof(WCHAR);
    *written = needed;
    if (len < needed) return FALSE;

    *((PULONG)buf) = 1;
    PWCHAR p = (PWCHAR)((PUCHAR)buf + sizeof(ULONG));
    StringCchCopyW(p, len / sizeof(WCHAR), g_AdapterName); p += wcslen(g_AdapterName) + 1;
    StringCchCopyW(p, len / sizeof(WCHAR), descStr);       p += wcslen(descStr)       + 1;
    *p = L'\0';
    return TRUE;
}

/* ── Path helpers ─────────────────────────────────────────────── */
static BOOL IsControlDev(LPCWSTR p)
{
    return p && (_wcsicmp(p, L"\\\\.\\Packet") == 0);
}
static BOOL IsAdapterDev(LPCWSTR p)
{
    if (!p) return FALSE;
    WCHAR exp[MAX_PATH];
    StringCchPrintfW(exp, MAX_PATH, L"\\\\.\\%s", g_AdapterName);
    return (_wcsicmp(p, exp) == 0);
}

/* ══════════════════════════════════════════════════════════════
 * IAT hook infrastructure
 * ══════════════════════════════════════════════════════════════ */
typedef HANDLE    (WINAPI *PfnCreateFileW)(LPCWSTR,DWORD,DWORD,LPSECURITY_ATTRIBUTES,DWORD,DWORD,HANDLE);
typedef BOOL      (WINAPI *PfnDeviceIoControl)(HANDLE,DWORD,LPVOID,DWORD,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL      (WINAPI *PfnCloseHandle)(HANDLE);
typedef BOOL      (WINAPI *PfnReadFile)(HANDLE,LPVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef BOOL      (WINAPI *PfnWriteFile)(HANDLE,LPCVOID,DWORD,LPDWORD,LPOVERLAPPED);
typedef SC_HANDLE (WINAPI *PfnOpenServiceW)(SC_HANDLE,LPCWSTR,DWORD);
typedef BOOL      (WINAPI *PfnStartServiceW)(SC_HANDLE,DWORD,LPCWSTR*);
typedef BOOL      (WINAPI *PfnQueryServiceStatus)(SC_HANDLE,LPSERVICE_STATUS);
typedef BOOL      (WINAPI *PfnCloseServiceHandle)(SC_HANDLE);
typedef BOOL      (WINAPI *PfnExitWindowsEx)(UINT,DWORD);

static PfnCreateFileW        g_OrigCFW   = NULL;
static PfnDeviceIoControl    g_OrigDIC   = NULL;
static PfnCloseHandle        g_OrigCH    = NULL;
static PfnReadFile           g_OrigRF    = NULL;
static PfnWriteFile          g_OrigWF    = NULL;
static PfnOpenServiceW       g_OrigOSW   = NULL;
static PfnStartServiceW      g_OrigSSW   = NULL;
static PfnQueryServiceStatus g_OrigQSS   = NULL;
static PfnExitWindowsEx      g_OrigEWE   = NULL;
static PfnCloseServiceHandle g_OrigCSH   = NULL;

/* ══════════════════════════════════════════════════════════════
 * Hook_CreateFileW
 * ══════════════════════════════════════════════════════════════ */
HANDLE WINAPI Hook_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSA, DWORD dwCD, DWORD dwFA, HANDLE hTmpl)
{
    if (!lpFileName) goto pt;

    if (IsControlDev(lpFileName)) {
        Log(L"[PacketShim] CreateFileW(\\Packet) → FAKE_CONTROL_HANDLE\n");
        return FAKE_CONTROL_HANDLE;
    }

    /* MAC-query fingerprint (FLS30.c FUN_00473262 line 50285):
     *   CreateFileW(<any>, 0, 1, NULL, 3, 0, (HANDLE)0xFFFFFFFF)
     * hTmpl == INVALID_HANDLE_VALUE with access==0 is unique to this call.
     * FLS30 opens desc_ptr+0x26 which may be any short string (e.g. "U")
     * rather than our adapter name, so we cannot rely on IsAdapterDev here. */
    if (dwDesiredAccess == 0 && hTmpl == (HANDLE)(ULONG_PTR)0xFFFFFFFFUL) {
        Log(L"[PacketShim] CreateFileW(%s acc=0 tmpl=-1) → FAKE_MAC_HANDLE\n", lpFileName);
        return FAKE_MAC_HANDLE;
    }

    if (IsAdapterDev(lpFileName)) {
        Log(L"[PacketShim] CreateFileW(%s acc=0x%08X) → pcap_open_live\n",
            lpFileName, dwDesiredAccess);
        return OpenPcapHandle(dwDesiredAccess, dwShareMode, dwFA);
    }

pt:
    return g_OrigCFW(lpFileName, dwDesiredAccess, dwShareMode, lpSA, dwCD, dwFA, hTmpl);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_DeviceIoControl
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_DeviceIoControl(
    HANDLE hDev, DWORD dwCode,
    LPVOID pIn, DWORD nIn, LPVOID pOut, DWORD nOut,
    LPDWORD pRet, LPOVERLAPPED pOv)
{
    /* Control device — only ENUM_ADAPTERS */
    if (hDev == FAKE_CONTROL_HANDLE) {
        if (dwCode == IOCTL_ENUM_ADAPTERS) {
            ULONG wr = 0;
            BOOL ok = BuildEnumResponse(pOut, nOut, &wr);
            if (pRet) *pRet = wr;
            if (!ok) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
            Log(L"[PacketShim] IOCTL_ENUM_ADAPTERS → %s\n", g_AdapterName);
            return TRUE;
        }
        Log(L"[PacketShim] unknown IOCTL 0x%08X on control device\n", dwCode);
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }

    /* IOCTL_GET_MAC on MAC-query handle (or any adapter handle) */
    if (dwCode == IOCTL_GET_MAC) {
        if (nOut < 6) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        CopyMemory(pOut, g_Mac, 6);
        if (pRet) *pRet = 6;
        Log(L"[PacketShim] IOCTL_GET_MAC → %02X:%02X:%02X:%02X:%02X:%02X\n",
            g_Mac[0], g_Mac[1], g_Mac[2], g_Mac[3], g_Mac[4], g_Mac[5]);
        return TRUE;
    }

    /* NDIS IOCTLs — FLS30 uses WriteFile for actual sends; treat as no-ops */
    if (dwCode == IOCTL_NDIS_SEND || dwCode == IOCTL_NDIS_SEND_LOOPBACK ||
        dwCode == IOCTL_NDIS_RESET) {
        if (pRet) *pRet = 0;
        return TRUE;
    }

    return g_OrigDIC(hDev, dwCode, pIn, nIn, pOut, nOut, pRet, pOv);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_CloseHandle
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_CloseHandle(HANDLE h)
{
    if (h == FAKE_CONTROL_HANDLE || h == FAKE_MAC_HANDLE) return TRUE;

    AdpEntry *a = LookupAdp(h);
    if (a) {
        a->stopThread = TRUE;
        /* pcap_breakloop forces pcap_next_ex to return immediately so
         * RecvThread exits cleanly without a timeout race. */
        if (a->pcap && g_pcapBreakloop) g_pcapBreakloop(a->pcap);
        if (a->startEvt) SetEvent(a->startEvt);
        if (a->thread) {
            if (WaitForSingleObject(a->thread, 5000) == WAIT_TIMEOUT)
                Log(L"[PacketShim] WARNING: RecvThread did not exit within 5s\n");
            CloseHandle(a->thread); a->thread = NULL;
        }
        if (a->startEvt) { CloseHandle(a->startEvt); a->startEvt = NULL; }
        if (a->pcap && g_pcapClose) { g_pcapClose(a->pcap); a->pcap = NULL; }
        DeleteCriticalSection(&a->irpLock);
        a->inUse = FALSE;
        Log(L"[PacketShim] CloseHandle(pcap adapter) closed cleanly\n");
        return TRUE;
    }

    return g_OrigCH(h);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_WriteFile — pcap_sendpacket for adapter handles
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_WriteFile(
    HANDLE hFile, LPCVOID lpBuf, DWORD nBytes,
    LPDWORD lpWritten, LPOVERLAPPED lpOv)
{
    AdpEntry *a = LookupAdp(hFile);
    if (a && a->pcap) {
        /* TestMode: intercept outbound 0x01 0x01 pings and queue a reply */
        if (g_TestMode && nBytes >= 16) {
            const BYTE *p = (const BYTE*)lpBuf;
            if (p[12]==0xAA && p[13]==0x55 && p[14]==0x01 && p[15]==0x01) {
                EnterCriticalSection(&g_ReplyLock);
                if (!g_ReplyReady) {
                    static const BYTE bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
                    BYTE pay[6] = {0x01,0x01,0x00,0x00,0x00,0x00};
                    BuildSynthFrame(g_ReplyFrame, bcast, k_FakeDauMac, pay, 6);
                    g_ReplyReady = TRUE;
                    Log(L"[PacketShim] TestMode: 0x01 0x01 ping intercepted → reply queued\n");
                }
                LeaveCriticalSection(&g_ReplyLock);
            }
        }

        /* Log outbound frame — full dump for NEXT-WIN (02 04) so we can
         * see what window range FLS30 is requesting; first 20 bytes for others */
        if (nBytes >= 16) {
            const BYTE *fp = (const BYTE*)lpBuf;
            BYTE t0=fp[14], t1=fp[15];
            LPCWSTR txtype = L"?";
            if      (t0==0x01&&t1==0x01) txtype=L"PING";
            else if (t0==0x01&&t1==0x02) txtype=L"FILE-LIST";  /* FLS30→DAU: list files             */
            else if (t0==0x01&&t1==0x05) txtype=L"FILE-SCAN";  /* FLS30→DAU: per-file meta request  */
            else if (t0==0x01&&t1==0x06) txtype=L"FILE-REQ";   /* FLS30→DAU: request file download  */
            else if (t0==0x01&&t1==0x07) txtype=L"LIVE-CTRL";
            else if (t0==0x01&&t1==0x0B) txtype=L"LIVE-CTRL2";
            else if (t0==0x02&&t1==0x04) txtype=L"NEXT-WIN";   /* FLS30→DAU: send next window       */
            else if (t0==0x02&&t1==0x05) txtype=L"ABORT";      /* FLS30→DAU: abort transfer         */
            else if (t0==0x03&&t1==0x03) txtype=L"LIVE-DATA";
            /* Full dump for NEXT-WIN and FILE-REQ; first 20 bytes otherwise */
            BOOL txFull = (t0==0x02&&t1==0x04) || (t0==0x01&&t1==0x06);
            DWORD tl = txFull ? nBytes : (nBytes < 20 ? nBytes : 20);
            /* 3 chars per byte + NUL; max 228 bytes → 685 chars; cap at 200 */
            if (tl > 64) tl = 64;
            WCHAR txHex[200] = {0}; WCHAR *wp2 = txHex;
            for (DWORD bi = 0; bi < tl; bi++) {
                StringCchPrintfW(wp2, 6, L"%02X ", fp[bi]);
                wp2 += 3;
            }
            Log(L"[PacketShim] TX %u bytes [%s]  %s\n", nBytes, txtype, txHex);
        }
        int r = g_pcapSendPkt(a->pcap, (const unsigned char*)lpBuf, (int)nBytes);
        if (r == 0) {
            if (lpWritten) *lpWritten = nBytes;
            if (lpOv) {
                lpOv->InternalHigh = nBytes;
                lpOv->Internal     = 0;
                if (lpOv->hEvent) SetEvent(lpOv->hEvent);
            }
            return TRUE;
        }
        const char *pcapErr = (g_pcapGeterr && a->pcap) ? g_pcapGeterr(a->pcap) : "?";
        Log(L"[PacketShim] pcap_sendpacket failed r=%d: %S\n", r, pcapErr);
        SetLastError(ERROR_WRITE_FAULT);
        return FALSE;
    }
    return g_OrigWF(hFile, lpBuf, nBytes, lpWritten, lpOv);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_ReadFile — async via RecvThread, or sync blocking loop
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_ReadFile(
    HANDLE hFile, LPVOID lpBuf, DWORD nBytes,
    LPDWORD lpRead, LPOVERLAPPED lpOv)
{
    AdpEntry *a = LookupAdp(hFile);
    if (a && a->pcap) {
        if (lpOv) {
            /* Async: push onto IRP queue then wake RecvThread */
            EnterCriticalSection(&a->irpLock);
            int nextHead = (a->irpHead + 1) % IRP_QUEUE_DEPTH;
            if (nextHead == a->irpTail) {
                /* Queue full — this should be extremely rare */
                LeaveCriticalSection(&a->irpLock);
                Log(L"[PacketShim] ReadFile: IRP queue full (depth=%d), rejecting\n",
                    IRP_QUEUE_DEPTH);
                SetLastError(ERROR_TOO_MANY_CMDS);
                return FALSE;
            }
            a->irpQueue[a->irpHead].buf   = lpBuf;
            a->irpQueue[a->irpHead].bufSz = nBytes;
            a->irpQueue[a->irpHead].ov    = lpOv;
            a->irpHead = nextHead;
            LeaveCriticalSection(&a->irpLock);
            lpOv->Internal     = (ULONG_PTR)0x103; /* STATUS_PENDING */
            lpOv->InternalHigh = 0;
            if (lpRead) *lpRead = 0;
            Log(L"[PacketShim] ReadFile queued: buf=%u bytes (head=%d)\n",
                nBytes, a->irpHead);
            SetEvent(a->startEvt);
            SetLastError(ERROR_IO_PENDING);
            return FALSE;
        }
        /* Synchronous: block until packet */
        while (TRUE) {
            struct pcap_pkthdr *hdr = NULL;
            const unsigned char *pkt = NULL;
            int r = g_pcapNextEx(a->pcap, &hdr, &pkt);
            if (r == 1) {
                DWORD cl = hdr->caplen < nBytes ? hdr->caplen : nBytes;
                CopyMemory(lpBuf, pkt, cl);
                if (lpRead) *lpRead = cl;
                return TRUE;
            }
            if (r != 0) { SetLastError(ERROR_READ_FAULT); return FALSE; }
        }
    }
    if (g_OrigRF)
        return g_OrigRF(hFile, lpBuf, nBytes, lpRead, lpOv);
    return ReadFile(hFile, lpBuf, nBytes, lpRead, lpOv);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_ExitWindowsEx — intercept FLS30's shutdown call
 * FLS30.c line 13537: ExitWindowsEx(5, 0)  (EWX_SHUTDOWN|EWX_FORCE)
 * Replace with ExitProcess(0) so the PC does not actually shut down.
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_ExitWindowsEx(UINT uFlags, DWORD dwReason)
{
    Log(L"[PacketShim] ExitWindowsEx(flags=0x%X) intercepted → ExitProcess(0)\n", uFlags);
    ExitProcess(0);
    return TRUE; /* never reached */
}


/* ══════════════════════════════════════════════════════════════
 * SCM hooks — fake the "Packet" service
 * ══════════════════════════════════════════════════════════════ */
SC_HANDLE WINAPI Hook_OpenServiceW(SC_HANDLE hSCM, LPCWSTR name, DWORD acc)
{
    if (name && _wcsicmp(name, L"Packet") == 0) {
        Log(L"[PacketShim] OpenServiceW(Packet) → fake\n");
        return FAKE_SERVICE_HANDLE;
    }
    return g_OrigOSW(hSCM, name, acc);
}

BOOL WINAPI Hook_StartServiceW(SC_HANDLE h, DWORD n, LPCWSTR *a)
{
    if (h == FAKE_SERVICE_HANDLE) {
        SetLastError(ERROR_SERVICE_ALREADY_RUNNING);
        return FALSE;
    }
    return g_OrigSSW(h, n, a);
}

BOOL WINAPI Hook_QueryServiceStatus(SC_HANDLE h, LPSERVICE_STATUS s)
{
    if (h == FAKE_SERVICE_HANDLE) {
        if (s) {
            s->dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
            s->dwCurrentState     = SERVICE_RUNNING;
            s->dwWin32ExitCode    = NO_ERROR;
            s->dwControlsAccepted = SERVICE_ACCEPT_STOP;
        }
        return TRUE;
    }
    return g_OrigQSS(h, s);
}

BOOL WINAPI Hook_CloseServiceHandle(SC_HANDLE h)
{
    if (h == FAKE_SERVICE_HANDLE) return TRUE;
    return g_OrigCSH(h);
}

/* ══════════════════════════════════════════════════════════════
 * PatchIAT — walk PE import table and swap one function pointer
 * ══════════════════════════════════════════════════════════════ */
#pragma warning(push)
#pragma warning(disable: 4152)
static BOOL PatchIAT(HMODULE hMod, LPCSTR modName,
                     LPCSTR funcName, PVOID newFn, PVOID *oldFn)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR imp =
        (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hMod +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    for (; imp->Name; imp++) {
        if (_stricmp((LPCSTR)((BYTE*)hMod + imp->Name), modName) != 0) continue;
        PIMAGE_THUNK_DATA orig  = (PIMAGE_THUNK_DATA)((BYTE*)hMod + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hMod + imp->FirstThunk);
        for (; orig->u1.AddressOfData; orig++, thunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
            PIMAGE_IMPORT_BY_NAME ibn =
                (PIMAGE_IMPORT_BY_NAME)((BYTE*)hMod + orig->u1.AddressOfData);
            if (_stricmp((char*)ibn->Name, funcName) != 0) continue;
            DWORD old;
            VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &old);
            if (oldFn) *oldFn = (PVOID)thunk->u1.Function;
            thunk->u1.Function = (ULONG_PTR)newFn;
            VirtualProtect(&thunk->u1.Function, sizeof(PVOID), old, &old);
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL InstallHooks(void)
{
    HMODULE hExe = GetModuleHandleW(NULL);
    BOOL ok = TRUE;

    ok &= PatchIAT(hExe, "kernel32.dll", "CreateFileW",
                   Hook_CreateFileW, (PVOID*)&g_OrigCFW);
    ok &= PatchIAT(hExe, "kernel32.dll", "DeviceIoControl",
                   Hook_DeviceIoControl, (PVOID*)&g_OrigDIC);
    ok &= PatchIAT(hExe, "kernel32.dll", "CloseHandle",
                   Hook_CloseHandle, (PVOID*)&g_OrigCH);
    if (!PatchIAT(hExe, "kernel32.dll", "ReadFile",
                  Hook_ReadFile, (PVOID*)&g_OrigRF))
        Log(L"[PacketShim] ReadFile not in IAT (OK for test harness)\n");
    ok &= PatchIAT(hExe, "kernel32.dll", "WriteFile",
                   Hook_WriteFile, (PVOID*)&g_OrigWF);
    ok &= PatchIAT(hExe, "advapi32.dll", "OpenServiceW",
                   Hook_OpenServiceW, (PVOID*)&g_OrigOSW);
    ok &= PatchIAT(hExe, "advapi32.dll", "StartServiceW",
                   Hook_StartServiceW, (PVOID*)&g_OrigSSW);
    ok &= PatchIAT(hExe, "advapi32.dll", "QueryServiceStatus",
                   Hook_QueryServiceStatus, (PVOID*)&g_OrigQSS);
    ok &= PatchIAT(hExe, "advapi32.dll", "CloseServiceHandle",
                   Hook_CloseServiceHandle, (PVOID*)&g_OrigCSH);
    /* Intercept shutdown (user32.dll) */
    if (!PatchIAT(hExe, "user32.dll", "ExitWindowsEx",
                  Hook_ExitWindowsEx, (PVOID*)&g_OrigEWE)) {
        Log(L"[PacketShim] ExitWindowsEx not in IAT\n");
    }

    Log(ok ? L"[PacketShim] hooks installed\n" : L"[PacketShim] WARNING: some hooks failed\n");
    return ok;
}
#pragma warning(pop)

/* ══════════════════════════════════════════════════════════════
 * PacketShimInit — exported entry point called by fls30_loader
 * ══════════════════════════════════════════════════════════════ */
__declspec(dllexport) BOOL WINAPI PacketShimInit(void)
{
    if (!g_Initialised && !ShimInit()) return FALSE;
    return InstallHooks();
}

