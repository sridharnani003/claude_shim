/*
 * packet_shim.c  —  Npcap compatibility shim for DAULink.exe
 * ===========================================================
 * DAULink.exe is a legacy 32-bit ground station application that
 * talks to a physical DAU over raw Ethernet (EtherType 0xAA55).
 * On Windows 7 it did this through a custom kernel-mode protocol
 * driver that is no longer supported on Windows 11.
 *
 * This DLL injects into DAULink.exe's process (via AppInit_DLLs
 * or a launcher script) and patches its import address table so
 * that every Win32 call aimed at the old driver is silently
 * redirected here.  The shim then implements the full DAU protocol
 * in user-space using Npcap's wpcap.dll.  DAULink.exe never knows
 * anything changed — it still calls CreateFileW, ReadFile,
 * WriteFile, DeviceIoControl as usual.
 *
 * Must be built as x86 (32-bit) to match DAULink.exe's process.
 * See build_dll.bat for the exact compiler invocation.
 *
 * Configuration is in fls30_shim.ini next to DAULink.exe.
 * See Documentation/CONTRIBUTING.md for the full dev setup guide.
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
#include <aclapi.h>    /* EXPLICIT_ACCESSW, SetEntriesInAclW — needed for VULN-06 DACL */
/* iphlpapi.h included for types only — GetAdaptersAddresses loaded dynamically
 * to avoid IPHLPAPI.DLL appearing in our static import table (it causes a
 * ~10-second DllMain stall when injected via remote thread). */
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
typedef int  (*PfnPcapSetMinToCopy)(pcap_t*, int); /* min bytes before waking read */

static HMODULE           g_hWpcap            = NULL;
static PfnPcapOpenLive   g_pcapOpenLive      = NULL;
static PfnPcapSendPacket g_pcapSendPkt       = NULL;
static PfnPcapNextEx     g_pcapNextEx        = NULL;
static PfnPcapClose      g_pcapClose         = NULL;
static PfnPcapGeterr     g_pcapGeterr        = NULL;
static PfnPcapCompile    g_pcapCompile       = NULL;
static PfnPcapSetFilter  g_pcapSetFilter     = NULL;
static PfnPcapFreeCode   g_pcapFreeCode      = NULL;
static PfnPcapFindAllDevs g_pcapFindAllDevs  = NULL;
static PfnPcapFreeAllDevs g_pcapFreeAllDevs  = NULL;
static PfnPcapBreakloop   g_pcapBreakloop    = NULL;
static PfnPcapSetMinToCopy g_pcapSetMinToCopy = NULL;

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
 * DAULink pipelines multiple overlapped ReadFile calls under sustained
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
     * irpLock guards irpHead/irpTail between the application's calling thread
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

    /* Retransmit tracking (RetxWait)
     * When the application sends RETRANSMIT NEXT-WIN (missing > 0), the DAU
     * will resend chunks for that window.  We hold any FILE-ACK for a future
     * window until the confirming FILE-ACK for the retransmit window arrives —
     * delivering an out-of-order FILE-ACK would confuse the application's
     * state machine and cause a stall or ABORT.
     *
     * retxPending/retxWindow written by Hook_WriteFile, read by RecvThread.
     * On x86/x64 strong-ordering: write retxWindow before retxPending=TRUE. */
    volatile LONG retxPending;  /* 1 after RETRANSMIT NEXT-WIN TX, 0 after DAU confirms */
    volatile WORD retxWindow;   /* window number whose retransmit is in flight          */

    /* Deferred frame buffer.
     * Holds a FILE-ACK for window W+N while we are still waiting for the
     * confirming FILE-ACK for window W.  1514 bytes = max Ethernet frame.
     * Delivered by the outer IRP loop once retxPending is cleared. */
    BOOL  deferredPending;
    BYTE  deferredFrame[1514];
    DWORD deferredFrameLen;

    /* Live-view NEXT-WIN auto-forwarding.
     * The DAU sends live telemetry in bursts then waits for NEXT-WIN.
     * The application's internal timer can take 1–7 s to send it.
     * RecvThread waits LIVE_NEXTWIN_TIMEOUT_MS then sends it automatically. */
    volatile BOOL liveDataPendingNextWin;
    BYTE          dauMac[6];   /* DAU source MAC learned from first RX frame */
} AdpEntry;

static AdpEntry g_Adp[MAX_ADP];

/* ── Global state ─────────────────────────────────────────────── */
static WCHAR g_NpcapGuid[MAX_GUID_LEN]    = {0};
static WCHAR g_AdapterName[128]           = L"DAULink";
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

/* ── Log-file state ───────────────────────────────────────────────
 * All log output goes to a timestamped file in C:\FLS_DOWNLOAD\
 * using synchronous WriteFile (fast: write-back cache, no kernel
 * mutex unlike OutputDebugStringW).
 * High-frequency per-chunk events (FILE-CHUNK, ReadFile queued)
 * are suppressed to keep the file small and eliminate DebugView
 * overhead that was causing disk-thread backup in the application.
 * Control-plane events (FILE-ACK, NEXT-WIN, retransmit, errors)
 * are written to both the file and OutputDebugStringW so that
 * DebugView still works for real-time monitoring.
 */
static HANDLE          g_LogFile          = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_LogCS;
static LARGE_INTEGER   g_LogStartQPC      = {{0,0}};
static LARGE_INTEGER   g_LogQPCFreq       = {{0,0}};
/* Master logging switch — set from INI [Debug] Logging=0/1 (default 1).
 * When FALSE both Log() and LogFile() return immediately, the log file
 * is closed after the "logging disabled" banner, and OutputDebugStringW
 * is never called.  Zero performance impact during transfers. */
static BOOL            g_LogEnabled       = TRUE;


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

/* Open a timestamped log file in C:\FLS_DOWNLOAD\.
 * Called from DllMain before ShimInit so all startup messages land
 * in the file.  Falls back silently if the directory cannot be
 * created (g_LogFile stays INVALID_HANDLE_VALUE → file path skipped). */
static void LogInit(void)
{
    InitializeCriticalSection(&g_LogCS);
    QueryPerformanceFrequency(&g_LogQPCFreq);
    QueryPerformanceCounter(&g_LogStartQPC);

    /* Create the log directory if it doesn't exist yet.
     * VULN-06: default DACL on C:\ makes the directory world-writable, exposing
     * MAC addresses, GUIDs, and frame hex dumps to any local user, and allowing
     * symlink/file-squatting attacks on the log file.
     * Restrict access to the current user (CREATOR OWNER) and Administrators only. */
    LPCWSTR logDir = L"C:\\FLS_DOWNLOAD";

    SECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, FALSE };
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    /* Explicit DACL: Administrators = Full Control, current user = Full Control,
     * everyone else = no access.  NULL DACL would be world-writable (wrong). */
    if (SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE)) {
        /* Build a restrictive DACL — Administrators (S-1-5-32-544) full control */
        EXPLICIT_ACCESSW ea[2]      = {0};
        PSID pAdminSid              = NULL;
        SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
        if (AllocateAndInitializeSid(&ntAuth, 2,
                SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                0,0,0,0,0,0, &pAdminSid)) {
            ea[0].grfAccessPermissions = GENERIC_ALL;
            ea[0].grfAccessMode        = SET_ACCESS;
            ea[0].grfInheritance       = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[0].Trustee.TrusteeForm  = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType  = TRUSTEE_IS_GROUP;
            ea[0].Trustee.ptstrName    = (LPWSTR)pAdminSid;

            PACL pAcl = NULL;
            if (SetEntriesInAclW(1, ea, NULL, &pAcl) == ERROR_SUCCESS) {
                SetSecurityDescriptorDacl(&sd, TRUE, pAcl, FALSE);
                sa.lpSecurityDescriptor = &sd;
            }
            FreeSid(pAdminSid);
        }
    }
    CreateDirectoryW(logDir, &sa); /* silently ignores ERROR_ALREADY_EXISTS */

    SYSTEMTIME st;
    GetLocalTime(&st);
    WCHAR logPath[MAX_PATH];
    StringCchPrintfW(logPath, MAX_PATH,
        L"%s\\shim_%04u%02u%02u-%02u%02u%02u.log",
        logDir,
        (DWORD)st.wYear, (DWORD)st.wMonth, (DWORD)st.wDay,
        (DWORD)st.wHour, (DWORD)st.wMinute, (DWORD)st.wSecond);

    g_LogFile = CreateFileW(logPath,
        GENERIC_WRITE, FILE_SHARE_READ,
        NULL, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        NULL);
    /* If creation fails just continue — OutputDebugStringW still works */
}

static void LogClose(void)
{
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_LogFile);
        g_LogFile = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&g_LogCS);
}

/* Write a formatted, timestamped line to the log file only.
 * Never calls OutputDebugStringW — zero DebugView overhead.
 * Used for per-window routine events (FILE-ACK, window boundary,
 * TX NEXT-WIN, RX hex dumps) that are useful for post-analysis
 * but do not need real-time visibility. */
static void LogFile(LPCWSTR fmt, ...)
{
    if (!g_LogEnabled) return;
    if (g_LogFile == INVALID_HANDLE_VALUE) return;

    /* 1024 WCHARs: accommodates GUIDs, hex dumps, and adapter names without
     * silent truncation that could hide security-relevant log entries (VULN-15). */
    WCHAR msg[1024];
    va_list a;
    va_start(a, fmt);
    StringCchVPrintfW(msg, 1024, fmt, a);
    va_end(a);

    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    double secs = (g_LogQPCFreq.QuadPart > 0)
        ? (double)(now.QuadPart - g_LogStartQPC.QuadPart)
          / (double)g_LogQPCFreq.QuadPart
        : 0.0;

    WCHAR line[1100]; /* msg(1024) + timestamp prefix(13) + margin */
    StringCchPrintfW(line, 1100, L"[%10.6f] %s", secs, msg);

    /* 1100 WCHARs × 4 bytes worst-case UTF-8 = 4400 bytes. */
    char utf8[4400];
    int n = WideCharToMultiByte(CP_UTF8, 0, line, -1,
                                utf8, (int)sizeof(utf8) - 1,
                                NULL, NULL);
    if (n > 1) {
        DWORD written;
        EnterCriticalSection(&g_LogCS);
        WriteFile(g_LogFile, utf8, (DWORD)(n - 1), &written, NULL);
        LeaveCriticalSection(&g_LogCS);
    }
}

/* Write to BOTH the log file and OutputDebugStringW.
 * Reserved for rare/important events: startup, errors, retransmit
 * detection, ABORT.  These fire at most a few hundred times per
 * session so the DBWinMutex overhead is negligible. */
static void Log(LPCWSTR fmt, ...)
{
    if (!g_LogEnabled) return;
    /* 1024 WCHARs: accommodates GUIDs, hex dumps, and adapter names without
     * silent truncation that could hide security-relevant log entries (VULN-15). */
    WCHAR msg[1024];
    va_list a;
    va_start(a, fmt);
    StringCchVPrintfW(msg, 1024, fmt, a);
    va_end(a);

    /* Real-time visibility in DebugView / WinDbg */
    OutputDebugStringW(msg);

    /* Also record in the file with timestamp */
    if (g_LogFile != INVALID_HANDLE_VALUE) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double secs = (g_LogQPCFreq.QuadPart > 0)
            ? (double)(now.QuadPart - g_LogStartQPC.QuadPart)
              / (double)g_LogQPCFreq.QuadPart
            : 0.0;

        WCHAR line[600];
        StringCchPrintfW(line, 600, L"[%10.6f] %s", secs, msg);

        char utf8[2400]; /* 600 WCHARs × 4 bytes worst-case UTF-8 */
        int n = WideCharToMultiByte(CP_UTF8, 0, line, -1,
                                    utf8, (int)sizeof(utf8) - 1,
                                    NULL, NULL);
        if (n > 1) {
            DWORD written;
            EnterCriticalSection(&g_LogCS);
            WriteFile(g_LogFile, utf8, (DWORD)(n - 1), &written, NULL);
            LeaveCriticalSection(&g_LogCS);
        }
    }
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
        LogInit(); /* open log file first so ShimInit messages land in it */
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
        LogClose(); /* flush and close log file last */
    }
    return TRUE;
}

/* ══════════════════════════════════════════════════════════════
 * ShimInit
 * ─────────────────────────────────────────────────────────────
 * Called once from DllMain when the DLL attaches to the process.
 * Does two things:
 *   1. Loads wpcap.dll and resolves all the pcap function pointers
 *      we need.  If wpcap.dll is not found, the shim still loads
 *      but will not be able to do any network I/O.
 *   2. Reads fls30_shim.ini to pick up the adapter name/GUID,
 *      TestMode flag, and the Logging on/off switch.
 *
 * After this returns, InstallHooks() patches the IAT and the shim
 * is fully active.  Any failure here is non-fatal — the shim
 * logs a warning and continues, which is better than crashing
 * DAULink.exe on startup.
 * ══════════════════════════════════════════════════════════════ */
static BOOL ShimInit(void)
{
    /* Load wpcap.dll — Npcap installs 32-bit copy in SysWOW64\Npcap
     * and adds its directory to PATH, so the short name usually works. */
    /* VULN-04: bare "wpcap.dll" triggers Windows DLL search order — an attacker
     * who can write to the application directory could drop a malicious wpcap.dll
     * there.  Disable the current-directory and PATH search by setting the safe
     * DLL search mode, then try the known Npcap install path first. */
    SetDllDirectoryW(L"");   /* disables current-dir from search path for this call */
    g_hWpcap = LoadLibraryW(L"C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll");
    if (!g_hWpcap)
        g_hWpcap = LoadLibraryW(L"wpcap.dll");  /* fallback: PATH only, no cwd */
    SetDllDirectoryW(NULL);  /* restore default search behaviour */
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
        g_pcapBreakloop   = (PfnPcapBreakloop)   GetProcAddress(g_hWpcap, "pcap_breakloop");
        g_pcapSetMinToCopy= (PfnPcapSetMinToCopy)GetProcAddress(g_hWpcap, "pcap_setmintocopy");
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

    GetPrivateProfileStringW(L"Adapter", L"FriendlyName", L"DAULink",
                             g_AdapterName, 128, iniPath);
    g_TestMode = (GetPrivateProfileIntW(L"Debug", L"TestMode", 0, iniPath) != 0);
    if (g_TestMode) Log(L"[PacketShim] *** TEST MODE ENABLED — synthetic DAU frames ***\n");

    /* Logging master switch: [Debug] Logging=1 (default on).
     * Set to 0 in the INI to suppress all output — no file writes,
     * no OutputDebugStringW, zero overhead during transfers. */
    BOOL loggingOn = (GetPrivateProfileIntW(L"Debug", L"Logging", 1, iniPath) != 0);
    if (!loggingOn) {
        /* Write one final banner while logging is still enabled, then
         * flip the switch and close the file — zero overhead from here on. */
        Log(L"[PacketShim] Logging DISABLED via INI — no further output.\n");
        g_LogEnabled = FALSE;
        LogClose(); /* close file; g_LogFile → INVALID_HANDLE_VALUE */
    } else {
        Log(L"[PacketShim] Logging ENABLED\n");
    }
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
 * never post WM_QUIT into the application's thread message queue.
 * ══════════════════════════════════════════════════════════════ */
#define ADPPICK_LB      2001
#define ADPPICK_OK      2002
#define ADPPICK_CANCEL  2003
#define ADPPICK_CLSNAME L"PacketShimAdpPick"

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
            L"PacketShim — first-run adapter setup\r\n"
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
            /* VULN-16: CP_ACP is locale-dependent — use CP_UTF8 since Npcap
             * adapter descriptions are UTF-8 internally. Fallback to CP_ACP
             * if UTF-8 decode fails (older Npcap builds). */
            if (d->description && d->description[0]) {
                if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, d->description, -1, line, 300))
                    MultiByteToWideChar(CP_ACP, 0, d->description, -1, line, 300);
            } else {
                if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, d->name, -1, line, 300))
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
         * be picked up by the application's own message pump later). */
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
        L"PacketShim — Select Network Adapter",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 500, 320,
        NULL, NULL, g_hDll, &ctx);
    if (!hwnd) return -1;

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    /* Pump messages until the window signals done.
     * We never call PostQuitMessage so the application's pump is unaffected. */
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
            L"PacketShim — No Adapters Found",
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
    /* VULN-08: validate that the GUID portion fits in MAX_GUID_LEN before
     * converting — a malformed adapter name with a very long '{...' section
     * would be silently truncated, potentially yielding a broken GUID. */
    const char *closeBrace = strchr(brace, '}');
    if (!closeBrace || (closeBrace - brace + 2) > MAX_GUID_LEN) {
        Log(L"[PacketShim] GUID too long or malformed in: %S\n",
            devPtrs[chosen]->name);
        g_pcapFreeAllDevs(alldevs);
        return;
    }
    WCHAR guidW[MAX_GUID_LEN] = {0};
    MultiByteToWideChar(CP_UTF8, 0, brace, -1, guidW, MAX_GUID_LEN);
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
    /* VULN-09: bare name triggers DLL search order — use full system path. */
    HMODULE hIPHlp = LoadLibraryW(L"C:\\Windows\\System32\\iphlpapi.dll");
    if (!hIPHlp) hIPHlp = LoadLibraryA("iphlpapi.dll"); /* WoW64 fallback */
    if (!hIPHlp) return;
    PfnGetAdaptersAddresses pfnGAA =
        (PfnGetAdaptersAddresses)GetProcAddress(hIPHlp, "GetAdaptersAddresses");
    if (!pfnGAA) { FreeLibrary(hIPHlp); return; }

    ULONG bufLen = 16384;
    PIP_ADAPTER_ADDRESSES p0 = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
    if (!p0) { FreeLibrary(hIPHlp); return; }

    /* First call may return ERROR_BUFFER_OVERFLOW and update bufLen with the
     * exact size needed (common on machines with many virtual adapters).
     * Retry once with the corrected size so g_Mac is always populated. */
    ULONG flags = GAA_FLAG_SKIP_UNICAST | GAA_FLAG_SKIP_ANYCAST |
                  GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG result = pfnGAA(AF_UNSPEC, flags, NULL, p0, &bufLen);
    if (result == ERROR_BUFFER_OVERFLOW) {
        free(p0);
        p0 = (PIP_ADAPTER_ADDRESSES)malloc(bufLen);
        if (!p0) { FreeLibrary(hIPHlp); return; }
        result = pfnGAA(AF_UNSPEC, flags, NULL, p0, &bufLen);
    }

    if (result == ERROR_SUCCESS) {
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
     *     of our outbound TX frames — the application must never see its own frames
     *     echoed back or its state machine confuses them for DAU replies).
     */
    if (g_pcapCompile && g_pcapSetFilter && g_pcapFreeCode) {
        char bpfStr[128];
        _snprintf_s(bpfStr, sizeof(bpfStr), _TRUNCATE,
            "ether proto 0xaa55 and not ether src %02x:%02x:%02x:%02x:%02x:%02x",
            g_Mac[0], g_Mac[1], g_Mac[2], g_Mac[3], g_Mac[4], g_Mac[5]);
        struct bpf_program fp = {0};
        if (g_pcapCompile(pcap, &fp, bpfStr, 1, 0) == 0) {
            if (g_pcapSetFilter(pcap, &fp) != 0) {
                /* VULN-22: filter install failed — abort rather than run unfiltered.
                 * Without the EtherType filter the shim would deliver every frame on
                 * the wire to DAULink.exe, which could cause it to process foreign
                 * traffic as DAU protocol frames and corrupt its state machine. */
                Log(L"[PacketShim] ERROR: pcap_setfilter failed — aborting open to avoid unfiltered capture\n");
                g_pcapFreeCode(&fp);
                g_pcapClose(pcap);
                SetLastError(ERROR_OPEN_FAILED);
                return INVALID_HANDLE_VALUE;
            }
            g_pcapFreeCode(&fp);
            Log(L"[PacketShim] BPF filter applied: %S\n", bpfStr);
        } else {
            /* VULN-22: compile failure also aborts — same reasoning. */
            Log(L"[PacketShim] ERROR: pcap_compile failed — aborting open to avoid unfiltered capture\n");
            g_pcapClose(pcap);
            SetLastError(ERROR_OPEN_FAILED);
            return INVALID_HANDLE_VALUE;
        }
    }

    /* Force Npcap to deliver every packet immediately.
     * Default min-copy is ~16 KB, meaning the kernel may hold frames
     * until the buffer fills before waking pcap_next_ex.  Setting it to
     * 1 byte delivers each frame the moment it arrives, cutting per-frame
     * latency from tens of milliseconds down to near zero. */
    if (g_pcapSetMinToCopy) {
        int mc = g_pcapSetMinToCopy(pcap, 1);
        Log(L"[PacketShim] pcap_setmintocopy(1) = %d\n", mc);
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
        if (!g_Adp[i].thread) {
            /* Thread creation failed — clean up and report error rather than
             * returning a handle that would silently never deliver any frames. */
            DWORD err = GetLastError();
            Log(L"[PacketShim] ERROR: CreateThread failed (%u) — slot %d not usable\n",
                err, i);
            CloseHandle(g_Adp[i].startEvt);
            DeleteCriticalSection(&g_Adp[i].irpLock);
            ZeroMemory(&g_Adp[i], sizeof(AdpEntry));
            LeaveCriticalSection(&g_Lock);
            g_pcapClose(pcap);
            SetLastError(ERROR_MAX_THRDS_REACHED);
            return INVALID_HANDLE_VALUE;
        }
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

/* ── Live-view NEXT-WIN auto-forwarding ───────────────────────────────────
 * When the DAU sends a burst of LIVE-DATA (03 03) frames it waits for a
 * NEXT-WIN before sending the next burst.  DAULink.exe has a Delphi timer
 * that fires that NEXT-WIN, but it can take 1–7 seconds depending on load.
 * The shim auto-sends NEXT-WIN on DAULink.exe's behalf if it hasn't seen
 * one within LIVE_NEXTWIN_TIMEOUT_MS.  This keeps live telemetry flowing
 * at roughly 1.6 Hz instead of once every few seconds.
 *
 * If DAULink.exe does send its own NEXT-WIN before the timer fires, we
 * cancel the auto-send flag in Hook_WriteFile so we don't double-send. */
#define LIVE_NEXTWIN_TIMEOUT_MS  50

static void SendLiveNextWin(AdpEntry *a)
{
    /* Build the same NEXT-WIN frame the application would send:
     * dst=DAU MAC, src=our MAC, EtherType=0xAA55, type=02 04, rest=zeros
     * (zeros in the missing-count field means COMPLETE, not retransmit). */
    BYTE frame[60];
    ZeroMemory(frame, sizeof(frame));
    CopyMemory(frame + 0, a->dauMac,  6);   /* dst = DAU */
    CopyMemory(frame + 6, g_Mac,      6);   /* src = us  */
    frame[12] = 0xAA; frame[13] = 0x55;    /* EtherType  */
    frame[14] = 0x02; frame[15] = 0x04;    /* NEXT-WIN   */
    /* bytes [16..59] already zero = window 0, missingCnt 0 (COMPLETE) */
    if (g_pcapSendPkt && a->pcap) {
        int r = g_pcapSendPkt(a->pcap, frame, sizeof(frame));
        LogFile(L"[PacketShim] LiveView: auto-sent NEXT-WIN to DAU (r=%d)\n", r);
    }
}

/* ══════════════════════════════════════════════════════════════
 * RecvThread
 * ─────────────────────────────────────────────────────────────
 * One instance of this thread runs per open adapter handle.  Its
 * job is to sit in a pcap_next_ex loop, pick up incoming frames,
 * apply the protocol state machine, and hand matching frames to
 * whatever ReadFile request DAULink.exe has queued up.
 *
 * The outer loop services IRP requests one at a time:
 *   1. Wait for DAULink.exe to post a ReadFile (startEvt).
 *   2. If there is a deferred FILE-ACK from a previous retransmit
 *      cycle, deliver that first before touching pcap.
 *   3. Otherwise, drain pcap_next_ex until a frame arrives.
 *   4. Apply retransmit state (RetxWait) and LiveView NEXT-WIN logic.
 *   5. Copy the frame into the caller's buffer and signal hEvent.
 *   6. Go back to step 1.
 *
 * When TestMode is active the pcap path is replaced entirely by a
 * small synthetic frame generator so you can drive DAULink.exe's
 * state machine without any physical hardware connected.
 *
 * Thread safety: each AdpEntry has exactly one RecvThread.  Fields
 * that are only read/written by this thread (windowMinSeq, windowMaxSeq,
 * deferredPending, etc.) need no locking.  retxPending is a volatile
 * LONG that can be written by Hook_WriteFile on another thread, so
 * reads of it use the hardware memory model (x86 strong ordering).
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

            /* Wait up to 50 ms for the application to post a ReadFile */
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
            /* VULN-14 (TestMode path): SetEvent inside the lock — same race fix
             * as the normal-mode path below. */
            if (moreIrps) SetEvent(a->startEvt); /* wake again for the next IRP */
            LeaveCriticalSection(&a->irpLock);

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
        /* Wait for Hook_ReadFile to post a pending IRP.
         * If a LIVE-DATA burst just ended (liveDataPendingNextWin), use a
         * short timeout so the shim can auto-send NEXT-WIN if the application is slow. */
        DWORD waitMs = a->liveDataPendingNextWin
                       ? LIVE_NEXTWIN_TIMEOUT_MS
                       : 200;
        DWORD wr = WaitForSingleObject(a->startEvt, waitMs);
        if (wr == WAIT_TIMEOUT) {
            if (a->liveDataPendingNextWin) {
                /* Application hasn't responded within the timeout window —
                 * send NEXT-WIN on its behalf to keep the DAU streaming. */
                a->liveDataPendingNextWin = FALSE;
                SendLiveNextWin(a);
            }
            continue;
        }
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
        /* VULN-14: SetEvent must be called inside the lock so there is no window
         * between checking moreIrps and signalling the event.  Without the lock,
         * a new ReadFile arriving between LeaveCriticalSection and SetEvent could
         * signal the event, which we then signal again — harmless but wasteful —
         * OR the consumer could drain the new entry before we signal, leaving the
         * event unsignalled for an IRP that needs service. */
        if (moreIrps) SetEvent(a->startEvt);
        LeaveCriticalSection(&a->irpLock);

        /* ── Deliver deferred FILE-ACK ───────────────────────────────────────
         * When a FILE-ACK for W+N arrived while retxPending was set for W,
         * RecvThread stashed it here and kept waiting for the real FILE-ACK W.
         * Once FILE-ACK W was delivered (clearing retxPending), the next IRP
         * lands here and we deliver the deferred W+N frame so the application can
         * advance normally. */
        if (a->deferredPending) {
            a->deferredPending = FALSE;
            /* VULN-17: read window/count fields only if the stored frame is long
             * enough — a truncated frame (< 26 bytes) would cause an OOB read. */
            if (a->deferredFrameLen >= 26) {
                WORD defWin = (WORD)a->deferredFrame[22] | ((WORD)a->deferredFrame[23] << 8);
                WORD defCnt = (WORD)a->deferredFrame[24] | ((WORD)a->deferredFrame[25] << 8);
                LogFile(L"[PacketShim] Delivering deferred FILE-ACK: window=0x%04X count=%u\n",
                    (DWORD)defWin, (DWORD)defCnt);
            } else {
                LogFile(L"[PacketShim] Delivering deferred frame (%u bytes — too short for window field)\n",
                    a->deferredFrameLen);
            }
            DeliverFrame(&req, a->deferredFrame, a->deferredFrameLen);
            continue; /* IRP consumed; go wait for the next one */
        }

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
                    else if (rxT0==0x01 && rxT1==0x02) ftype = L"FILE-LIST";  /* DAU→app: file list resp    */
                    else if (rxT0==0x01 && rxT1==0x05) ftype = L"FILE-SCAN";  /* DAU→app: file meta resp    */
                    else if (rxT0==0x01 && rxT1==0x06) ftype = L"FILE-META";  /* DAU→app: download meta     */
                    else if (rxT0==0x01 && rxT1==0x07) ftype = L"LIVE-CTRL";
                    else if (rxT0==0x01 && rxT1==0x0B) ftype = L"LIVE-CTRL2";
                    else if (rxT0==0x01 && rxT1==0x0C) ftype = L"DAU-POLL";   /* DAU→app: next-win ready?   */
                    else if (rxT0==0x02 && rxT1==0x01) ftype = L"FILE-CHUNK"; /* DAU→app: file data chunk   */
                    else if (rxT0==0x02 && rxT1==0x02) ftype = L"FILE-ACK";   /* DAU→app: window boundary   */
                    else if (rxT0==0x02 && rxT1==0x03) ftype = L"FILE-DONE";  /* DAU→app: transfer complete */
                    else if (rxT0==0x02 && rxT1==0x05) ftype = L"FILE-ERR";   /* DAU→app: download error    */
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

                /* ── FILE-ACK frame layout (confirmed from log analysis) ─────
                 *   [14..15] = 02 02 (type)
                 *   [16..17] = running seq count (LE WORD)
                 *   [18..19] = secondary field
                 *   [20..21] = protocol constant (always 0x0003; NOT chunk count)
                 *   [22..23] = window number (LE WORD)
                 *   [24..25] = chunk count for this window (LE WORD)
                 *   [26..]   = sensor/status payload
                 *
                 * If the DAU skips the confirming FILE-ACK for the retransmit
                 * window and jumps to the next window instead, we stash the
                 * premature FILE-ACK in deferredFrame and wait — delivering it
                 * early would confuse the application's state machine.
                 * ──────────────────────────────────────────────────────────── */

                if (rxT0==0x02 && rxT1==0x02) {
                    /* Snapshot and reset seq tracking — single thread, no lock */
                    DWORD minSeq = a->windowMinSeq;
                    DWORD maxSeq = a->windowMaxSeq;
                    a->windowMinSeq = INVALID_SEQ;
                    a->windowMaxSeq = 0;

                    /* Log seq range if available */
                    if (minSeq != INVALID_SEQ && maxSeq >= minSeq) {
                        DWORD expectedCount = (maxSeq - minSeq) + 1;
                        LogFile(L"[PacketShim] *** Window boundary: seq %lu..%lu → expected %lu chunks ***\n",
                            minSeq, maxSeq, expectedCount);
                    }

                    /* Read window number [22..23] and chunk count [24..25] */
                    if (hdr->caplen >= 26) {
                        WORD ackWin   = (WORD)pkt[22] | ((WORD)pkt[23] << 8);
                        WORD ackCount = (WORD)pkt[24] | ((WORD)pkt[25] << 8);
                        LogFile(L"[PacketShim] FILE-ACK: window=0x%04X count=%u\n",
                            (DWORD)ackWin, (DWORD)ackCount);

                        /* ── Retransmit window tracking (RetxWait) ──────────
                         * retxPending is set when the application sends a
                         * RETRANSMIT NEXT-WIN for window W (Hook_WriteFile).
                         * We wait for the DAU to confirm via FILE-ACK W before
                         * delivering anything to the application.
                         *
                         * If the DAU skips W and sends FILE-ACK W+N first, we
                         * stash W+N as deferred and keep waiting.  Delivering
                         * W+N while the application is still expecting W would
                         * confuse its state machine and cause it to go silent —
                         * no further RETRANSMIT or COMPLETE, eventual ABORT.
                         * ──────────────────────────────────────────────────── */
                        if (a->retxPending && ackWin > a->retxWindow) {
                            /* FILE-ACK W+N arrived while we are still waiting
                             * for the confirming FILE-ACK W.  The application
                             * is not ready for W+N yet — stash it and keep
                             * waiting.  When FILE-ACK W finally arrives, we
                             * deliver it, clear retxPending, and the deferred
                             * W+N is picked up by the outer IRP loop on the
                             * very next iteration. */
                            DWORD copyLen = hdr->caplen < sizeof(a->deferredFrame)
                                            ? hdr->caplen
                                            : (DWORD)sizeof(a->deferredFrame);
                            a->deferredFrameLen = copyLen;
                            CopyMemory(a->deferredFrame, pkt, copyLen);
                            a->deferredPending = TRUE;

                            Log(L"[PacketShim] RetxWait: FILE-ACK win=0x%04X deferred (retxWindow=0x%04X still pending)\n",
                                (DWORD)ackWin, (DWORD)(WORD)a->retxWindow);

                            continue; /* keep retxPending=1; wait for FILE-ACK W */

                        } else if (a->retxPending && ackWin == a->retxWindow) {
                            /* DAU sent the confirming FILE-ACK for the exact
                             * retransmit window — no injection needed. */
                            InterlockedExchange(&a->retxPending, 0);
                            LogFile(L"[PacketShim] RetxPending cleared: legitimate FILE-ACK for win=0x%04X\n",
                                (DWORD)ackWin);
                        }
                    } else {
                        Log(L"[PacketShim] FILE-ACK too short (%u bytes)\n", hdr->caplen);
                    }
                }

                /* ── RX frame log (skip FILE-CHUNK to prevent DebugView storm) ──
                 * FILE-CHUNK (02 01) frames arrive at wire rate (~100/window).
                 * Logging every one fills DebugView and causes ~80 ms/chunk
                 * overhead that can starve the application's disk write thread.  The window
                 * boundary message already summarises the chunk count and seq
                 * range, so individual chunk logs add no diagnostic value.
                 * All other frame types (FILE-ACK, DAU-POLL, NEXT-WIN, etc.)
                 * are logged with a full or partial hex dump as before. */
                if (!(rxT0==0x02 && rxT1==0x01)) {
                    BOOL fullDump = (rxT0==0x02 && rxT1==0x02) ||  /* FILE-ACK  */
                                    (rxT0==0x01 && rxT1==0x0C);    /* DAU-POLL  */
                    DWORD logLen = fullDump ? hdr->caplen :
                                   (hdr->caplen < 20 ? hdr->caplen : 20);
                    /* 3 chars/byte + NUL; 60 bytes max → 181 chars */
                    WCHAR hexBuf[200] = {0};
                    WCHAR *wp = hexBuf;
                    for (DWORD bi = 0; bi < logLen; bi++) {
                        StringCchPrintfW(wp, 6, L"%02X ", pkt[bi]);
                        wp += 3;
                    }
                    if (req.bufSz > 0 && hdr->caplen > req.bufSz) {
                        LogFile(L"[PacketShim] RX %u bytes [%s] TRUNCATED to buf=%u  %s\n",
                            hdr->caplen, ftype, req.bufSz, hexBuf);
                    } else {
                        LogFile(L"[PacketShim] RX %u bytes [%s] buf=%u  %s\n",
                            hdr->caplen, ftype, req.bufSz, hexBuf);
                    }
                }
                /* ── DAU MAC learning & live-view NEXT-WIN trigger ───────
                 * Learn the DAU's source MAC from the first received frame.
                 * When a LIVE-DATA (03 03) frame is delivered, set the
                 * pending flag so RecvThread auto-sends NEXT-WIN if the application's
                 * Delphi timer doesn't fire within LIVE_NEXTWIN_TIMEOUT_MS. */
                if (hdr->caplen >= 12 &&
                    (a->dauMac[0] | a->dauMac[1] | a->dauMac[2] |
                     a->dauMac[3] | a->dauMac[4] | a->dauMac[5]) == 0) {
                    CopyMemory(a->dauMac, pkt + 6, 6);
                }
                if (rxT0 == 0x03 && rxT1 == 0x03) {
                    a->liveDataPendingNextWin = TRUE;
                }

                DeliverFrame(&req, pkt, hdr->caplen);
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
 * ─────────────────────────────────────────────────────────────
 * Formats the response buffer for IOCTL_ENUM_ADAPTERS:
 *   [DWORD count=1] [WCHAR name\0] [WCHAR desc\0] [\0]
 *
 * The application parses the description string and extracts the
 * adapter name from it by skipping the first 12 wide characters.
 * We prefix the desc with "\Device\NPF_" (exactly 12 WCHARs) so
 * that the extracted portion is g_AdapterName — the name the
 * application will then pass back to CreateFileW as "\\.\<name>",
 * which IsAdapterDev recognises and intercepts.
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
    /* buf=NULL or len too small: report needed size and return FALSE so the
     * caller can retry with a correctly-sized buffer. */
    if (!buf || len < needed) return FALSE;

    *((PULONG)buf) = 1;
    /* Track remaining space accurately so each StringCchCopyW receives the
     * correct count — passing len/sizeof(WCHAR) for the second write would
     * overstate the available room once p has advanced past the first string. */
    PWCHAR  p    = (PWCHAR)((PUCHAR)buf + sizeof(ULONG));
    ULONG   rem  = len - sizeof(ULONG);  /* bytes remaining after the count field */
    StringCchCopyW(p, rem / sizeof(WCHAR), g_AdapterName);
    p   += wcslen(g_AdapterName) + 1;
    rem -= nw;
    StringCchCopyW(p, rem / sizeof(WCHAR), descStr);
    p   += wcslen(descStr) + 1;
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
 * ─────────────────────────────────────────────────────────────
 * DAULink.exe opens three types of paths we care about:
 *   1. \\.\Packet           — the "control" device it uses to list
 *                             adapters.  We return a fake handle and
 *                             handle the subsequent DeviceIoControl
 *                             calls ourselves.
 *   2. \\.\Packet_<name>    — opened first with access=0 just to
 *                             query the MAC address via IOCTL.
 *                             Return a different fake handle.
 *   3. \\.\Packet_<name>    — opened again with GENERIC_READ|WRITE
 *                             for the actual data transfer.  This
 *                             is where we call pcap_open_live and
 *                             spin up a RecvThread.
 *
 * Anything that does not match these patterns is passed straight
 * through to the real CreateFileW — we do not want to intercept
 * ordinary file or registry opens.
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

    /* MAC-query fingerprint: the application opens the adapter device
     * with dwDesiredAccess=0 and hTemplate=INVALID_HANDLE_VALUE specifically
     * for the MAC address IOCTL, using a short path string that may not match
     * our configured adapter name.  Matching on these two parameters is more
     * reliable than matching on the path alone. */
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
 * ─────────────────────────────────────────────────────────────
 * Handles the two IOCTLs DAULink.exe sends to the packet driver:
 *
 *   IOCTL_ENUM_ADAPTERS (0x8000000C) — sent to the control handle.
 *   DAULink.exe wants a list of available adapters as a counted
 *   DWORD followed by a double-NUL-terminated wide string list.
 *   We reply with the single adapter name from fls30_shim.ini.
 *
 *   IOCTL_GET_MAC (0x170002) — sent to the MAC-query handle.
 *   DAULink.exe wants the 6-byte hardware MAC of the NIC.  We
 *   return whatever FetchMac() loaded at startup.
 *
 * Everything else on a fake handle is logged and ignored.
 * DeviceIoControl calls on real (non-fake) handles pass through.
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_DeviceIoControl(
    HANDLE hDev, DWORD dwCode,
    LPVOID pIn, DWORD nIn, LPVOID pOut, DWORD nOut,
    LPDWORD pRet, LPOVERLAPPED pOv)
{
    /* Control device — only ENUM_ADAPTERS */
    if (hDev == FAKE_CONTROL_HANDLE) {
        if (dwCode == IOCTL_ENUM_ADAPTERS) {
            /* pOut=NULL is legal — caller probing the required buffer size. */
            if (!pOut) {
                ULONG needed = 0;
                BuildEnumResponse(NULL, 0, &needed);
                if (pRet) *pRet = needed;
                SetLastError(ERROR_INSUFFICIENT_BUFFER);
                return FALSE;
            }
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
        if (!pOut || nOut < 6) { SetLastError(ERROR_INSUFFICIENT_BUFFER); return FALSE; }
        CopyMemory(pOut, g_Mac, 6);
        if (pRet) *pRet = 6;
        Log(L"[PacketShim] IOCTL_GET_MAC → %02X:%02X:%02X:%02X:%02X:%02X\n",
            g_Mac[0], g_Mac[1], g_Mac[2], g_Mac[3], g_Mac[4], g_Mac[5]);
        return TRUE;
    }

    /* NDIS IOCTLs — the application uses WriteFile for actual sends; treat these as no-ops */
    if (dwCode == IOCTL_NDIS_SEND || dwCode == IOCTL_NDIS_SEND_LOOPBACK ||
        dwCode == IOCTL_NDIS_RESET) {
        if (pRet) *pRet = 0;
        return TRUE;
    }

    return g_OrigDIC(hDev, dwCode, pIn, nIn, pOut, nOut, pRet, pOv);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_CloseHandle
 * ─────────────────────────────────────────────────────────────
 * Cleans up when DAULink.exe is done with an adapter handle.
 * The most important thing here is stopping RecvThread cleanly —
 * we set stopThread, call pcap_breakloop to unblock pcap_next_ex,
 * then wait up to 5 seconds for the thread to exit before we
 * release the pcap handle.  Skipping this wait causes crashes
 * because pcap_close on a handle still in use frees memory the
 * thread is touching.
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_CloseHandle(HANDLE h)
{
    if (h == FAKE_CONTROL_HANDLE || h == FAKE_MAC_HANDLE) return TRUE;

    AdpEntry *a = LookupAdp(h);
    if (a) {
        /* VULN-19: use InterlockedExchange so the write is sequentially
         * consistent on all architectures (x86 store is already atomic for
         * aligned DWORD, but the compiler barrier here prevents reordering). */
        InterlockedExchange((LONG*)&a->stopThread, 1);
        /* pcap_breakloop forces pcap_next_ex to return immediately so
         * RecvThread exits cleanly without a timeout race. */
        if (a->pcap && g_pcapBreakloop) g_pcapBreakloop(a->pcap);
        if (a->startEvt) SetEvent(a->startEvt);
        if (a->thread) {
            if (WaitForSingleObject(a->thread, 5000) == WAIT_TIMEOUT) {
                /* RecvThread did not exit within 5 s even after pcap_breakloop.
                 *
                 * DO NOT call TerminateThread — it skips stack unwind and does
                 * not release mutexes.  If RecvThread holds an internal Npcap
                 * lock at the moment of termination, the subsequent pcap_close
                 * call below will deadlock or corrupt Npcap state (VULN-10).
                 *
                 * Safest path: close the thread handle (the OS will release the
                 * thread when it eventually exits naturally) and skip pcap_close.
                 * The pcap handle is leaked, but the OS reclaims all process
                 * resources on exit.  This is far safer than a deadlock or heap
                 * corruption inside DAULink.exe's address space. */
                Log(L"[PacketShim] WARNING: RecvThread still running after 5s — "
                    L"skipping pcap_close to avoid Npcap mutex deadlock. "
                    L"pcap handle will be released by OS on process exit.\n");
                CloseHandle(a->thread); a->thread = NULL;
                if (a->startEvt) { CloseHandle(a->startEvt); a->startEvt = NULL; }
                DeleteCriticalSection(&a->irpLock);
                a->inUse = FALSE;
                return TRUE;  /* skip pcap_close — intentional leak */
            }
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
 * Hook_WriteFile
 * ─────────────────────────────────────────────────────────────
 * Intercepts outbound frames from DAULink.exe and forwards them
 * to the wire via pcap_sendpacket.  But before forwarding, we
 * inspect the frame type so we can track protocol state:
 *
 *   NEXT-WIN (02 04) with missing > 0  →  RETRANSMIT request.
 *     Set retxPending=1, record retxWindow.  RecvThread will now
 *     hold any FILE-ACK for a future window until the confirming
 *     FILE-ACK for this window arrives.
 *
 *   NEXT-WIN (02 04) with missing = 0  →  COMPLETE signal.
 *     If retxPending is active and this COMPLETE is for a window
 *     older than retxWindow, it is a spurious ghost frame from the
 *     application's async loop completing the previous window after
 *     the retransmit was already requested.  DROP IT — if the DAU
 *     sees this COMPLETE it will skip the retransmit and advance,
 *     which desynchronises the transfer and causes an ABORT.
 *
 *   Everything else goes to the wire unchanged.
 *
 * TestMode intercept: PING (01 01) frames are caught here and a
 * synthetic reply is queued for RecvThread to deliver back.
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
         * see what window range the application is requesting; first 20 bytes for others */
        if (nBytes >= 16) {
            const BYTE *fp = (const BYTE*)lpBuf;
            BYTE t0=fp[14], t1=fp[15];
            LPCWSTR txtype = L"?";
            if      (t0==0x01&&t1==0x01) txtype=L"PING";
            else if (t0==0x01&&t1==0x02) txtype=L"FILE-LIST";  /* app→DAU: list files             */
            else if (t0==0x01&&t1==0x05) txtype=L"FILE-SCAN";  /* app→DAU: per-file meta request  */
            else if (t0==0x01&&t1==0x06) txtype=L"FILE-REQ";   /* app→DAU: request file download  */
            else if (t0==0x01&&t1==0x07) txtype=L"LIVE-CTRL";
            else if (t0==0x01&&t1==0x0B) txtype=L"LIVE-CTRL2";
            else if (t0==0x02&&t1==0x04) txtype=L"NEXT-WIN";   /* app→DAU: send next window       */
            else if (t0==0x02&&t1==0x05) txtype=L"ABORT";      /* app→DAU: abort transfer         */
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
            /* ABORT always goes to DebugView; everything else is file-only */
            if (t0==0x02 && t1==0x05)
                Log(L"[PacketShim] TX %u bytes [%s]  %s\n", nBytes, txtype, txHex);
            else
                LogFile(L"[PacketShim] TX %u bytes [%s]  %s\n", nBytes, txtype, txHex);

            /* ── NEXT-WIN (02 04) processing ──────────────────────────────────
             * Two sub-cases:
             *   missingCnt > 0 → RETRANSMIT: track the window, set retxPending.
             *   missingCnt == 0 → COMPLETE:   may be spurious — the application's
             *     async loop can complete the previous window and send a COMPLETE
             *     NEXT-WIN for it moments after we already sent a RETRANSMIT for
             *     the current window.  If retxPending is set and this COMPLETE is
             *     for a window earlier than retxWindow,
             *     DROP it — the DAU must not see it or it will abandon the
             *     retransmit, advance to the next window, and the transfer will
             *     desynchronise and eventually ABORT.
             * ─────────────────────────────────────────────────────────────────── */
            if (t0==0x02 && t1==0x04 && nBytes >= 26) {
                const BYTE *fp2 = (const BYTE*)lpBuf;
                WORD winNum     = (WORD)fp2[22] | ((WORD)fp2[23] << 8);
                WORD missingCnt = (WORD)fp2[24] | ((WORD)fp2[25] << 8);
                if (missingCnt > 0) {
                    /* RETRANSMIT NEXT-WIN: record it.
                     * retxWindow is written before retxPending is set.
                     * On x86 (TSO) stores are never reordered past later stores,
                     * so RecvThread seeing retxPending=1 is guaranteed to also
                     * see the updated retxWindow.  Safe on this platform. */
                    a->retxWindow = winNum;
                    InterlockedExchange(&a->retxPending, 1);
                    Log(L"[PacketShim] RetxTrack: window=0x%04X missing=%u — awaiting DAU retransmit\n",
                        (DWORD)a->retxWindow, (DWORD)missingCnt);
                } else {
                    /* COMPLETE NEXT-WIN from the application — cancel the
                     * live-view auto-send flag so RecvThread doesn't also
                     * send one for the same cycle. */
                    if (a->liveDataPendingNextWin) {
                        a->liveDataPendingNextWin = FALSE;
                        LogFile(L"[PacketShim] LiveView: application sent own NEXT-WIN — auto-send cancelled\n");
                    }
                }
                if (a->retxPending && winNum < a->retxWindow) {
                    /* SPURIOUS COMPLETE for a window < retxWindow — DROP IT.
                     * The application's async loop finished processing the
                     * previous window just after we sent a retransmit request.
                     * Suppress this so the DAU honours the retransmit. */
                    Log(L"[PacketShim] *** DROPPING spurious COMPLETE NEXT-WIN win=0x%04X (retxWindow=0x%04X) — not sending to DAU ***\n",
                        (DWORD)winNum, (DWORD)a->retxWindow);
                    if (lpWritten) *lpWritten = nBytes;
                    if (lpOv) {
                        lpOv->InternalHigh = nBytes;
                        lpOv->Internal     = 0;
                        if (lpOv->hEvent) SetEvent(lpOv->hEvent);
                    }
                    return TRUE;   /* tell the application "sent OK" — packet silently dropped */
                }
            }
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
 * Hook_ReadFile
 * ─────────────────────────────────────────────────────────────
 * DAULink.exe keeps several overlapped ReadFile requests in flight
 * simultaneously to avoid stalling when the DAU sends a burst of
 * frames.  We handle this with an 8-slot circular IRP queue:
 *
 *   - Push the request (buffer pointer + OVERLAPPED) onto the tail.
 *   - Return ERROR_IO_PENDING immediately so DAULink.exe can post
 *     the next request without waiting.
 *   - RecvThread pops the head when a frame arrives and signals
 *     OVERLAPPED.hEvent so DAULink.exe's WaitForSingleObject wakes.
 *
 * If the queue fills up (all 8 slots busy) we reject the request
 * with ERROR_TOO_MANY_CMDS.  In practice this never happens on the
 * target hardware but might on a much faster machine.
 *
 * Non-overlapped (synchronous) ReadFile calls are not expected from
 * DAULink.exe on the data handle, but are handled as a fallback by
 * looping on pcap_next_ex directly.
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
            /* ReadFile queued — not logged; fires ~100× per window
             * and would flood DebugView.  Window boundary messages
             * already capture the IRP flow at the right granularity. */
            SetEvent(a->startEvt);
            SetLastError(ERROR_IO_PENDING);
            return FALSE;
        }
        /* Synchronous: block until packet.
         * DAULink.exe always uses overlapped I/O on the data handle so this
         * path is a safety fallback only.  Check stopThread on each iteration
         * so Hook_CloseHandle can break this loop if needed. */
        while (!a->stopThread) {
            struct pcap_pkthdr *hdr = NULL;
            const unsigned char *pkt = NULL;
            int r = g_pcapNextEx(a->pcap, &hdr, &pkt);
            if (r == 1) {
                DWORD cl = hdr->caplen < nBytes ? hdr->caplen : nBytes;
                CopyMemory(lpBuf, pkt, cl);
                if (lpRead) *lpRead = cl;
                return TRUE;
            }
            /* r==0: 1 ms timeout, retry.  r<0: pcap error or breakloop — exit. */
            if (r != 0) { SetLastError(ERROR_READ_FAULT); return FALSE; }
        }
        SetLastError(ERROR_OPERATION_ABORTED);
        return FALSE;
    }
    if (g_OrigRF)
        return g_OrigRF(hFile, lpBuf, nBytes, lpRead, lpOv);
    return ReadFile(hFile, lpBuf, nBytes, lpRead, lpOv);
}

/* ══════════════════════════════════════════════════════════════
 * Hook_ExitWindowsEx
 * ─────────────────────────────────────────────────────────────
 * The application calls ExitWindowsEx with EWX_SHUTDOWN|EWX_FORCE
 * when closing.  On a field laptop this would shut down Windows
 * entirely, which is not what the operator expects.
 * We intercept it and call ExitProcess(0) instead, so DAULink.exe
 * exits cleanly without touching the rest of the system.
 * ══════════════════════════════════════════════════════════════ */
BOOL WINAPI Hook_ExitWindowsEx(UINT uFlags, DWORD dwReason)
{
    Log(L"[PacketShim] ExitWindowsEx(flags=0x%X) intercepted → ExitProcess(0)\n", uFlags);
    ExitProcess(0);
    return TRUE; /* never reached */
}


/* ══════════════════════════════════════════════════════════════
 * SCM hooks — fake the "Packet" service
 * ─────────────────────────────────────────────────────────────
 * DAULink.exe calls OpenServiceW("Packet") and StartServiceW at
 * startup to load the legacy kernel driver.  Since that driver
 * does not exist on Windows 11 the SCM call would fail, producing
 * an error dialog before DAULink.exe even gets to the network.
 *
 * We intercept OpenServiceW for the "Packet" service name and
 * return a fake SC_HANDLE.  StartServiceW, QueryServiceStatus,
 * and CloseServiceHandle on that fake handle all silently succeed.
 * DAULink.exe moves on believing the driver started fine.
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

