# Software Design Document (SDD)

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

## 1. System Architecture

`packet_shim.dll` is a 32-bit DLL injected into DAULink.exe's process. It intercepts the application's Win32 calls at the import address table (IAT) and routes them through a protocol-aware engine that uses Npcap for actual network I/O. From DAULink.exe's perspective it is calling `kernel32.dll` normally; the shim is invisible.

Four components work together:

1. **IAT Hook Engine** — patches DAULink.exe's import table at `DllMain` time.
2. **Adapter Manager** — maps fake Win32 handles to live `pcap_t` sessions and per-adapter state.
3. **Receive Thread (`RecvThread`)** — a background thread that pulls frames from Npcap, enforces the protocol state machine, and fulfils pending IRP requests.
4. **Async IRP Queue** — a per-adapter 8-slot circular buffer that holds outstanding `ReadFile` requests until a frame arrives to satisfy them.

---

## 2. Component Design

### 2.1 IAT Hook Engine

During `DllMain(DLL_PROCESS_ATTACH)` the shim walks DAULink.exe's PE import directory and replaces function pointers in the IAT with its own proxies:

| Original function | Proxy |
|---|---|
| `CreateFileW` | `Hook_CreateFileW` |
| `ReadFile` | `Hook_ReadFile` |
| `WriteFile` | `Hook_WriteFile` |
| `DeviceIoControl` | `Hook_DeviceIoControl` |
| `CloseHandle` | `Hook_CloseHandle` |
| `OpenServiceW` | `Hook_OpenServiceW` |
| `ExitWindowsEx` | `Hook_ExitWindowsEx` |

IAT patching is used rather than trampoline-style hooks because it is simpler, does not touch instruction bytes, and is entirely stable on 32-bit x86 binaries.

### 2.2 Fake Handle Namespace

DAULink.exe opens several distinct device paths. The shim maps them to fake `HANDLE` values it manufactures:

| Path DAULink.exe opens | Fake handle |
|---|---|
| `\\.\Packet` (control device) | `FAKE_CONTROL_HANDLE` |
| `\\.\Packet_<name>` with no write access (MAC query) | `FAKE_MAC_HANDLE` |
| `\\.\Packet_<name>` with `GENERIC_READ|GENERIC_WRITE` | `FAKE_ADP_BASE + slot` (0..3) |

Any `ReadFile`, `WriteFile`, `DeviceIoControl`, or `CloseHandle` call on one of these values is intercepted. Any other handle value is passed through to the real `kernel32.dll`.

### 2.3 Async IRP Queue

DAULink.exe uses overlapped I/O: it submits multiple `ReadFile` requests before any data has arrived, then waits on the `OVERLAPPED.hEvent` objects. The IRP queue manages these pending requests.

- **Depth:** 8 slots per adapter (`IRP_QUEUE_DEPTH = 8`).
- **`Hook_ReadFile`:** if the request carries an `OVERLAPPED` pointer, push it onto the queue tail, set `lpOv->Internal = STATUS_PENDING`, call `SetLastError(ERROR_IO_PENDING)`, and return `FALSE`. Return immediately — do not block.
- **`RecvThread`:** when a frame is ready to deliver, pop the head of the queue, copy the frame into the caller's buffer, set `*lpNumberOfBytesRead`, and call `SetEvent(req.ov->hEvent)`.
- The queue is protected by a `CRITICAL_SECTION` (`irpLock`). `RecvThread` waits on `startEvt` when the queue is empty.

### 2.4 Receive Thread (`RecvThread`)

`RecvThread` runs one instance per open adapter. It loops on `pcap_next_ex()` and processes each arriving frame:

1. **Filter:** drop frames that are not EtherType `0xAA55`.
2. **MAC learning:** if `dauMac` has not been set, record the source MAC of the first received frame.
3. **Frame dispatch by type:**
   - `02 01` FILE-CHUNK: update `windowMinSeq` / `windowMaxSeq` for this window.
   - `02 02` FILE-ACK: reconstruct chunk count (see §2.5), then apply RetxWait logic (see §2.6).
   - `03 03` LIVE-DATA: start the 50 ms NEXT-WIN auto-send timer.
   - All other types: deliver directly to the IRP queue.
4. **Deferred frame check:** after every delivery, if `deferredPending` is set and `retxPending` is clear, deliver `deferredFrame` on the next available IRP and clear `deferredPending`.

### 2.5 FILE-ACK Chunk Count Tracking

During each window `RecvThread` records the lowest and highest FILE-CHUNK sequence numbers it sees in `windowMinSeq` and `windowMaxSeq`. When the FILE-ACK (`02 02`) arrives, it computes:

```
expectedCount = windowMaxSeq - windowMinSeq + 1
```

This value is logged via `LogFile()` for post-analysis (how many chunks the DAU actually sent vs. what the FILE-ACK claims). On the current hardware the DAU populates bytes `[24..25]` of the FILE-ACK correctly, so no patching of the frame is performed. Both fields are reset to their sentinels when the FILE-ACK is processed so they are fresh for the next window.

This tracking was put in place during early debugging when it was unclear whether the count field was always populated. It remains useful as a diagnostic sanity check — if the log shows `expected 3527` but the FILE-ACK reports a wildly different number, something is wrong upstream.

### 2.6 RetxWait State Machine

`Hook_WriteFile` parses every outbound NEXT-WIN frame (`02 04`):

- **`missing > 0` (retransmit request):** set `retxPending = 1`, record `retxWindow = windowNumber`.
- **`missing = 0` (complete) while `retxPending` and `windowNumber <= retxWindow`:** this is a spurious COMPLETE generated by DAULink.exe's async race. Return `TRUE` to the caller but do not forward the frame to the wire (silent drop).

`RecvThread` handles the FILE-ACK side:

- **Incoming FILE-ACK, `retxPending = 1`, `ackWindow > retxWindow`:** copy the frame into `deferredFrame[1514]`, set `deferredPending = 1`. Do not deliver yet.
- **Incoming FILE-ACK, `retxPending = 1`, `ackWindow == retxWindow`:** this is the confirming ACK. Deliver it to the next IRP. Clear `retxPending`. On the next iteration, deliver `deferredFrame` if `deferredPending`.
- **Incoming FILE-ACK, `retxPending = 0`:** deliver normally.

### 2.7 Auto NEXT-WIN (Live-View)

If `RecvThread` sees a LIVE-DATA (`03 03`) frame and DAULink.exe has not sent a NEXT-WIN within 50 ms, the shim constructs and transmits a NEXT-WIN frame automatically. The destination MAC is `dauMac` (learned from the first received frame). The `liveDataPendingNextWin` flag tracks whether the timer is active.

### 2.8 Hook_OpenServiceW and Startup Intercept

DAULink.exe calls `OpenServiceW` for the service name "Packet" and then `StartServiceW`. The shim intercepts `OpenServiceW`, returns a fake service handle, and silently discards the `StartServiceW` call. This prevents the startup error that occurs because the legacy kernel driver is absent.

---

## 3. Data Structures

### 3.1 AdpEntry

One `AdpEntry` exists for each open adapter slot (up to `MAX_ADP = 4`).

```c
typedef struct {
    HANDLE   hFile;              // Fake Win32 handle returned to DAULink.exe
    pcap_t  *pcap;               // Live Npcap capture session

    // IRP Queue (8 slots)
    CRITICAL_SECTION irpLock;
    IrpReq   irpQueue[8];        // IRP_QUEUE_DEPTH = 8
    int      irpHead, irpTail;
    HANDLE   startEvt;           // Signalled when a new ReadFile arrives

    // RetxWait state
    volatile LONG retxPending;   // 1 while waiting for retransmit confirmation
    WORD          retxWindow;    // Window number being retransmitted

    // Deferred frame
    BOOL  deferredPending;
    BYTE  deferredFrame[1514];   // Max Ethernet frame size
    DWORD deferredFrameLen;

    // Live-view auto NEXT-WIN
    volatile LONG liveDataPendingNextWin;  // 1 = 50 ms timer is running

    // DAU MAC (learned from first received frame)
    BYTE dauMac[6];

    // FILE-CHUNK sequence tracking (for FILE-ACK count reconstruction)
    DWORD windowMinSeq;
    DWORD windowMaxSeq;
    BOOL  windowSeqValid;        // FALSE until first chunk seen in window
} AdpEntry;
```

### 3.2 IrpReq

```c
typedef struct {
    LPVOID       buf;            // Caller's output buffer
    DWORD        bufLen;         // Buffer length
    LPDWORD      pBytesRead;     // Pointer to caller's bytes-read DWORD
    OVERLAPPED  *ov;             // Caller's OVERLAPPED structure
} IrpReq;
```

---

## 4. Logging Architecture

The shim uses a two-tier logging system controlled by the global `g_LogEnabled` flag (read from `Logging=` in `fls30_shim.ini`).

| Function | Output | When to use |
|---|---|---|
| `LogFile(fmt, ...)` | File only (`C:\FLS_DOWNLOAD\shim_YYYYMMDD-HHMMSS.log`) | Per-window events: chunk counts, window numbers, ACK delivery, deferred frame delivery |
| `Log(fmt, ...)` | File **and** DebugView (`OutputDebugStringW`) | Important events: state transitions, errors, retransmit start/clear, IRP queue overflows |

When `g_LogEnabled = 0` (i.e. `Logging=0` in INI), both functions are no-ops — no file is opened, no `OutputDebugStringW` is called, zero overhead.

**Why the split matters:** `OutputDebugStringW` acquires a global kernel mutex. During high-throughput transfers, calling it on every packet was enough to delay `RecvThread` by several milliseconds — long enough to cause Npcap buffer overflows and trigger the transfer failures the shim is designed to prevent. The fix was to reserve `Log()` (file + DebugView) for infrequent events and use `LogFile()` (file only) for the per-packet detail that is only read after the fact.

The log file is created at shim initialisation with a timestamp in its name. This means each run produces a fresh file and old runs are preserved automatically.

---

## 5. Globals

| Variable | Type | Purpose |
|---|---|---|
| `g_LogEnabled` | `int` | Master logging switch (from `Logging=` in INI) |
| `g_TestMode` | `int` | Synthetic frame generation switch |
| `g_adp[]` | `AdpEntry[4]` | Adapter slot array |
| `g_adpCount` | `int` | Number of slots in use |
| `g_hLogFile` | `HANDLE` | Open log file handle (NULL when logging disabled) |
