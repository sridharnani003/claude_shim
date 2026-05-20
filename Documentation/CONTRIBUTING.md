# Contributing to packet_shim

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Date:** 2026-05-19

---

## Overview

`packet_shim.dll` is a single-file C project. There is no complex build system — the entire implementation lives in `packet_shim.c`, with a thin header (`packet_shim.h`) for shared types, and `build_dll.bat` for building. The `fls30_shim.ini` config file controls runtime behaviour.

### File Layout

```
packet_shim.c       Main implementation: IAT hooks, RecvThread, state machine, logging
packet_shim.h       Shared types and constants (AdpEntry, IrpReq, fake handle values)
build_dll.bat       Build script (cl.exe invocation for x86 release DLL)
fls30_shim.ini      Runtime configuration — copy this next to DAULink.exe
Documentation/      All design documents (start with walkthrough.md)
```

---

## Skill Requirements

You do not need to know all of this before diving in, but these are the areas the code draws on:

| Skill | Why it matters here |
|---|---|
| **C (Windows API, pointer arithmetic, struct layout)** | The core implementation is plain C. Frame parsing is done by casting raw byte pointers to struct pointers or indexing byte arrays directly. Getting offsets wrong by one byte breaks the protocol silently. |
| **Windows DLL / IAT hooking** | The injection mechanism works by patching function pointers in DAULink.exe's import address table. You need to understand PE structure well enough to walk the import directory at runtime. |
| **Npcap / libpcap API** | `pcap_open_live`, `pcap_next_ex`, `pcap_sendpacket`, `pcap_setfilter`, `pcap_setmintocopy` are all used. The Npcap SDK docs are the primary reference. |
| **Win32 async I/O (OVERLAPPED, ERROR_IO_PENDING, SetEvent)** | DAULink.exe pipelines multiple overlapped ReadFile requests. The IRP queue must correctly manage `OVERLAPPED` structures and signal `hEvent` at exactly the right moment. |
| **Ethernet frame structure** | Frames are constructed and parsed by hand: 6-byte destination MAC, 6-byte source MAC, 2-byte EtherType (`0xAA55`), then payload. Minimum frame size is 60 bytes (hardware pads shorter frames with zeros — which is the root cause of the chunk count bug). |
| **Threading (CreateThread, CRITICAL_SECTION, volatile, InterlockedExchange)** | RecvThread runs concurrently with DAULink.exe's threads. The IRP queue is protected by a CRITICAL_SECTION. `retxPending` is a `volatile LONG` updated with `InterlockedExchange`. |
| **Wireshark** | Useful for capturing traffic during testing to verify what the shim is actually sending and receiving. Not required for normal development. |
| **API Monitor** | Useful for tracing Win32 calls if you need to understand what DAULink.exe is doing at the call level. Not required for normal development. |
| **WinDbg / DebugView** | DebugView shows `Log()` output in real time (when `Logging=1`). Useful for watching state transitions live. Read the Heisenbug note below before you rely on it heavily. |
| **x86 calling conventions** | Only relevant if you need to understand how the IAT hook proxies preserve registers. The current hooks use standard `__stdcall` / `__cdecl` and the compiler handles it. |

---

## Development Environment Setup

### Prerequisites

1. **Visual Studio 2022** with "Desktop development with C++" workload.
2. **Npcap SDK** — download from [npcap.com](https://npcap.com). Extract it somewhere and note the path (you will need to point the build script at the include and lib directories).
3. **Npcap runtime** — install Npcap on your test machine with "WinPcap API-compatible mode" checked.
4. **Test signing** (only if you are also building `packet.sys`):
   ```
   bcdedit /set testsigning on
   ```
   Then reboot. Not needed if you are only working on the DLL.

### Configure the Build Script

Open `build_dll.bat` and set the `NPCAP_SDK` variable to point at your Npcap SDK directory. The script will pick up include and lib paths from there.

---

## How to Build

```powershell
.\build_dll.bat
```

This runs `cl.exe` with the x86 target, links against `wpcap.lib` and `kernel32.lib`, and outputs `packet_shim.dll` to `.\out\`.

If you prefer to build from the Visual Studio IDE, create a new DLL project, add `packet_shim.c`, set Platform to Win32 (x86), and add the Npcap SDK include and lib paths to the project properties.

---

## How to Deploy

1. Copy `out\packet_shim.dll` to the DAULink.exe directory (e.g. `C:\FLS30\BIN\`).
2. Copy `fls30_shim.ini` to the same directory and configure it (see below).
3. Register via `AppInit_DLLs`:
   ```
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\FLS30\BIN\packet_shim.dll" /f
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
   ```
4. Launch DAULink.exe normally.

**Alternative — launcher batch file:** if you would rather not use `AppInit_DLLs` (which injects into every process, not just DAULink.exe), create a small launcher:

```bat
@echo off
set PATH=C:\FLS30\BIN;%PATH%
start "" /D "C:\FLS30\BIN" "C:\FLS30\BIN\DAULink.exe"
```

Then place `packet_shim.dll` so that it is on the DLL search path before DAULink.exe's startup resolves imports. This is tidier for production environments.

---

## How to Configure (`fls30_shim.ini`)

```ini
[Npcap]
AdapterGUID=

[Adapter]
FriendlyName=Intel(R) Ethernet Connection (3) I219-LM

[Debug]
TestMode=0
Logging=1
```

- `FriendlyName` is what you see in Device Manager or `Get-NetAdapter`. Get it right — if the name does not match, the shim cannot open the adapter.
- `AdapterGUID` is an alternative to `FriendlyName`. Use this if the friendly name contains unusual characters or if you want to pin to a specific adapter regardless of name changes. Leave blank to use `FriendlyName`.
- `Logging=1` is the default. Log files go to `C:\FLS_DOWNLOAD\shim_YYYYMMDD-HHMMSS.log`. The directory must exist; the shim does not create it.
- `TestMode=1` generates synthetic DAU frames. The full protocol flow will execute without any hardware connected. Useful for testing shim logic in isolation.

---

## How to Debug

### Using the Log File

With `Logging=1`, every run creates a timestamped log at `C:\FLS_DOWNLOAD\`. Open it after a transfer (or stall) to see what happened. Key things to look for:

- `RetxTrack: set retxPending W=N` — the shim detected a retransmit request for window N.
- `RetxWait: defer FILE-ACK W=N` — the shim stashed a premature FILE-ACK.
- `RetxWait: confirm W=N, clear retxPending` — the confirming ACK arrived; retransmit complete.
- `RetxWait: deliver deferred FILE-ACK W=N` — the deferred frame was delivered.
- `SpuriousDrop: COMPLETE W=N dropped` — a spurious COMPLETE was suppressed.
- `IRP queue full` — all 8 IRP slots were occupied when a new ReadFile arrived. This should not happen on normal hardware; if you see it repeatedly, the machine is faster than expected and you may need to increase `IRP_QUEUE_DEPTH`.

### Using DebugView

Open Sysinternals DebugView before launching DAULink.exe. With `Logging=1`, critical events (state transitions, errors) will appear in real time via `OutputDebugStringW`. Per-window detail (chunk counts, ACK delivery) goes to the file only.

**Important:** read the Heisenbug note below before using DebugView during high-throughput transfers.

### Using TestMode

Set `TestMode=1` in `fls30_shim.ini`. Launch DAULink.exe. The shim will generate synthetic DAU frames so you can walk through the full state machine — PING, FILE-LIST, FILE-SCAN, FILE-REQ, FILE-META, FILE-CHUNK, FILE-ACK, NEXT-WIN — without any hardware. This is the fastest way to verify a code change that touches the state machine.

---

## What to Do When a Transfer Stalls

1. Make sure `Logging=1` is set and the previous run produced a log file in `C:\FLS_DOWNLOAD\`.
2. Open the log and search for the last successful window number.
3. Look at what came after: was there a `RetxTrack` entry without a matching `RetxWait: confirm`? That means the confirming FILE-ACK never arrived — check your network connection.
4. Was there a `SpuriousDrop` entry where you would not expect one? That means `retxPending` was still set from a previous retransmit when it should have been cleared.
5. Did the log stop mid-transfer with no error? The shim's IRP queue may have overflowed silently. Check for `IRP queue full` entries.
6. If the log shows everything completed normally but DAULink.exe is stuck anyway, the application's state machine is confused about something unrelated to the shim — capture with Wireshark to see what is on the wire.

---

## Known Gotchas

**Npcap promiscuous TX echo.** In promiscuous mode, Npcap delivers your own transmitted frames back to you as received frames. `RecvThread` will see frames that the shim itself just sent via `pcap_sendpacket`. The EtherType filter is not sufficient to drop these (they have EtherType `0xAA55` too). The shim filters on source MAC to distinguish echoed TX from real DAU frames, but if you add new frame types make sure you are not accidentally processing your own transmissions.

**DebugView performance impact.** Even with `Logging=1`, if you add `Log()` calls to hot paths (per-chunk code), `OutputDebugStringW` will slow down `RecvThread` enough to stall transfers. This is the DebugView Heisenbug — see the walkthrough for the full story. The rule is: `Log()` for infrequent events only, `LogFile()` for per-window or per-chunk detail, `Logging=0` for production runs where you do not need a post-mortem log.

**IRP queue overflow on fast machines.** `IRP_QUEUE_DEPTH = 8` was validated on the target hardware. On a significantly faster machine (faster NIC, faster CPU), DAULink.exe may submit ReadFile requests faster than RecvThread can service them. You will see `IRP queue full` in the log. Increasing `IRP_QUEUE_DEPTH` in `packet_shim.h` and rebuilding is the fix — but validate on target hardware afterward.

**`C:\FLS_DOWNLOAD` is created automatically.** `LogInit()` calls `CreateDirectoryW` at startup, so you do not need to create it by hand. If the drive is read-only or you are running without admin rights, the directory creation will fail silently and logging will be disabled for that run — the shim will still function.

**32-bit only.** The DLL must be built as x86. If you accidentally build x64, it will not inject into DAULink.exe and you will get no error message — DAULink.exe will simply behave as if the shim is not there (because it isn't).

---

## Future Work Ideas

- **Automatic adapter detection.** Currently the operator must configure `FriendlyName` manually. The shim could enumerate all Npcap-visible adapters and pick the one that receives the first EtherType `0xAA55` frame automatically, with fallback to the INI config.
- **Multi-DAU support.** `MAX_ADP = 4` slots exist but the adapter-selection logic currently maps all of them to the single configured NIC. Supporting distinct DAU MAC addresses per slot would allow multiple DAUs to be polled from a single host.
- **Live telemetry latency tuning.** The 50 ms auto NEXT-WIN timer for LIVE-DATA bursts was set conservatively. On a dedicated Ethernet segment the latency could be tuned lower (10–20 ms) for better live-view responsiveness.
- **Log rotation.** Currently each run creates a new timestamped file and old files accumulate. A simple log count limit (e.g. keep the last 10) would prevent the log directory from growing unbounded.
- **Installer.** A small MSI or PowerShell script that copies the DLL, creates `C:\FLS_DOWNLOAD`, writes the registry key, and validates the Npcap installation would reduce manual deployment steps for field technicians.
