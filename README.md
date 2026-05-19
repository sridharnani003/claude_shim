# packet_shim — Npcap shim for DAULink.exe on Windows 11

## What this is

DAULink.exe is a legacy closed-source ground station application that communicates with a physical Data Acquisition Unit (DAU) over raw Ethernet using EtherType `0xAA55`. On Windows 7 this worked fine because the companion kernel driver it relied on was a functional NDIS 5.x protocol driver. On Windows 11 that driver does not load — NDIS 5.x support is gone — so the application cannot open the network at all. Rather than rewriting the application (which is closed source), this project provides a 32-bit DLL (`packet_shim.dll`) that injects into DAULink.exe's process via `AppInit_DLLs` and patches its import address table at startup. From that point on every network-related Win32 call the application makes is silently redirected into the shim, which implements the full DAU protocol in user-space using Npcap. The kernel driver is never involved.

---

## Quick Start

### Prerequisites

| Requirement | Notes |
|---|---|
| Visual Studio 2022 | With the "Desktop development with C++" workload |
| WDK 11 | Only needed if you also build packet.sys; not required for the DLL |
| Npcap | Install with the "WinPcap API-compatible mode" option checked |
| Test signing | `bcdedit /set testsigning on` then reboot (required if you also install packet.sys) |

### Build

```powershell
# From the repo root
.\build_dll.bat
```

This produces `packet_shim.dll` (x86, Release) in `.\out\`.

### Deploy

1. Copy `packet_shim.dll` to the same folder as `DAULink.exe` (e.g. `C:\FLS30\BIN\`).
2. Copy `fls30_shim.ini` to that same folder and edit `[Adapter] FriendlyName=` to match your NIC's friendly name (visible in Device Manager or `Get-NetAdapter`).
3. Register the shim:
   ```
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs /t REG_SZ /d "C:\FLS30\BIN\packet_shim.dll" /f
   reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v LoadAppInit_DLLs /t REG_DWORD /d 1 /f
   ```
4. Launch DAULink.exe normally.

> **Tip:** If you would rather not touch `AppInit_DLLs`, a small launcher batch file can inject the DLL via `LOAD_WITH_ALTERED_SEARCH_PATH` before starting DAULink.exe. See `Documentation/CONTRIBUTING.md` for details.

---

## INI Configuration (`fls30_shim.ini`)

The file lives next to `DAULink.exe`. All keys are optional; defaults are shown.

| Section | Key | Default | Description |
|---|---|---|---|
| `[Npcap]` | `AdapterGUID` | _(empty)_ | If set, opens this adapter by GUID directly, bypassing name matching |
| `[Adapter]` | `FriendlyName` | _(empty)_ | Windows-friendly NIC name, e.g. `Intel(R) Ethernet Connection (3) I219-LM` |
| `[Debug]` | `TestMode` | `0` | Set to `1` to generate synthetic DAU frames — lets you exercise the protocol without any hardware connected |
| `[Debug]` | `Logging` | `1` | `1` = full logging to timestamped file + important events to DebugView; `0` = zero overhead, completely silent |

Log files are written to `C:\FLS_DOWNLOAD\shim_YYYYMMDD-HHMMSS.log`.

---

## Documentation

All design and protocol documents live in [`Documentation/`](Documentation/walkthrough.md):

| Document | What it covers |
|---|---|
| [Walkthrough](Documentation/walkthrough.md) | Start here — overview, discovery story, lessons learned |
| [Requirements](Documentation/requirements.md) | Why this project exists; failure modes; derived requirements |
| [SRS](Documentation/srs.md) | Functional and non-functional requirements |
| [SDD](Documentation/sdd.md) | Software design: structs, threads, state machine |
| [SSD](Documentation/ssd.md) | Sequence diagrams for key protocol flows |
| [RTM](Documentation/rtm.md) | Requirements traceability matrix |
| [Contributing](Documentation/CONTRIBUTING.md) | How to build, deploy, debug, and extend |

---

## Current Status

The shim is working on live hardware. Three complete transfers have been verified:

| Transfer | Size | Time | Throughput | Result |
|---|---|---|---|---|
| 1 | 285 MB | 124 s | ~2.3 MB/s | Checksum match |
| 2 | 376 MB | 156 s | ~2.4 MB/s | Checksum match |
| 3 | 29 MB | 12 s | ~2.4 MB/s | Checksum match |

All transfers match Windows 7-reference throughput. All checksums verified.
