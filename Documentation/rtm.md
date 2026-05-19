# Requirements Traceability Matrix (RTM)

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

This matrix traces every requirement in the SRS to its implementation in `packet_shim.c`. Status reflects verification on live hardware (three successful transfers, checksums confirmed).

| Req ID | Description | Component | Implementation in `packet_shim.c` | Status |
|:---|:---|:---|:---|:---|
| **FR-01.1** | Hook `CreateFileW` | IAT Hook Engine | `Hook_CreateFileW` | Implemented & Verified |
| **FR-01.2** | Hook `CloseHandle` | IAT Hook Engine | `Hook_CloseHandle` | Implemented & Verified |
| **FR-01.3** | Hook `DeviceIoControl` | IAT Hook Engine | `Hook_DeviceIoControl` | Implemented & Verified |
| **FR-01.4** | Hook `ReadFile` / `WriteFile` | IAT Hook Engine | `Hook_ReadFile`, `Hook_WriteFile` | Implemented & Verified |
| **FR-01.5** | Hook `OpenServiceW` | IAT Hook Engine | `Hook_OpenServiceW` | Implemented & Verified |
| **FR-01.6** | Hook `ExitWindowsEx` | IAT Hook Engine | `Hook_ExitWindowsEx` | Implemented & Verified |
| **FR-02.1** | IRP queue depth = 8 | Async IRP Queue | `IRP_QUEUE_DEPTH = 8`; `AdpEntry.irpQueue[8]` | Implemented & Verified |
| **FR-02.2** | Return `ERROR_IO_PENDING` | `Hook_ReadFile` | `lpOv->Internal = STATUS_PENDING; SetLastError(ERROR_IO_PENDING);` | Implemented & Verified |
| **FR-02.3** | Fulfil IRP from RecvThread | `RecvThread` | Pop `irpQueue` head, `memcpy` frame, signal `ov->hEvent` | Implemented & Verified |
| **FR-02.4** | Set `lpNumberOfBytesRead` on fulfil | `RecvThread` | `*req.pBytesRead = frameLen;` | Implemented & Verified |
| **FR-03.1** | Adapter list on IOCTL 0x8000000C | Adapter Manager | `Hook_DeviceIoControl` IOCTL dispatch | Implemented & Verified |
| **FR-03.2** | Fake handle namespace | Adapter Manager | `FAKE_CONTROL_HANDLE`, `FAKE_MAC_HANDLE`, `FAKE_ADP_BASE` constants | Implemented & Verified |
| **FR-03.3** | `MAX_ADP = 4` adapter slots | Adapter Manager | `g_adp[MAX_ADP]` global array | Implemented & Verified |
| **FR-03.4** | MAC query on IOCTL 0x170002 | Adapter Manager | `Hook_DeviceIoControl` IOCTL dispatch | Implemented & Verified |
| **FR-04.1** | `pcap_open_live` with EtherType filter | Npcap Integration | BPF filter `ether proto 0xAA55` set on open | Implemented & Verified |
| **FR-04.2** | `pcap_setmintocopy(1)` | Npcap Integration | Called immediately after `pcap_open_live` succeeds | Implemented & Verified |
| **FR-04.3** | `pcap_sendpacket` for outbound frames | `Hook_WriteFile` | Direct call after spurious-drop check passes | Implemented & Verified |
| **FR-05.1** | Track `windowMinSeq` / `windowMaxSeq` | `RecvThread` | Updated on each FILE-CHUNK (`02 01`) received | Implemented & Verified |
| **FR-05.2** | Patch FILE-ACK bytes `[24..25]` | `RecvThread` | `count = maxSeq - minSeq + 1; wpkt[24..25] = count;` | Implemented & Verified |
| **FR-06.1** | Set `retxPending` on RETRANSMIT NEXT-WIN | `Hook_WriteFile` | `if (missing > 0) { a->retxPending = 1; a->retxWindow = win; }` | Implemented & Verified |
| **FR-06.2** | Defer FILE-ACK for window > retxWindow | `RecvThread` | `memcpy(a->deferredFrame, pkt, len); a->deferredPending = 1;` | Implemented & Verified |
| **FR-06.3** | Deliver deferred frame after confirm | `RecvThread` | On `ackWindow == retxWindow`: clear `retxPending`, deliver, then deliver `deferredFrame` on next IRP | Implemented & Verified |
| **FR-07.1** | Drop spurious COMPLETE NEXT-WIN | `Hook_WriteFile` | `if (a->retxPending && win <= a->retxWindow && missing == 0) return TRUE;` (frame discarded) | Implemented & Verified |
| **FR-08.1** | Learn `dauMac` from first received frame | `RecvThread` | `memcpy(a->dauMac, pkt+6, 6)` on first frame | Implemented & Verified |
| **FR-08.2** | Use `dauMac` in auto-sent frames | `RecvThread` | Auto NEXT-WIN destination set from `a->dauMac` | Implemented & Verified |
| **FR-08.3** | Auto NEXT-WIN after 50 ms LIVE-DATA silence | `RecvThread` | 50 ms timer via `WaitForSingleObject` on `liveDataPendingNextWin` flag | Implemented & Verified |
| **FR-09.1** | TestMode synthetic frame generation | `RecvThread` / init | Enabled when `g_TestMode = 1` (from `TestMode=1` in INI) | Implemented & Verified |
| **NFR-01.2** | `Logging=0` → zero overhead | Logging | `g_LogEnabled` check at top of `Log()` and `LogFile()` — early return, no I/O | Implemented & Verified |
| **NFR-01.3** | `Logging=1` → file + DebugView split | Logging | `LogFile()` writes to `g_hLogFile` only; `Log()` writes file + `OutputDebugStringW` | Implemented & Verified |
| **NFR-02.1** | O(1) hot-path processing | Architecture | Circular buffer arithmetic only; no loops over unbounded data in `RecvThread` | Implemented & Verified |
| **NFR-02.2** | ~2.4 MB/s sustained throughput | System | Confirmed: 285 MB/124 s, 376 MB/156 s, 29 MB/12 s — all checksums match | Verified on live HW |
| **NFR-03.1** | Read config from `fls30_shim.ini` | Init | `GetPrivateProfileIntW` / `GetPrivateProfileStringW` in `ShimInit` | Implemented & Verified |
| **NFR-03.2** | INI keys: `AdapterGUID`, `FriendlyName`, `TestMode`, `Logging` | Init | All four keys read during `ShimInit` | Implemented & Verified |
| **NFR-04.1** | Built as 32-bit (x86) DLL | Build | `/arch:IA32` (or Platform=Win32) in project settings | Implemented & Verified |

---

## Verification Notes

**Transfer verification:** All three live-hardware transfers completed without DebugView attached (which would have reintroduced the Heisenbug). Checksums were verified against reference files from the Windows 7 machine.

**Logging=0 verification:** Confirmed by running a transfer with `Logging=0` in INI and observing that `C:\FLS_DOWNLOAD` contains no new log file and Process Monitor shows no file I/O from the shim during transfer.

**RetxWait verification:** Confirmed by observing the RetxTrack/RetxWait lines in the log file during transfers that included retransmit events, and verifying the transfers completed successfully rather than stalling.
