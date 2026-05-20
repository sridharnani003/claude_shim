# Software Requirements Document (SRD)

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

## 1. Introduction

### 1.1 Purpose

This document explains why `packet_shim.dll` exists, what problem it solves, and what it must do to solve it correctly. It covers the background of the failure, how the protocol was analysed, the specific failure modes that were found, and the requirements that the shim must satisfy.

### 1.2 Scope

The scope is limited to the network communication layer between the host machine running DAULink.exe and the physical DAU hardware. The goal is to restore reliable, full-speed file transfer on Windows 11 without modifying DAULink.exe or the DAU firmware.

---

## 2. Problem Statement

### 2.1 Why DAULink.exe stopped working on Windows 11

DAULink.exe was written for Windows 7. To communicate with the DAU over raw Ethernet it relied on a companion kernel driver that registered with NDIS 5.x, created named device objects (`\Device\Packet` and `\Device\Packet_<adapter>`), and exposed IOCTLs for adapter enumeration, MAC address queries, and raw frame send/receive.

NDIS 5.x protocol driver support was removed from Windows starting with Windows 8. On Windows 11, the driver fails to load entirely — the SCM reports it as started but no device objects are created. DAULink.exe calls `CreateFileW(L"\\.\Packet")`, gets `ERROR_FILE_NOT_FOUND`, and exits with an error before any communication can take place.

The modern equivalent is Npcap: it provides the same raw Ethernet capture and injection capability, is actively maintained, and works on Windows 10 and 11. The problem is that DAULink.exe is closed source and hardcoded to the old Win32 call sequence. The shim bridges this gap by intercepting those calls inside the application's own process and routing them through Npcap.

### 2.2 How the protocol was discovered

There was no need to look inside the DAULink.exe binary. The analysis was done entirely with live traffic capture on a Windows 7 reference machine where the hardware worked correctly.

Two tools ran simultaneously:

- **Wireshark** with an `eth.type == 0xAA55` display filter captured every Ethernet frame between DAULink.exe and the DAU — frame type, payload, timing, and sequence.
- **API Monitor** traced every Win32 call made by DAULink.exe — `CreateFileW`, `ReadFile`, `WriteFile`, `DeviceIoControl`, `CloseHandle`, `OpenServiceW` — with full parameter and buffer dumps and timestamps.

Cross-referencing the two captures was straightforward. Each `WriteFile` on the data handle corresponded directly to a frame appearing on the wire. Each `ReadFile` completion matched a frame that had just been received. Working through the logs systematically revealed the complete frame layout, the state machine the application follows, and the timing constraints between request and response. No binary analysis was needed; the protocol was entirely visible at the network level.

---

## 3. Failure Modes

Three distinct failure modes were identified through traffic capture analysis. All three were first observed on the Windows 7 reference machine and then confirmed by reproducing each one with a naive Npcap passthrough on Windows 11.

### 3.1 Zero-padded FILE-ACK chunk count

**Observed behaviour:** The DAU sends a FILE-ACK frame (type `02 02`) at the end of each transfer window. The frame payload is short — well under the Ethernet minimum of 60 bytes — so the NIC zero-pads the frame before delivery. The chunk count field sits at bytes `[24..25]` (little-endian) in the payload. Because this field falls in the zero-padded region, it always arrives as zero.

DAULink.exe reads the chunk count from this field and uses it to decide whether the window is complete. A count of zero means "zero chunks in this window, nothing to acknowledge." The application idles waiting for something that never arrives. The transfer stalls permanently.

**Required fix:** Track the sequence numbers of FILE-CHUNK frames (`02 01`) received during each window. At window boundary, compute the correct count as `(windowMaxSeq - windowMinSeq + 1)` and write it into bytes `[24..25]` of the FILE-ACK before delivering it to the application.

### 3.2 Spurious COMPLETE NEXT-WIN during retransmit

**Observed behaviour:** When DAULink.exe detects missing chunks it sends a RETRANSMIT NEXT-WIN (`02 04`, `missing > 0`) asking the DAU to resend them. Almost immediately afterward — before the DAU can respond — the application's async processing loop for the previous window completes and issues a COMPLETE NEXT-WIN (`02 04`, `missing = 0`). This COMPLETE reaches the DAU while it is still preparing the retransmit. The DAU interprets COMPLETE as "all done, advance" and abandons the retransmit. The application then waits indefinitely for chunks that will never arrive.

**Required fix:** When RETRANSMIT NEXT-WIN is seen, record the window number (`retxWindow`) and set a `retxPending` flag. Any subsequent COMPLETE NEXT-WIN for a window ≤ `retxWindow` that arrives while `retxPending` is set must be silently dropped — never forwarded to the wire. The flag is cleared only when the DAU's confirming FILE-ACK for `retxWindow` is received.

### 3.3 Out-of-order FILE-ACK delivery during retransmit

**Observed behaviour:** After RETRANSMIT NEXT-WIN for window W, the DAU resends the missing chunks for W and sends a confirming FILE-ACK for W. However — because modern OS scheduling is faster than Windows 7's — the DAU may also send a FILE-ACK for window W+N before the application has finished processing the confirming FILE-ACK for W. Delivering W+N first puts the application's state machine into an inconsistent state and causes the transfer to fail.

**Required fix:** While `retxPending` is set, any FILE-ACK for a window greater than `retxWindow` must be stashed in a deferred buffer (`deferredFrame`, 1514 bytes) and withheld. When the confirming FILE-ACK for W subsequently arrives, deliver W to the application, clear `retxPending`, then deliver the deferred frame on the next available IRP.

---

## 4. Derived Requirements

### 4.1 Functional Requirements

| ID | Requirement |
|---|---|
| FR-01 | The shim shall intercept DAULink.exe's Win32 calls to the legacy packet driver interface at runtime without modifying the DAULink.exe binary on disk. |
| FR-02 | The shim shall open the physical NIC identified by `fls30_shim.ini` using Npcap and filter received frames to EtherType `0xAA55`. |
| FR-03 | The shim shall present fake device handles (`\\.\Packet`, `\\.\Packet_<name>`) matching the handle namespace DAULink.exe expects. |
| FR-04 | The shim shall reconstruct the correct FILE-ACK chunk count from observed FILE-CHUNK sequence numbers and patch bytes `[24..25]` of every FILE-ACK before delivery. |
| FR-05 | The shim shall detect RETRANSMIT NEXT-WIN, set `retxPending`, and silently drop COMPLETE NEXT-WIN frames for windows ≤ `retxWindow` while `retxPending` is active. |
| FR-06 | The shim shall stash FILE-ACK frames for windows > `retxWindow` in a deferred buffer while `retxPending` is active, and deliver them in order after the confirming FILE-ACK is received. |
| FR-07 | The shim shall support up to `MAX_ADP = 4` simultaneous adapters. |
| FR-08 | The shim shall implement an 8-slot async IRP queue per adapter, returning `ERROR_IO_PENDING` immediately and fulfilling requests from a background receive thread. |
| FR-09 | The shim shall learn the DAU MAC address from the source MAC of the first received frame and use it as the destination for auto-sent NEXT-WIN frames. |
| FR-10 | The shim shall auto-send NEXT-WIN if a LIVE-DATA burst ends and DAULink.exe has not sent NEXT-WIN within 50 ms. |
| FR-11 | The shim shall support `TestMode=1` in `fls30_shim.ini` to generate synthetic DAU frames for protocol testing without hardware. |

### 4.2 Non-Functional Requirements

| ID | Requirement |
|---|---|
| NFR-01 | When `Logging=0`, the shim shall introduce zero logging overhead — no file I/O, no DebugView output, nothing. |
| NFR-02 | When `Logging=1`, per-window events shall be written to `C:\FLS_DOWNLOAD\shim_YYYYMMDD-HHMMSS.log`; critical events shall also appear in DebugView via `OutputDebugStringW`. |
| NFR-03 | Sustained throughput shall match the Windows 7 reference (~2.4 MB/s for large transfers). |
| NFR-04 | The DLL shall be built as a 32-bit (x86) module to match DAULink.exe's process architecture. |
| NFR-05 | The shim shall call `pcap_setmintocopy(1)` on each opened Npcap handle so the receive thread wakes immediately on each arriving packet. |
