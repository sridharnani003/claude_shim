# Software Requirements Specification (SRS)

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

## 1. Introduction

### 1.1 Purpose

This SRS defines the functional and non-functional requirements for `packet_shim.dll`. It is the definitive statement of what the shim does — not what it was originally planned to do, but what is actually implemented and verified on live hardware.

### 1.2 Product Perspective

`packet_shim.dll` is a 32-bit DLL that injects into DAULink.exe's process via `AppInit_DLLs`. Once loaded it patches DAULink.exe's import address table so that every relevant Win32 call is redirected to the shim. From DAULink.exe's perspective nothing has changed — it still calls `CreateFileW`, `ReadFile`, `WriteFile`, and friends. The shim implements the full protocol stack in user-space using Npcap.

### 1.3 User Classes

- **Field technicians:** Operate DAULink.exe directly. They need transfers to complete reliably without manual intervention.
- **System administrators:** Deploy the shim, configure `fls30_shim.ini`, and interpret the log file when something goes wrong.
- **Developers:** Build, extend, and debug the shim. See `CONTRIBUTING.md`.

---

## 2. Functional Requirements

### FR-01: Win32 API Interception

The shim must redirect DAULink.exe's calls to the legacy packet driver interface.

- **FR-01.1** — Hook `CreateFileW` to intercept opens of `\\.\Packet` (control device) and `\\.\Packet_<name>` (per-adapter data devices). Return fake handles.
- **FR-01.2** — Hook `CloseHandle` to release Npcap sessions and IRP queue resources associated with fake handles.
- **FR-01.3** — Hook `DeviceIoControl` to handle IOCTL `0x8000000C` (adapter enumeration) and IOCTL `0x170002` (MAC address query).
- **FR-01.4** — Hook `ReadFile` and `WriteFile` for raw frame receive and transmit on fake adapter handles.
- **FR-01.5** — Hook `OpenServiceW` to intercept the SCM call for "Packet" and return a fake service handle, preventing DAULink.exe from failing at startup.
- **FR-01.6** — Hook `ExitWindowsEx` to allow the shim to clean up before the application shuts down.

### FR-02: Asynchronous IRP Queue

DAULink.exe submits multiple overlapped `ReadFile` requests simultaneously to keep the pipeline full.

- **FR-02.1** — The shim shall implement a circular IRP queue with exactly **8 slots** per adapter (`IRP_QUEUE_DEPTH = 8`).
- **FR-02.2** — `Hook_ReadFile` shall push each overlapped request onto the queue tail and return `ERROR_IO_PENDING` immediately.
- **FR-02.3** — The background receive thread (`RecvThread`) shall pop requests from the queue head and fulfil them when a matching frame arrives.
- **FR-02.4** — On fulfilling an IRP, `RecvThread` shall copy the frame into the caller's buffer, set `lpNumberOfBytesRead`, and signal `OVERLAPPED.hEvent`.

### FR-03: Adapter Management and Handle Namespace

- **FR-03.1** — On `DeviceIoControl(0x8000000C)`, the shim shall return a list of adapter names derived from the NIC configured in `fls30_shim.ini`.
- **FR-03.2** — Fake handles shall use a well-defined namespace: `FAKE_CONTROL_HANDLE` for `\\.\Packet`, `FAKE_MAC_HANDLE` for MAC-query opens, and `FAKE_ADP_BASE + slot` for data handles.
- **FR-03.3** — The shim shall support up to `MAX_ADP = 4` concurrently open adapter slots.
- **FR-03.4** — On `DeviceIoControl(0x170002)`, the shim shall return the MAC address of the physical NIC. The DAU MAC is learned separately from received frames (FR-09).

### FR-04: EtherType Filtering and Npcap Integration

- **FR-04.1** — The shim shall open the physical NIC using `pcap_open_live` with a BPF filter for EtherType `0xAA55`.
- **FR-04.2** — The shim shall call `pcap_setmintocopy(1)` on each opened handle so `RecvThread` wakes on each individual packet rather than waiting for a buffer fill threshold.
- **FR-04.3** — Raw frames submitted via `Hook_WriteFile` shall be forwarded to the wire using `pcap_sendpacket`.

### FR-05: FILE-ACK Chunk Count Tracking

The DAU populates the chunk count field at bytes `[24..25]` (little-endian) of the FILE-ACK frame. The shim tracks FILE-CHUNK sequence numbers independently as a diagnostic cross-check.

- **FR-05.1** — `RecvThread` shall track the minimum and maximum FILE-CHUNK sequence numbers received within each window (`windowMinSeq`, `windowMaxSeq` per adapter).
- **FR-05.2** — When a FILE-ACK is received, the shim shall compute `expectedCount = windowMaxSeq - windowMinSeq + 1` and log it via `LogFile()` alongside the count the DAU reported. This allows post-analysis to detect any discrepancy between what was sent and what the DAU acknowledged. No frame patching is performed.

### FR-06: RetxWait — Retransmit Deferral

- **FR-06.1** — When `Hook_WriteFile` sees NEXT-WIN with `missing > 0`, it shall set `retxPending = 1` and record `retxWindow`.
- **FR-06.2** — While `retxPending` is active: if a FILE-ACK arrives for a window > `retxWindow`, it shall be copied into `deferredFrame` (1514 bytes) and `deferredPending` set to 1. The frame is not delivered to DAULink.exe yet.
- **FR-06.3** — When the confirming FILE-ACK for `retxWindow` arrives, the shim shall deliver it, clear `retxPending`, and deliver `deferredFrame` on the next available IRP.

### FR-07: Spurious COMPLETE Drop

- **FR-07.1** — While `retxPending` is active: if `Hook_WriteFile` sees NEXT-WIN with `missing = 0` for a window ≤ `retxWindow`, it shall return success to DAULink.exe but silently discard the frame — it is never sent to the wire.

### FR-08: DAU MAC Learning and Auto NEXT-WIN

- **FR-08.1** — `RecvThread` shall record the source MAC of the first EtherType `0xAA55` frame received and store it as `dauMac` per adapter.
- **FR-08.2** — Auto-sent frames (auto NEXT-WIN, TestMode frames) shall use `dauMac` as the Ethernet destination.
- **FR-08.3** — If a LIVE-DATA (`03 03`) burst ends and DAULink.exe has not sent NEXT-WIN within 50 ms, the shim shall construct and transmit a NEXT-WIN frame automatically.

### FR-09: TestMode

- **FR-09.1** — When `TestMode=1` in `fls30_shim.ini`, the shim shall generate synthetic DAU frames internally so the full protocol flow can be exercised without hardware connected.

---

## 3. Non-Functional Requirements

### NFR-01: Logging

- **NFR-01.1** — The logging behaviour is controlled by `Logging=` in the `[Debug]` section of `fls30_shim.ini`.
- **NFR-01.2** — When `Logging=0`, the shim shall produce zero output — no file I/O, no `OutputDebugStringW` calls, no overhead whatsoever.
- **NFR-01.3** — When `Logging=1` (the default), per-window events shall be written to a timestamped log file at `C:\FLS_DOWNLOAD\shim_YYYYMMDD-HHMMSS.log` via `LogFile()`. Critical events (errors, state transitions) shall additionally be sent to DebugView via `Log()`. There is no separate `Verbose` key.

### NFR-02: Performance

- **NFR-02.1** — All hot-path logic in `Hook_WriteFile` and `RecvThread` shall be O(1) — no scanning or sorting of unbounded data.
- **NFR-02.2** — Sustained throughput shall match the Windows 7 reference machine (~2.4 MB/s).

### NFR-03: Configuration

- **NFR-03.1** — Configuration shall be read from `fls30_shim.ini` in the same directory as DAULink.exe.
- **NFR-03.2** — Supported keys: `[Npcap] AdapterGUID`, `[Adapter] FriendlyName`, `[Debug] TestMode`, `[Debug] Logging`.

### NFR-04: Architecture

- **NFR-04.1** — The DLL shall be compiled as 32-bit (x86) to match DAULink.exe's process.
