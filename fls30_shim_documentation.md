# Software Design Document: FLS30 Packet Shim

## 1. Introduction

### 1.1 Purpose
The **FLS30 Packet Shim** (`packet_shim.dll`) is a compatibility layer designed to allow the legacy 32-bit Borland Delphi FLS30 ground-station software to run on modern Windows operating systems (specifically Windows 11). 

### 1.2 Problem Statement
FLS30 communicates with a physical Data Acquisition Unit (DAU) using raw Ethernet frames (EtherType `0xAA55`). Originally, it relied on a custom NDIS 5.x kernel driver (`packet.sys`) via standard Win32 I/O calls (`CreateFile` to `\\.\Packet`, `ReadFile`, `WriteFile`, `DeviceIoControl`). 
Because NDIS 5.x drivers are no longer supported on Windows 11, FLS30 fails to communicate with the DAU. Furthermore, a critical bug in FLS30's internal protocol state machine causes downloads to stall indefinitely if network drivers zero-pad minimum-length Ethernet frames.

### 1.3 Solution
The shim operates entirely in user-space. It injects into `FLS30.exe`, hooks its Win32 I/O calls, and routes the raw network traffic through the modern **Npcap** library (`wpcap.dll`). It also implements a protocol-aware fix to actively patch incoming frames, resolving the download stall bug without modifying the original FLS30 binary.

---

## 2. System Architecture

### 2.1 High-Level Flow
1. **Application Layer (FLS30)**: Makes standard `CreateFile`, `ReadFile`, `WriteFile`, and `DeviceIoControl` calls aimed at the legacy driver.
2. **Shim Layer (`packet_shim.dll`)**: Intercepts these calls via Import Address Table (IAT) hooking.
3. **Network Layer (Npcap)**: The shim translates the Win32 I/O requests into `pcap_open_live`, `pcap_sendpacket`, and `pcap_next_ex` calls to interface with the physical network adapter.

### 2.2 IAT Hooking
The shim overrides specific kernel32.dll functions in FLS30's Import Address Table:
* **`Hook_CreateFileW`**: Intercepts attempts to open `\\.\Packet` or the DAU adapter. Returns custom "fake" handles (`FAKE_CONTROL_HANDLE`, `FAKE_MAC_HANDLE`, or an adapter slot handle like `FAKE_ADP_BASE`).
* **`Hook_DeviceIoControl`**: Emulates legacy NDIS IOCTLs (e.g., `IOCTL_ENUM_ADAPTERS` to list adapters, `IOCTL_GET_MAC` to return the NIC's MAC address).
* **`Hook_WriteFile`**: Intercepts outbound raw frames and passes them to `pcap_sendpacket`.
* **`Hook_ReadFile`**: Intercepts incoming read requests. Since FLS30 uses Overlapped (asynchronous) I/O, the shim queues the request and signals a background thread.
* **`Hook_CloseHandle`**: Properly cleans up pcap handles and terminates background threads.

---

## 3. Core Components and Threading Model

### 3.1 The `AdpEntry` Structure
Each opened network adapter is managed by an `AdpEntry` slot.
```c
typedef struct {
    BOOL         inUse;
    pcap_t      *pcap;          // The Npcap handle
    
    // Async I/O State
    HANDLE       thread;        // Background thread for this adapter
    volatile BOOL stopThread;
    HANDLE       startEvt;      // Event signaled when FLS30 posts a ReadFile
    LPVOID       recvBuf;       // Pointer to FLS30's read buffer
    DWORD        recvBufSz;     // Size of FLS30's read buffer
    LPOVERLAPPED recvOv;        // Overlapped structure to signal completion
    
    // Protocol State
    DWORD        windowMinSeq;  // Lowest sequence number in current burst
    DWORD        windowMaxSeq;  // Highest sequence number in current burst
} AdpEntry;
```

### 3.2 Threading Model (Async Read Emulation)
Because `pcap_next_ex` is a blocking/polling call, but FLS30 expects asynchronous `ReadFile` semantics, the shim isolates receive operations into dedicated background threads:
1. **Setup**: When FLS30 opens the adapter, a dedicated `RecvThread` is spawned for that specific `AdpEntry`.
2. **Request**: FLS30 calls `ReadFile`. `Hook_ReadFile` saves the buffer pointers into `AdpEntry`, sets `startEvt`, and returns `ERROR_IO_PENDING`.
3. **Execution**: The `RecvThread` wakes up, loops over `pcap_next_ex` until a valid frame arrives, copies the frame into `recvBuf`, and signals the Overlapped event.
4. **Thread Safety**: Because each `AdpEntry` has exactly *one* `RecvThread` processing incoming frames sequentially, variables like `windowMinSeq` and `windowMaxSeq` require no mutexes or atomic operations, preventing multi-adapter concurrency bugs.

---

## 4. Protocol Specifics and Active Fixes

### 4.1 The Ethernet Padding Bug (The Stall)
**Symptom**: File downloads from the DAU start, but freeze indefinitely after the first chunk burst (window boundary).
**Root Cause**: 
* The DAU sends a `02 02` (`FILE-ACK`) window boundary frame.
* The DAU's payload is extremely short. Standard Ethernet NICs pad short frames to a minimum of 60 bytes with zeros.
* FLS30's internal function `FUN_004379b8` reads the "expected window chunk count" from byte offset 20 of the `02 02` frame. 
* Because of the zero-padding, FLS30 reads `0`. It skips verifying the chunks, falsely marks the download as complete, and fails to send the `NEXT-WIN` (`TX 02 04`) frame to continue the transfer.

### 4.2 The Sequence Patch Fix
To fix the stall without modifying `FLS30.exe`, the shim actively patches the incoming `02 02` frames on the fly.
1. **Observation**: During a window burst, the DAU sends `02 01` (`FILE-CHUNK`) frames. Each contains a 32-bit sequence number at byte offset 16.
2. **Tracking**: The `RecvThread` continuously updates `windowMinSeq` and `windowMaxSeq` as chunks arrive.
3. **Patching**: When the `02 02` frame arrives, the shim calculates the expected chunk count:
   `ExpectedCount = (windowMaxSeq - windowMinSeq) + 1`
4. **Injection**: The shim safely bounds-checks the frame length. If byte offset 20 is `0`, it injects `ExpectedCount` into bytes 20 and 21 before delivering the frame to FLS30.

**Why sequence tracking?**
Simply counting the number of received `02 01` frames is dangerous. If the network drops a packet in the middle of a burst, a simple frame counter would under-report the expected count. FLS30 would check a smaller window, silently ignore the dropped packet, and corrupt the downloaded file. By using the *highest sequence number*, the shim ensures FLS30 will correctly notice the gap and request a packet retry, preserving data integrity.

---

## 5. Security and Stability Features

* **Buffer Overflow Prevention**: The shim bounds-checks incoming Ethernet frame lengths before copying them into the local `patchBuf` array (`if (hdr->caplen > sizeof(patchBuf))`), protecting against stack overflows from jumbo frames or LRO offloading.
* **TX Loopback Guard**: Npcap's promiscuous mode echoes outbound packets back to the receiver. The shim applies a BPF filter (`not ether src <MAC>`) and includes a secondary software guard in `RecvThread` to silently drop frames originating from the host's own MAC address, preventing the FLS30 state machine from processing its own echoes.
* **Test Mode**: The shim includes an INI-configurable `TestMode` that generates synthetic `03 03` live-data frames and responds to `01 01` pings. This allows GUI testing and state-machine verification without physical DAU hardware.

## 6. Future Maintenance
* **Npcap Dependency**: The shim requires `wpcap.dll` to be present on the system. If Npcap updates its architecture, the dynamic loading logic in `ShimInit` may need path adjustments.
* **Multi-DAU Support**: The `AdpEntry` array (`MAX_ADP = 4`) fully supports FLS30 opening multiple DAU instances simultaneously. Ensure that any future state-tracking additions are placed inside `AdpEntry` rather than global variables to maintain thread safety.
