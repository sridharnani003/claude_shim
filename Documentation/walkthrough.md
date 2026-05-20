# Project Walkthrough: packet_shim

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

## What Is This?

`packet_shim.dll` is a 32-bit Windows DLL that makes a legacy closed-source ground station application (DAULink.exe) work on Windows 11. DAULink.exe communicates with a physical Data Acquisition Unit (DAU) over raw Ethernet using EtherType `0xAA55`. On Windows 7 it worked fine. On Windows 11 the kernel driver it relied on does not load, so it fails immediately on startup.

The shim injects into DAULink.exe's process and patches its import address table so that every network-related Win32 call is silently redirected into the shim. The shim implements the full DAU protocol in user-space using Npcap. The application never knows anything has changed.

**Current status:** working on live hardware. Three complete transfers verified — 285 MB, 376 MB, and 29 MB — all with checksums matching the Windows 7 reference, all at roughly the same throughput (~2.4 MB/s).

---

## Documentation Map

Start here, then read in this order:

| Document | What you will get out of it |
|---|---|
| [Requirements](requirements.md) | Why the project exists, how the protocol was discovered, and the three failure modes that must be handled |
| [SRS](srs.md) | The formal requirement list — what the shim must do |
| [SDD](sdd.md) | How it is designed: structs, threads, state machine, logging |
| [SSD](ssd.md) | Sequence diagrams for the normal flow, the retransmit flow, and the logging architecture |
| [RTM](rtm.md) | Every requirement mapped to its implementation |
| [CONTRIBUTING](CONTRIBUTING.md) | How to build, deploy, debug, and extend the shim |

---

## How the Protocol Was Discovered

There was no need to look inside the DAULink.exe binary. The DAU hardware was connected to a Windows 7 reference machine where everything worked, and two tools ran simultaneously:

**Wireshark** captured every Ethernet frame with an `eth.type == 0xAA55` display filter. This gave full visibility into every frame the DAU and the application exchanged: frame types, payloads, sequence numbers, and timing.

**API Monitor** traced every Win32 call made by DAULink.exe — `CreateFileW`, `ReadFile`, `WriteFile`, `DeviceIoControl`, `CloseHandle`, `OpenServiceW` — with full parameter dumps and timestamps.

Cross-referencing the two captures was the key step. Each `WriteFile` on the data handle corresponded to a frame appearing on the wire moments later; each `ReadFile` completion matched a frame that had just been received. Working through the logs systematically — matching buffer contents and timestamps — revealed the complete frame layout, the state machine, the IRP pipeline depth, and the timing constraints. The protocol is entirely observable at the network level. Nothing about the binary was needed.

---

## The Three Problems (and How They Were Fixed)

### Problem 1: Application stalls without sending NEXT-WIN

After receiving a window's worth of FILE-CHUNK data, the application reads a field from the FILE-ACK frame to decide whether the window is complete. Early captures showed the application sometimes concluded the window was complete immediately and never sent NEXT-WIN — leaving the DAU waiting indefinitely.

Through careful frame-by-frame analysis we confirmed that byte field `[20..21]` in the FILE-ACK frame (initially suspected to be the chunk count) is actually a fixed protocol constant. The real chunk count is at `[24..25]` and the DAU populates it correctly. The actual stall trigger turned out to be the retransmit race described in Problem 2, not a zero-count field.

The FILE-CHUNK sequence numbers are still tracked (`windowMinSeq` / `windowMaxSeq`) and the expected count is logged at each window boundary. This is useful for spotting dropped chunks during post-analysis, even though no frame patching is done.

### Problem 2: Spurious COMPLETE NEXT-WIN

When DAULink.exe detects missing chunks, it sends RETRANSMIT NEXT-WIN (`missing > 0`). A few milliseconds later, its async processing loop for the previous window completes and sends a COMPLETE NEXT-WIN (`missing = 0`) for that window. The DAU receives the COMPLETE while still preparing the retransmit and abandons it. Transfer stalls.

**Fix (RetxWait):** when RETRANSMIT NEXT-WIN is seen, set `retxPending` and record `retxWindow`. While `retxPending` is active, silently drop any COMPLETE NEXT-WIN for a window ≤ `retxWindow` — return success to the application but never put the frame on the wire. Clear `retxPending` when the confirming FILE-ACK arrives.

### Problem 3: FILE-ACK for W+N arrives before W is confirmed

After a retransmit, the DAU may send FILE-ACK for the next window (W+N) before the confirming FILE-ACK for W reaches the application. Delivering W+N first confuses the state machine.

**Fix (deferred delivery):** while `retxPending` is active, stash FILE-ACKs for windows > `retxWindow` in a 1514-byte deferred buffer. Deliver them only after the confirming FILE-ACK for `retxWindow` has been processed.

---

## Lessons Learned

### The DebugView Heisenbug

During early testing, transfers would stall intermittently but only when DebugView was open. Without DebugView, the same transfer completed cleanly every time. This is a classic Heisenbug caused by observer interference.

`OutputDebugStringW` acquires a global kernel mutex each time it is called. Under high-throughput conditions (hundreds of FILE-CHUNK frames per second), calling it on every frame was blocking `RecvThread` for long enough that Npcap's receive buffer would overflow and frames would be dropped — the exact failure the shim was designed to prevent.

The fix was the two-tier logging split: `LogFile()` writes to a file only (fast, no kernel mutex) and is safe to call frequently. `Log()` calls both the file and DebugView and is reserved for infrequent events like state transitions and errors. `Logging=0` in the INI disables both completely.

All three verified transfers were done with `Logging=1` but DebugView not running, so the file logging was active but the DebugView path was never exercised. This confirmed the fix — the file-only path does not cause the stall.

### RetxWait Was the Last Piece

The spurious COMPLETE drop (problem 2) was identified and fixed first. After that, occasional stalls still occurred on transfers with multiple retransmit events. The log file (once it existed and was readable) showed the pattern: FILE-ACK for W+N was arriving and being delivered while the application was still expecting the confirming FILE-ACK for W. Adding the deferred delivery logic (problem 3) eliminated those remaining stalls. The three verified transfers all included retransmit events and all completed cleanly.
