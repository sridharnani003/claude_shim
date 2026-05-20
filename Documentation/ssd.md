# System Sequence Diagrams (SSD)

**Project:** packet_shim — Npcap shim for DAULink.exe  
**Revision:** 2.0  
**Date:** 2026-05-19

---

The following diagrams show the interaction between DAULink.exe, the injected PacketShim, and the DAU hardware across three scenarios.

---

## 1. Normal File Transfer Flow

The "happy path" — data is requested and acknowledged without packet loss or timing anomalies. The chunk count reconstruction (FR-05) fires silently on every FILE-ACK but is not highlighted here because it is transparent to the participants.

```mermaid
sequenceDiagram
    participant App as DAULink.exe
    participant Shim as PacketShim (DLL)
    participant Npcap as Npcap Driver
    participant DAU as DAU Hardware

    App->>Shim: WriteFile (NEXT-WIN W, missing=0)
    Note over Shim: Parse: NEXT-WIN complete. No retxPending. Forward.
    Shim->>Npcap: pcap_sendpacket
    Npcap->>DAU: [Ethernet] NEXT-WIN W

    DAU-->>Npcap: [Ethernet] FILE-CHUNK W×N
    Npcap-->>Shim: pcap_next_ex (chunks)
    Note over Shim: Track windowMinSeq / windowMaxSeq
    App->>Shim: ReadFile (OVERLAPPED)
    Shim-->>App: Deliver FILE-CHUNK (fulfil IRP)

    DAU-->>Npcap: [Ethernet] FILE-ACK W
    Npcap-->>Shim: pcap_next_ex
    Note over Shim: Reconstruct chunk count → patch [24..25]. No retxPending. Deliver.
    App->>Shim: ReadFile (OVERLAPPED)
    Shim-->>App: Deliver FILE-ACK W (patched count)

    Note over App: State machine advances to W+1
    App->>Shim: WriteFile (NEXT-WIN W+1, missing=0)
```

---

## 2. Retransmit — RetxWait and Spurious COMPLETE Drop

This shows how the shim prevents the race condition where DAULink.exe sends a spurious COMPLETE immediately after a RETRANSMIT, and how it holds a premature FILE-ACK for W+N until the retransmit for W is confirmed.

```mermaid
sequenceDiagram
    participant App as DAULink.exe
    participant Shim as PacketShim (DLL)
    participant DAU as DAU Hardware

    Note over App: Missing chunks detected in window W
    App->>Shim: WriteFile (NEXT-WIN W, missing=N)
    Note over Shim: Set retxPending=1, retxWindow=W. Forward.
    Shim->>DAU: [Ethernet] NEXT-WIN W missing=N

    Note over App: Async loop for W-1 completes — race condition fires
    App->>Shim: WriteFile (NEXT-WIN W-1, missing=0)
    Note over Shim: retxPending=1 AND W-1 ≤ retxWindow.<br/>SPURIOUS COMPLETE → drop silently.
    Shim--xDAU: (frame not sent)

    DAU-->>Shim: [Ethernet] FILE-CHUNK W (retransmitted)
    Shim-->>App: Deliver FILE-CHUNK W (fulfil IRP)

    DAU-->>Shim: [Ethernet] FILE-ACK W+1 (arrives early)
    Note over Shim: retxPending=1 AND W+1 > retxWindow.<br/>DEFER → copy to deferredFrame. Do not deliver yet.
    Shim--xApp: (held in deferredFrame)

    DAU-->>Shim: [Ethernet] FILE-ACK W (confirms retransmit)
    Note over Shim: retxPending=1 AND ackWindow==retxWindow.<br/>Deliver W. Clear retxPending.
    Shim-->>App: Deliver FILE-ACK W

    App->>Shim: ReadFile (OVERLAPPED)
    Note over Shim: retxPending=0, deferredPending=1.<br/>Deliver deferred frame. Clear deferredPending.
    Shim-->>App: Deliver deferred FILE-ACK W+1
```

> **Why this matters:** without the spurious COMPLETE drop, that frame would reach the DAU while it is still preparing the retransmit. The DAU would interpret it as "all done, advance" and abandon the retransmit. DAULink.exe would then wait forever for chunks that will never arrive, resulting in an ABORT.

---

## 3. Logging Architecture

This diagram shows how the two-tier logging system works and when each path is active.

```mermaid
sequenceDiagram
    participant Code as ShimCode (any thread)
    participant LogFile as LogFile()
    participant Log as Log()
    participant File as Log file<br/>(C:\FLS_DOWNLOAD\shim_*.log)
    participant DBV as DebugView<br/>(OutputDebugStringW)

    Note over Code: g_LogEnabled = 0 (Logging=0 in INI)
    Code->>LogFile: LogFile("window %d ACK delivered", w)
    Note over LogFile: g_LogEnabled==0 → no-op, return immediately
    Code->>Log: Log("ERROR: IRP queue full")
    Note over Log: g_LogEnabled==0 → no-op, return immediately

    Note over Code: g_LogEnabled = 1 (Logging=1, the default)
    Code->>LogFile: LogFile("window %d chunk count=%d", w, n)
    LogFile->>File: WriteFile (per-window detail)
    Note over LogFile: DebugView NOT called — file only

    Code->>Log: Log("RetxWait: retxPending set W=%d", w)
    Log->>File: WriteFile (important event)
    Log->>DBV: OutputDebugStringW (important event)
    Note over Log: Both paths active for critical events
```

**Rule of thumb for contributors:** use `LogFile()` for anything that fires on every window or chunk (per-packet detail that you will read from the file after the fact). Use `Log()` only for events that happen once or twice per transfer — state changes, errors, retransmit start/clear. Calling `Log()` on every packet defeats the purpose of the split because `OutputDebugStringW` is slow under load.
