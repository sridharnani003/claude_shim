/*
 * dau_sim.c  —  Two-PC DAU Simulator for FLS30 testing
 * ======================================================
 * Run this on PC2 connected to PC1 (running FLS30+shim) via LAN cable.
 * It listens for EtherType 0xAA55 frames from FLS30, replies to pings,
 * and sends continuous 0x03 0x03 live-data frames.
 *
 * Build (x86):
 *   cl /nologo /W3 /O2 dau_sim.c /link /MACHINE:X86 /OUT:dau_sim.exe
 *
 * Run as Administrator:
 *   dau_sim.exe
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

/* ── pcap dynamic load ──────────────────────────────────────── */
typedef struct pcap pcap_t;
struct pcap_pkthdr  { unsigned tv_sec, tv_usec, caplen, len; };
struct bpf_program  { unsigned bf_len; void *bf_insns; };

typedef pcap_t*     (*PfnOpen)(const char*,int,int,int,char*);
typedef int         (*PfnSend)(pcap_t*,const unsigned char*,int);
typedef int         (*PfnNext)(pcap_t*,struct pcap_pkthdr**,const unsigned char**);
typedef void        (*PfnClose)(pcap_t*);
typedef const char* (*PfnErr)(pcap_t*);
typedef int         (*PfnCompile)(pcap_t*,struct bpf_program*,const char*,int,unsigned);
typedef int         (*PfnSetFilter)(pcap_t*,struct bpf_program*);
typedef void        (*PfnFreeCode)(struct bpf_program*);
typedef int         (*PfnFindAllDevs)(void**,char*);
typedef void        (*PfnFreeAllDevs)(void*);

/* pcap_if_t minimal layout */
typedef struct pcap_if {
    struct pcap_if *next;
    char           *name;
    char           *description;
    void           *addresses;
    unsigned        flags;
} pcap_if_t;

static PfnOpen        pfOpen;
static PfnSend        pfSend;
static PfnNext        pfNext;
static PfnClose       pfClose;
static PfnErr         pfErr;
static PfnCompile     pfCompile;
static PfnSetFilter   pfSetFilter;
static PfnFreeCode    pfFreeCode;
static PfnFindAllDevs pfFindAllDevs;
static PfnFreeAllDevs pfFreeAllDevs;

/* ── Fake DAU MAC ───────────────────────────────────────────── */
static const unsigned char k_DauMac[6] = {0x00,0xDE,0xAD,0xDA,0x7F,0x00};
static const unsigned char k_Bcast[6]  = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

/* ── Build a minimal 60-byte EtherType 0xAA55 frame ─────────── */
static void BuildFrame(unsigned char *out60,
                       const unsigned char *dst,
                       const unsigned char *src,
                       const unsigned char *payload, int payLen)
{
    memset(out60, 0, 60);
    memcpy(out60,     dst, 6);
    memcpy(out60 + 6, src, 6);
    out60[12] = 0xAA; out60[13] = 0x55;
    if (payLen > 46) payLen = 46;
    memcpy(out60 + 14, payload, payLen);
}

int main(void)
{
    SetDllDirectoryA("C:\\Windows\\SysWOW64\\Npcap");
    HMODULE h = LoadLibraryA("wpcap.dll");
    if (!h) { printf("wpcap.dll load failed: %u\n", GetLastError()); return 1; }

    pfOpen        = (PfnOpen)       GetProcAddress(h, "pcap_open_live");
    pfSend        = (PfnSend)       GetProcAddress(h, "pcap_sendpacket");
    pfNext        = (PfnNext)       GetProcAddress(h, "pcap_next_ex");
    pfClose       = (PfnClose)      GetProcAddress(h, "pcap_close");
    pfErr         = (PfnErr)        GetProcAddress(h, "pcap_geterr");
    pfCompile     = (PfnCompile)    GetProcAddress(h, "pcap_compile");
    pfSetFilter   = (PfnSetFilter)  GetProcAddress(h, "pcap_setfilter");
    pfFreeCode    = (PfnFreeCode)   GetProcAddress(h, "pcap_freecode");
    pfFindAllDevs = (PfnFindAllDevs)GetProcAddress(h, "pcap_findalldevs");
    pfFreeAllDevs = (PfnFreeAllDevs)GetProcAddress(h, "pcap_freealldevs");

    if (!pfOpen || !pfSend || !pfNext) {
        printf("GetProcAddress failed\n"); return 1;
    }

    /* List adapters */
    char errbuf[256] = {0};
    pcap_if_t *devs = NULL;
    pfFindAllDevs((void**)&devs, errbuf);

    printf("\n DAU Simulator — FLS30 Two-PC Test\n");
    printf(" ===================================\n\n");
    printf(" Available adapters:\n");

    int idx = 0;
    for (pcap_if_t *d = devs; d; d = d->next, idx++) {
        printf("   [%d] %s\n       %s\n\n",
               idx, d->name, d->description ? d->description : "(no description)");
    }

    printf(" Enter adapter number to use: ");
    int choice = 0;
    scanf_s("%d", &choice);

    const char *devName = NULL;
    idx = 0;
    for (pcap_if_t *d = devs; d; d = d->next, idx++) {
        if (idx == choice) { devName = d->name; break; }
    }
    if (!devName) { printf("Invalid choice\n"); return 1; }

    printf("\n Opening: %s\n", devName);
    pcap_t *pcap = pfOpen(devName, 65535, 1, 1, errbuf);
    if (!devs) pfFreeAllDevs(devs);
    if (!pcap) { printf("pcap_open_live failed: %s\n", errbuf); return 1; }
    printf(" Opened OK\n");

    /* Filter: only EtherType 0xAA55 */
    if (pfCompile && pfSetFilter && pfFreeCode) {
        struct bpf_program fp = {0};
        if (pfCompile(pcap, &fp, "ether proto 0xaa55", 1, 0) == 0) {
            pfSetFilter(pcap, &fp);
            pfFreeCode(&fp);
            printf(" BPF filter set: ether proto 0xaa55\n");
        }
    }

    printf("\n Simulating DAU — press Ctrl+C to stop\n");
    printf(" Sending 0x03 0x03 data frames at 10 Hz...\n\n");

    DWORD lastData = 0;
    unsigned long frameCount = 0;

    while (1) {
        DWORD now = GetTickCount();

        /* ── Receive and handle incoming frames from FLS30 ───── */
        struct pcap_pkthdr *pkthdr = NULL;
        const unsigned char *pkt   = NULL;
        int r = pfNext(pcap, &pkthdr, &pkt);
        if (r == 1 && pkthdr->caplen >= 16) {
            unsigned char ptype0 = pkt[14];
            unsigned char ptype1 = pkt[15];
            printf(" RX: EtherType=%02X%02X  type=[%02X %02X]  len=%u",
                   pkt[12], pkt[13], ptype0, ptype1, pkthdr->caplen);

            if (ptype0 == 0x01 && ptype1 == 0x01) {
                printf("  <- PING — sending 0x01 0x01 reply");
                /* Reply with 0x01 0x01: dst = FLS30's src MAC */
                unsigned char pay[6] = {0x01,0x01,0x00,0x00,0x00,0x00};
                unsigned char frame[60];
                BuildFrame(frame, pkt + 6, k_DauMac, pay, 6);
                pfSend(pcap, frame, 60);
            }
            printf("\n");
        }

        /* ── Send 0x03 0x03 data frame every 100 ms ──────────── */
        if (now - lastData >= 100) {
            unsigned char pay[46] = {0x03,0x03,0x00,0x00,0x00,0x00};
            /* Put a simple counter in bytes [2..5] for visibility */
            pay[2] = (unsigned char)(frameCount >> 24);
            pay[3] = (unsigned char)(frameCount >> 16);
            pay[4] = (unsigned char)(frameCount >>  8);
            pay[5] = (unsigned char)(frameCount);
            unsigned char frame[60];
            BuildFrame(frame, k_Bcast, k_DauMac, pay, sizeof(pay));
            int sr = pfSend(pcap, frame, 60);
            if (sr != 0)
                printf(" TX ERROR: %s\n", pfErr ? pfErr(pcap) : "?");
            else if (frameCount % 50 == 0)   /* print every 5 sec */
                printf(" TX: 0x03 0x03 frame #%lu\n", frameCount);
            frameCount++;
            lastData = now;
        }

        Sleep(1);
    }

    pfClose(pcap);
    return 0;
}
