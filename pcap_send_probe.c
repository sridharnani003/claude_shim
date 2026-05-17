/*
 * pcap_send_probe.c — test pcap_open_live + pcap_sendpacket on the target NIC
 * Build (x86): cl /nologo /W3 /O2 pcap_send_probe.c /link /MACHINE:X86 /OUT:pcap_send_probe.exe
 * Run as Administrator.
 */
#include <windows.h>
#include <stdio.h>

typedef struct pcap pcap_t;
struct pcap_pkthdr { unsigned tv_sec, tv_usec, caplen, len; };
typedef pcap_t*     (*PfnOpen)(const char*, int, int, int, char*);
typedef int         (*PfnSend)(pcap_t*, const unsigned char*, int);
typedef const char* (*PfnErr)(pcap_t*);
typedef void        (*PfnClose)(pcap_t*);

int main(void)
{
    SetDllDirectoryA("C:\\Windows\\SysWOW64\\Npcap");
    HMODULE h = LoadLibraryA("wpcap.dll");
    if (!h) { printf("wpcap.dll load failed: %u\n", GetLastError()); return 1; }

    PfnOpen  pfOpen  = (PfnOpen) GetProcAddress(h, "pcap_open_live");
    PfnSend  pfSend  = (PfnSend) GetProcAddress(h, "pcap_sendpacket");
    PfnErr   pfErr   = (PfnErr)  GetProcAddress(h, "pcap_geterr");
    PfnClose pfClose = (PfnClose)GetProcAddress(h, "pcap_close");
    if (!pfOpen || !pfSend) { printf("GetProcAddress failed\n"); return 1; }

    /* Adapter GUID from fls30_shim.ini */
    const char *dev = "\\Device\\NPF_{1C08C389-F4FF-4A46-B8AB-9E5768689404}";
    char errbuf[256] = {0};

    printf("Opening: %s\n", dev);
    pcap_t *pcap = pfOpen(dev, 65535, 1, 1, errbuf);
    if (!pcap) { printf("pcap_open_live FAILED: %s\n", errbuf); return 1; }
    printf("pcap_open_live OK\n");

    /* Minimal EtherType 0xAA55 frame (60 bytes) */
    unsigned char frame[60] = {0};
    memset(frame + 0, 0xFF, 6);           /* dst: broadcast */
    frame[6]=0x02; frame[7]=0x00;
    frame[8]=0x46; frame[9]=0x4C;
    frame[10]=0x53; frame[11]=0x30;       /* src: "FLS0" */
    frame[12]=0xAA; frame[13]=0x55;       /* EtherType */
    memset(frame + 14, 0x42, 46);

    int r = pfSend(pcap, frame, sizeof(frame));
    if (r == 0) {
        printf("pcap_sendpacket OK — 60 bytes sent\n");
    } else {
        const char *e = pfErr ? pfErr(pcap) : "?";
        printf("pcap_sendpacket FAILED r=%d: %s\n", r, e);
    }

    pfClose(pcap);
    return (r == 0) ? 0 : 1;
}
