#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"

// https://web.mit.edu/freebsd/head/sys/net/ethernet.h 
#define	ETHER_ADDR_LEN		6	/* length of an Ethernet address */
#define	ETHER_TYPE_LEN		2	/* length of the Ethernet type field */
#define	ETHER_CRC_LEN		4	/* length of the Ethernet CRC */
#define	ETHER_HDR_LEN		(ETHER_ADDR_LEN*2+ETHER_TYPE_LEN)

typedef struct spoof_th_arg {
    pcap_t *handle;
    Mac my_mac;
    Ip my_ip;
    Ip sender_ip;
    Ip target_ip;
} spoof_th_arg;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)


void * th_spoof_proc(void *arg) {
    spoof_th_arg *spoof_info = (spoof_th_arg*)arg;
    
    return NULL;
}


int send_arp_packet(pcap_t *handle, int arp_op, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip) {
    EthArpPacket packet;

    if(arp_op != ArpHdr::Request && arp_op != ArpHdr::Reply)
        return -1;

	packet.eth_.dmac_ = dmac;
	packet.eth_.smac_ = smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(arp_op);
	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
	}

    return 0;
}


int get_sender_mac(pcap_t *handle, Mac my_mac, Ip my_ip, Ip sender_ip, Ip target_ip, Mac *out) {
    Mac sender_mac;
    struct ArpHdr *arpHdr;
    struct pcap_pkthdr* header;
    const u_char* pkt;

    const int MAX_TRY = 5;
    const int MAX_TIME = 4; // secs

    int start;
    int res;

    for(int i=0; i < MAX_TRY; i++) {
        if(send_arp_packet(handle,  ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), my_mac, Mac("00:00:00:00:00:00"), my_ip, sender_ip) != 0)
            return -1;
        
        start = time(0);
        while (true) {
            if(time(0) - start > MAX_TIME)
                break;
                
            res = pcap_next_ex(handle, &header, &pkt);
            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                break;
            }

            arpHdr = (struct ArpHdr*)(pkt + ETHER_HDR_LEN);

            if( arpHdr->op_ == htons(ArpHdr::Reply) &&
                target_ip == arpHdr->sip() &&
                my_ip == arpHdr->tip_ && my_mac == arpHdr->tmac()
            ) {
                memcpy(reinterpret_cast<uint8_t*>(out), reinterpret_cast<uint8_t*>(&arpHdr->smac_), arpHdr->smac_.SIZE);
                return 0;
            }
        }
    }
    return -1;
}