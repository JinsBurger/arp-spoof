#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include "attack_util.hpp"

pthread_mutex_t pcap_send_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t pcap_recv_mutex = PTHREAD_MUTEX_INITIALIZER;

int safe_send_packet(pcap_t *handle, u_char *packet, uint32_t size) {
     pthread_mutex_lock(&pcap_send_mutex);
	int res = pcap_sendpacket(handle, packet, size);
    pthread_mutex_unlock(&pcap_send_mutex);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
	}
    return 0;
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

    ERR_CHK (
        safe_send_packet,
        (handle, reinterpret_cast<u_char*>(&packet), sizeof(EthArpPacket)),
        return -1;
    )

    return 0;
}

int read_packet(pcap_t *handle, pcap_pkthdr **out_header, u_char** out_pkt) {
    int res;
    pcap_pkthdr *tmp_out_header;
    const u_char *tmp_out_pkt;

    pthread_mutex_lock(&pcap_recv_mutex);
    res = pcap_next_ex(handle, &tmp_out_header, &tmp_out_pkt);

    if (res == 0 || res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
        res = -1;
    } else {
        *out_header = (pcap_pkthdr*)malloc(sizeof(pcap_pkthdr));
        memcpy(*out_header, tmp_out_header, sizeof(pcap_pkthdr));

        *out_pkt = (u_char*)malloc(tmp_out_header->caplen);
        memcpy(*out_pkt, tmp_out_pkt, tmp_out_header->caplen);
        res = 0;
    }

    pthread_mutex_unlock(&pcap_recv_mutex);
    return res;
}


int get_mac_by_ip(pcap_t *handle, Mac my_mac, Ip my_ip, Ip sender_ip, Mac *out) {
    Mac sender_mac;
    struct ArpHdr *arpHdr;
    pcap_pkthdr* header = NULL;
    u_char* pkt = NULL;
    const int MAX_TRY = 5;
    const int MAX_TIME = 4; // secs
    int return_code = -1;

    int start;
    int res;

    for(int i=0; i < MAX_TRY; i++) {
        ERR_CHK( 
                send_arp_packet,
                (handle,  ArpHdr::Request, Mac("ff:ff:ff:ff:ff:ff"), my_mac, Mac("00:00:00:00:00:00"), my_ip, sender_ip),
                return_code = -1; break;
        )        
        start = time(0);

        while (1) {
            if(time(0) - start > MAX_TIME)
                break;

            ERR_CHK( 
                read_packet,
                (handle, &header, &pkt),
                return_code = -1; break;
            )

            arpHdr = (struct ArpHdr*)(pkt + ETHER_HDR_LEN);
            if( arpHdr->op_ == htons(ArpHdr::Reply) &&
                sender_ip == arpHdr->sip() &&
                my_ip == arpHdr->tip() && my_mac == arpHdr->tmac()
            ) {
                memcpy(reinterpret_cast<uint8_t*>(out), reinterpret_cast<uint8_t*>(&arpHdr->smac_), arpHdr->smac_.SIZE);
                return_code = 0;
                goto fin;
            }

            free((void*)header); header = NULL;
            free((void*)pkt); pkt = NULL;
        }
    }

    fin:
    if(header) free((void*)header);
    if(pkt) free((void*)pkt);

    return return_code;
}
