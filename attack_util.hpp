
#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>

extern pthread_mutex_t pcap_handle_mutex;

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

    pthread_mutex_lock(&pcap_handle_mutex);
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    pthread_mutex_unlock(&pcap_handle_mutex);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return -1;
	}

    return 0;
}


int get_mac_from_ip(pcap_t *handle, Mac my_mac, Ip my_ip, Ip sender_ip, Ip target_ip, Mac *out) {
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

            pthread_mutex_lock(&pcap_handle_mutex);
            res = pcap_next_ex(handle, &header, &pkt);
            pthread_mutex_unlock(&pcap_handle_mutex);

            if (res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
               // printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
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
