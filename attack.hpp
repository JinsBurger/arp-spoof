#ifndef _ATTACK_H_
#define _ATTACK_H_

#include <pcap.h>
#include <netdb.h>
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

void initialize_spoof();
void *spoof_proc_th(void *arg);
int get_sender_mac(pcap_t*, Mac, Ip, Ip, Ip, Mac);

int send_arp_packet(pcap_t *handle, int arp_op, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip);
int get_mac_from_ip(pcap_t *handle, Mac my_mac, Ip my_ip, Ip sender_ip, Ip target_ip, Mac *out);

#endif