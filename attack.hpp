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



typedef struct arp_info_st {
    pcap_t *send_handle;
    pcap_t *recv_handle;
    Mac my_mac;
    Mac sender_mac;
    Mac target_mac;
    Ip my_ip;
    Ip sender_ip;
    Ip target_ip;
    
} arp_info_st;


#define LIBNET_LIL_ENDIAN 1
struct custom_libnet_ipv4_hdr
{
#if (LIBNET_LIL_ENDIAN)
    uint8_t ip_hl:4,      /* header length */
           ip_v:4;         /* version */
#endif
#if (LIBNET_BIG_ENDIAN)
    uint8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
#endif
    uint8_t ip_tos;       /* type of service */
#ifndef IPTOS_LOWDELAY
#define IPTOS_LOWDELAY      0x10
#endif
#ifndef IPTOS_THROUGHPUT
#define IPTOS_THROUGHPUT    0x08
#endif
#ifndef IPTOS_RELIABILITY
#define IPTOS_RELIABILITY   0x04
#endif
#ifndef IPTOS_LOWCOST
#define IPTOS_LOWCOST       0x02
#endif
    uint16_t ip_len;         /* total length */
    uint16_t ip_id;          /* identification */
    uint16_t ip_off;
#ifndef IP_RF
#define IP_RF 0x8000        /* reserved fragment flag */
#endif
#ifndef IP_DF
#define IP_DF 0x4000        /* dont fragment flag */
#endif
#ifndef IP_MF
#define IP_MF 0x2000        /* more fragments flag */
#endif 
#ifndef IP_OFFMASK
#define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
#endif
    uint8_t ip_ttl;          /* time to live */
    uint8_t ip_p;            /* protocol */
    uint16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */

    Ip sip() { return ntohl(ip_src.s_addr);  }
    Ip dip() { return ntohl(ip_dst.s_addr);  }
};



#define ARP_TIME_SEC 5

#pragma pack(push, 1)
typedef struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
} EthArpPacket;
#pragma pack(pop)


int send_arp_packet(pcap_t *handle, int arp_op, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip);
void *arpinfect_proc(void *arg);
void *spoof_proc(void *arg);
void initialize_attack_thread();
void terminate_attack_thread();

#endif