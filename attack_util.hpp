#ifndef _ATTACK_UTIL_H_
#define _ATTACK_UTIL_H_


#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "attack.hpp"


#define ERR_CHK(func_name, params, error_code) \
    if( func_name params != 0 ) { \
        printf("Error in "#func_name"\n"); \
        error_code \
    }


int safe_send_packet(pcap_t *handle, u_char *packet, uint32_t size) ;
int send_arp_packet(pcap_t *handle, int arp_op, Mac dmac, Mac smac, Mac tmac, Ip sip, Ip tip);
int read_packet(pcap_t *handle, pcap_pkthdr **out_header, u_char** out_pkt);
int get_mac_by_ip(pcap_t *handle, Mac my_mac, Ip my_ip, Ip sender_ip, Mac *out);
#endif