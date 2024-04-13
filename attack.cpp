
#include <pcap.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <string.h>
#include "attack.hpp"
#include "attack_util.hpp"

pthread_mutex_t pcap_handle_mutex;

void initialize_spoof() {
    pcap_handle_mutex = PTHREAD_MUTEX_INITIALIZER;
}

void *spoof_proc_th(void *arg) {
    spoof_th_arg *spoof_info = (spoof_th_arg*)arg;
    Mac sender_mac;
    Mac target_mac;

    if(get_mac_from_ip(spoof_info->handle, spoof_info->my_mac, spoof_info->my_ip,  spoof_info->sender_ip, spoof_info->target_ip, &sender_mac) != 0) {
        printf("Error in get_mac_from_ip");
        goto fin;
    }

    if(get_mac_from_ip(spoof_info->handle, spoof_info->my_mac, spoof_info->my_ip,  spoof_info->target_ip, spoof_info->target_ip, &target_mac) != 0) {
        printf("Error in get_mac_from_ip");
        goto fin;
    }


    fin:
    return NULL;
}
