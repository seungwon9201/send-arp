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

	myMac = MyMac(dev);

	for (int i = 2; i < argc; i += 2) {
		const char* senderIp = argv[i];
		const char* targetIp = argv[i + 1];
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac("9C:B1:50:0E:4F:66");
		packet.eth_.smac_ = Mac("90:de:80:d5:82:7a");
		packet.eth_.type_ = htons(EthHdr::Arp);

		packet.arp_.hrd_ = htons(ArpHdr::ETHER);
		packet.arp_.pro_ = htons(EthHdr::Ip4);
		packet.arp_.hln_ = Mac::Size;
		packet.arp_.pln_ = Ip::Size;
		packet.arp_.op_ = htons(ArpHdr::Request);
		packet.arp_.smac_ = myMac;
		packet.arp_.sip_ = htonl(Ip(senderIp));
		packet.arp_.tmac_ = Mac("9C:B1:50:0E:4F:66");
		packet.arp_.tip_ = htonl(Ip(targetIp));

		int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
		}
	}
	pcap_close(pcap);
}
