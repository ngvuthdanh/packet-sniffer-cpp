#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
   
    struct ether_header *ethHeader = (struct ether_header *)packet;

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
        char srcIp[INET_ADDRSTRLEN];
        char dstIp[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &(ipHeader->ip_src), srcIp, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ipHeader->ip_dst), dstIp, INET_ADDRSTRLEN);

        std::cout << "Packet captured:" << std::endl;
        std::cout << "Source IP: " << srcIp << std::endl;
        std::cout << "Destination IP: " << dstIp << std::endl;
        std::cout << "Protocol: " << (int)ipHeader->ip_p << std::endl;
        std::cout << "-----------------------" << std::endl;
    }
}

int main() {
    char *dev;                
    char errbuf[PCAP_ERRBUF_SIZE]; 

    dev = pcap_lookupdev(errbuf);
    if (dev == nullptr) {
        std::cerr << "Error finding device: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Sniffing on device: " << dev << std::endl;

    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Error opening device: " << errbuf << std::endl;
        return 1;
    }

    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        std::cerr << "Error capturing packets: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
}
