#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

#include <stdint.h> // uint8_t 이런게 들어 있음
#include <libnet.h> //과제에 필요한 구조체가 선언되어 있음
#include <netinet/in.h>

/* */
const char* mac_ADR(uint8_t* macAddress) {
    char buf[23] = {};
    sprintf(buf, "%02x : %02x : %02x : %02x : %02x : %02x", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
    
    return buf;
}

const char* ip_ADR(in_addr_t ipAddress) {
    char buf[16] = {};
    sprintf(buf, "%s", inet_ntoa(ipAddress));
    
    return buf;
}

const char* port_num(uint16_t portNumber) {
    char buf[6] = {};
    sprintf(buf, "%d", ntohs(portNumber));
    return buf;
}

const char* get_sample_data(uint8_t* data, uint8_t pre_len) {
    char buf[10] = {};
    
    uint8_t len_10 = data - pre_len;

    len_10 = 10 < len_10 ? 10 : len_10;

    for (int i = 0 ; i < len_10 ; i++) {
        sprintf(&buf[i], "%s", len_10[i]);
    }
    
    return buf;
}

/* */

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

/* */

void print_info(uint8_t* mac, in_addr ip, uint16_t port) {

    printf("MAC\t: %s\n", mac_ADR(mac));
    printf("IP\t: %s\n", ip_ADR(ip));
    printf("PORT\t: %s\n", port_num(port)); //.c_str()

}

void print_data(const u_char* packet, uint8_t ip_Len, uint8_t ip_HeaderLen, uint8_t tcpOffset) {
    uint8_t* data = (uint8_t*)(packet); // + sizeof(struct libnet_ethernet_hdr) + ip_HeaderLen + tcpOffset);
    //uint8_t len = ntohs(ip_Len) - (ip_HeaderLen + tcpOffset);
    uint8_t pre_len = sizeof(struct libnet_ethernet_hdr) + ip_HeaderLen + tcpOffset;
    //ip_Len은 ip 헤더 및 데이터를 포함한 ip 패킷 전체의 길이라는 것 같음.
    printf("%s", get_sample_data(data, pre_len));
}
/* */

int main(int argc, char* argv[]) {

	if (!parse(&param, argc, argv))  // 파일 제대로 읽어들였는지 (?) 확인함.
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		
        if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        /* */
        struct libnet_ethernet_hdr* ethernet_h = (struct libnet_ethernet_hdr*)packet;
        
        struct libnet_ipv4_hdr* ip_h = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
        
        struct libnet_tcp_hdr* tcp_h = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + (ip_h->ip_hl << 2));

        if (ntohs(ethernet_h->ether_type) != ETHERTYPE_IP) continue; //IP 패킷이 아닐 경우 
        if (ip_h->ip_p != IPPROTO_TCP) continue; //TCP 데이터가 아닐 경우

        printf("Ethernet\t/IP\t/TCP\n");
        
        printf("SRC info : ");
        print_info(ethernet_h->ether_shost, ip_h->ip_src, tcp_h->th_sport);
        
        printf("DST info : ");
        print_info(ethernet_h->ether_dhost, ip_h->ip_dst, tcp_h->th_dport);
        
        print_data(packet, sizeof(struct libnet_ethernet_hdr), ip_h->ip_hl, tcp_h -> th_off);
        //print_data(packet, ip_h->ip_len, ip_h->ip_hl*4 , tcp_h->th_off*4);
        /* */
	}

	pcap_close(pcap);
}
