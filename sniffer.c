#include <stdlib.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include "net_info.h"

void print_info(const struct pcap_pkthdr* p_hdr);
void inf_pcap_handler(u_char* arg, const struct pcap_pkthdr* p_hdr, const u_char* packet);

/*
 * Program controller:
 *   - creates the sniffer,
 *   - establishes the connection to other nodes, and
 *   - outputs collected data
 */
int main() {
	// for live capture
	pcap_t* handle;
	char errbuff[PCAP_ERRBUF_SIZE];
	char* device;
	// the packets
	const u_char* pckt;
	struct pcap_pkthdr p_hdr;
	int count = 0;
	
	// get first device available for packet capture
	device = pcap_lookupdev(errbuff);
	if ( device==NULL ) {			// report error
		printf("Error finding device: %s\n",errbuff);
		return 1;
	}
	fprintf(stderr, "Found device: %s\n", device);
	
	/*// open stream in promiscuous mode, w/10s timeout
	handle = pcap_open_live(device, BUFSIZ, 0,  10000, errbuff);
	if ( handle==NULL ) {			// report error
		fprintf(stderr, "Can't open device %s: %s\n", device, errbuff);
		return 2;
	}*/
	
	// promiscuous mode customizability
	handle = pcap_create("any", errbuff);	// using wireless OR wired communicates
	if ( handle==NULL ) {			// report error
		fprintf(stderr, "Can't open device %s: %s\n", device, errbuff);
		return 2;
	}
	pcap_set_rfmon(handle,0);		// monitor mode enabled if 1
	pcap_set_promisc(handle, 1);		// promiscuous mode is on if non-zero
	pcap_set_snaplen(handle, BUFSIZ);
	pcap_set_timeout(handle, 10000);	// 10s
	int status = pcap_activate(handle);	// open the stream
	if ( status>=0 )
		fprintf(stderr, "Activated with warning: %s\n", pcap_statustostr(handle));
	else {
		fprintf(stderr, "Error activating: %d\n", status);
		return 2;
	}
	
	int N = 100;				// process N packets: 0 for infinite-looping
	pcap_loop(handle, N, inf_pcap_handler, NULL);
	pcap_close(handle);
	
	return 0;
}

/* Print the info of a single packet. */
void print_info(const struct pcap_pkthdr* p_hdr) {
	printf("%db Captured out of %db total packet size", p_hdr->caplen, p_hdr->len);
}

#define SIZE_ETHERNET 14			// always 14
/* Called on each packet received for processing. */
void inf_pcap_handler(u_char* args, const struct pcap_pkthdr* p_hdr, const u_char* p) {
	print_info(&p_hdr);
	
	const struct sniff_ip* ip;
	const struct sniff_tcp* tcp;
	ip = (struct sniff_ip*)(p + SIZE_ETHERNET);
	if ( IP_HL(ip)*4 < 20 ) {
		tcp = (struct sniff_tcp*)(p + SIZE_ETHERNET + IP_HL(ip)*4);
		if ( TH_OFF(tcp)*4 < 20 ) {			// error report
			printf("ERROR: packet is not TCP/IP protocol.\n");
			exit(0);
		}
		printf("\tTCP src: %d/dst: %d\n\n",ntohs(tcp->th_sport),ntohs(tcp->th_dport));
	} else
		printf("\tIP src: %s/dst: %s\n\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
}

