#include <stdlib.h>
#include "net_info.h"
#include <string.h>

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
	if ( status>0 )			// report the warning/error code, if any
		fprintf(stderr, "Activated with warning: %s\n", pcap_statustostr((int)handle));
	else if ( status==0 )
		fprintf(stderr, "Activated stream\n");
		else {
			fprintf(stderr, "Error activating: %d\n", status);
			return 2;
		}
	
	// setting filters: (1) ICMP packets b/w 2 specific hosts and (2) TCP packets with d_port from 10-100
	struct bpf_program filter;
	char f_expr[] = "\(\(src host 192.168.56.103 and dst host 192.168.56.102) or \(src host 192.168.56.102 and dst host 192.168.56.103)) or \(tcp dst portrange 10-100)";
	bpf_u_int32 ip;
	if ( pcap_compile(handle, &filter, f_expr, 0, ip) == -1 ) {
		fprintf(stderr, "Bad filter: %s\n", pcap_geterr(handle));
		return 2;
	}
	if ( pcap_setfilter(handle, &filter) == -1 ) {
		fprintf(stderr, "Error setting filter: %s\n", pcap_geterr(handle));
		return 2;
	}
	fprintf(stderr, "Applied filter: %s\n", &f_expr[0]);
	
	int N = 100;				// process N packets: 0 for infinite-looping
	pcap_loop(handle, N, inf_pcap_handler, NULL);
	pcap_close(handle);
	fprintf(stderr, "Closed stream\n");
	
	return 0;
}

/* Print the info of a single packet. */
void print_info(const struct pcap_pkthdr* p_hdr) {
	printf("Captured %db/%db\t", p_hdr->caplen, p_hdr->len);
}

/* Called on each packet received for processing. */
void inf_pcap_handler(u_char* args, const struct pcap_pkthdr* p_hdr, const u_char* p) {
	print_info(p_hdr);
	
	const struct sniff_ethernet* e = (struct sniff_ethernet*)(p);
	//printf("TYPE=%hu\t", e->ether_type);
	
	//if IP packet
	const struct sniff_ip* ip = (struct sniff_ip*)(p + sizeof(struct sniff_ethernet));
	//printf("PROTO=%d\t", ip->ip_p);
	u_int s_ip = sizeof(struct sniff_ip);
	if ( s_ip>0 && s_ip < 20) {
		printf("Invalid IP header length: %u bytes\t", s_ip);
		return;
	}
	
	// if TCP packet
	const struct sniff_tcp* tcp = (struct sniff_tcp*)(p + sizeof(struct sniff_ethernet) + s_ip);
	u_int s_tcp = sizeof(struct sniff_tcp);
	
	// if it is IP and not TCP
	//if ( s_ip!=0 && s_tcp==0 )
	char src[100];
	strcpy(src,inet_ntoa(ip->ip_src));
	char dst[100];
	strcpy(dst,inet_ntoa(ip->ip_dst));
	printf("IP src/dst: %s/%s\t",src,dst);
	
	// otherwise, print out the TCP data
	if ( s_tcp>0 && s_tcp < 20) {
		printf("Invalid TCP header length: %u bytes\t", s_tcp);
		return;
	}
	//if ( s_tcp!=0 )
	printf("TCP src/dst: %d/%d\t %d/%d\t",ntohs(tcp->th_sport),ntohs(tcp->th_dport),tcp->th_sport,tcp->th_dport);
	
	// payload
	const char* payload = (u_char *)(p + sizeof(struct sniff_ethernet) + s_ip + s_tcp);
	printf("\n\n");//Payload: %s\n\n", payload);
}

