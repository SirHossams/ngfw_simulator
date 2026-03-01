#include <iostream>
#include "../shared-headers/packet.h"
using namespace std;

// 				Prototypes
/*______________________________________*/
string FindInterface();
void Sniff(string name);
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char* payload, int len);
/*______________________________________*/

void print_hex_ascii_line(const u_char *payload, int len, int offset){
	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}

	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

    return;
}

void print_payload(const u_char* payload, int len){
    int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

    return;
}

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
    static int count = 1; // Packet Sequence number

    const struct sniff_ethernet* ethernet;  /* The Ethernet header */
	const struct sniff_ip* ip;              /* The IP header */
	const struct sniff_tcp* tcp;            /* The TCP header */
	const u_char* payload;                    /* Packet payload */

    int size_ip;
	int size_tcp;
	int size_payload;

    cout << "Packet Number " << count << '\n';
    count++;

    ethernet = (struct sniff_ethernet*)(packet);

    /* Compute IP header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

    /* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

    /* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

    /* compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    /* compute tcp payload (segment) offset */
	payload = packet + SIZE_ETHERNET + size_ip + size_tcp;

	/* compute tcp payload (segment) size */
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

    if (size_payload > 0) {
		printf("   Payload (%d bytes):\n", size_payload);
		print_payload(payload, size_payload);
	}

    cout << '\n';
	return;
}

string FindInterface(){
    pcap_if_t *alldevices;
    char errbuf[PCAP_ERRBUF_SIZE];

    int result = pcap_findalldevs(&alldevices, errbuf);
    if (result == -1) {
        cerr << "Error finding devices: " <<  errbuf << '\n';
    }

    if (alldevices == NULL) {
        cerr << "No devices found.\n";
    }

    // cout << "First device: " << alldevices->name << endl;
    string device_name = alldevices -> name;
    pcap_freealldevs(alldevices);
    return device_name;
}

void Sniff(string name){
    bpf_u_int32 net, mask;
    char errbuf[PCAP_ERRBUF_SIZE];
    // Why true in pcap_openlive() ?
    // Packet sniffers (e.g., Wireshark) automatically enables promiscuous mode by default when starting a packet capture.
    // This allows your network interface card (NIC) to pass all traffic it sees to the capture engine, rather than just traffic addressed to your machine.
    pcap_t* handle = pcap_open_live(name.c_str(), 1024, true, 100, errbuf);
    if(handle == NULL){
        cerr << "Couldn't open device " << name << " for sniffing \n"  << errbuf << endl;
        return;
    }
    if (pcap_datalink(handle) != DLT_EN10MB){
	    cerr << "Device " << name << "doesn't support provide Ethernet headers (not supported)";
        pcap_close(handle);
        return;
    }
    if (pcap_lookupnet(name.c_str(), &net, &mask, errbuf) != 0) {
		cerr << "Couldn't get properties of device " << name << '\n' <<  errbuf;
		net = 0;
		mask = 0;
	}
    pcap_loop(handle, 0, PacketHandler, nullptr);
    pcap_close(handle);
}

int main(int argc, char *argv[])
{
    const string device = FindInterface();
    cout << device << endl;
    Sniff(device);
    return 0;
}