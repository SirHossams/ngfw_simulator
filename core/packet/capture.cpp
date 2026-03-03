#include <iostream>
#include "../shared-headers/packet.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <sys/un.h>
using namespace std;

// 				Prototypes
/*______________________________________*/

string FindInterface();
void Sniff(string name);
void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_payload(const u_char* payload, int len);

/*______________________________________*/

int pep_socket = -1;

bool SendToPEP(const vector<uint8_t>& data){
    if (pep_socket < 0)
        return false;

    uint32_t size = data.size();

    if (send(pep_socket, &size, sizeof(size), 0) <= 0)
        return false;

    if (send(pep_socket, data.data(), data.size(), 0) <= 0)
        return false;

    return true;
}

bool InitPEPSocket(){
    pep_socket = socket(AF_UNIX, SOCK_STREAM, 0);

    if (pep_socket < 0){
		cout << "Socket Error: Couldn't connect to PEP";
        return false;
	}

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, "/tmp/pep.sock");

    if (connect(pep_socket, (sockaddr*)&addr, sizeof(addr)) < 0)
        return false;

    return true;
}

// Setting up the buffer
vector<uint8_t> SerializePacket(const NormalizedPacket& np){
    vector<uint8_t> buffer;

    auto append = [&](const void* data, size_t size) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        buffer.insert(buffer.end(), ptr, ptr + size);
    };

    append(&np.capture_sequence_number, sizeof(np.capture_sequence_number));
    append(&np.capture_timestamp_sec, sizeof(np.capture_timestamp_sec));
    append(&np.capture_timestamp_usec, sizeof(np.capture_timestamp_usec));

    append(&np.ether_type, sizeof(np.ether_type));
    append(&np.ip_version, sizeof(np.ip_version));
    append(&np.ttl, sizeof(np.ttl));
    append(&np.total_length, sizeof(np.total_length));
    append(&np.protocol, sizeof(np.protocol));

    append(&np.src_port, sizeof(np.src_port));
    append(&np.dst_port, sizeof(np.dst_port));
    append(&np.sequence_number, sizeof(np.sequence_number));
    append(&np.acknowledgment_number, sizeof(np.acknowledgment_number));
    append(&np.window_size, sizeof(np.window_size));
    append(&np.tcp_flags, sizeof(np.tcp_flags));

    uint32_t payload_size = np.payload.size();
    append(&payload_size, sizeof(payload_size));

    if (!np.payload.empty())
        append(np.payload.data(), np.payload.size());

    return buffer;
}

void PushToJsonDB(const NormalizedPacket& np){
    nlohmann::json j;

    j["frame"] = np.capture_sequence_number;
    j["timestamp_sec"] = np.capture_timestamp_sec;
    j["timestamp_usec"] = np.capture_timestamp_usec;

    j["src_mac"] = np.src_mac;
    j["dst_mac"] = np.dst_mac;
    j["ether_type"] = np.ether_type;

    j["ip_version"] = np.ip_version;
    j["src_ip"] = np.src_ip;
    j["dst_ip"] = np.dst_ip;
    j["ttl"] = np.ttl;
    j["total_length"] = np.total_length;
    j["protocol"] = np.protocol;

    j["src_port"] = np.src_port;
    j["dst_port"] = np.dst_port;
    j["seq"] = np.sequence_number;
    j["ack"] = np.acknowledgment_number;
    j["window"] = np.window_size;
    j["flags"] = np.tcp_flags;

    j["payload_size"] = np.payload.size();

	ofstream file("/home/flashhack/Work/Github/ngfw_simulator/core/databases/subject-database.json", ios::app);
	if (!file.is_open()) {
        cerr << "ERROR: Could not open subject-database.json\n";
        return;
    }
    file << j.dump() << endl;
}

// void print_hex_ascii_line(const u_char *payload, int len, int offset){
// 	int i;
// 	int gap;
// 	const u_char *ch;

// 	/* offset */
// 	printf("%05d   ", offset);

// 	/* hex */
// 	ch = payload;
// 	for(i = 0; i < len; i++) {
// 		printf("%02x ", *ch);
// 		ch++;
// 		/* print extra space after 8th byte for visual aid */
// 		if (i == 7)
// 			printf(" ");
// 	}
// 	/* print space to handle line less than 8 bytes */
// 	if (len < 8)
// 		printf(" ");

// 	/* fill hex gap with spaces if not full line */
// 	if (len < 16) {
// 		gap = 16 - len;
// 		for (i = 0; i < gap; i++) {
// 			printf("   ");
// 		}
// 	}

// 	printf("   ");

// 	/* ascii (if printable) */
// 	ch = payload;
// 	for(i = 0; i < len; i++) {
// 		if (isprint(*ch))
// 			printf("%c", *ch);
// 		else
// 			printf(".");
// 		ch++;
// 	}

// 	printf("\n");

//     return;
// }

// void print_payload(const u_char* payload, int len){
//     int len_rem = len;
// 	int line_width = 16;			/* number of bytes per line */
// 	int line_len;
// 	int offset = 0;					/* zero-based offset counter */
// 	const u_char *ch = payload;

// 	if (len <= 0)
// 		return;

// 	/* data fits on one line */
// 	if (len <= line_width) {
// 		print_hex_ascii_line(ch, len, offset);
// 		return;
// 	}

// 	/* data spans multiple lines */
// 	for ( ;; ) {
// 		/* compute current line length */
// 		line_len = line_width % len_rem;
// 		/* print line */
// 		print_hex_ascii_line(ch, line_len, offset);
// 		/* compute total remaining */
// 		len_rem = len_rem - line_len;
// 		/* shift pointer to remaining bytes to print */
// 		ch = ch + line_len;
// 		/* add offset */
// 		offset = offset + line_width;
// 		/* check if we have line width chars or less */
// 		if (len_rem <= line_width) {
// 			/* print last line and get out */
// 			print_hex_ascii_line(ch, len_rem, offset);
// 			break;
// 		}
// 	}

//     return;
// }

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

    static uint64_t global_packet_counter = 1;

    const sniff_ethernet* ethernet;
    const sniff_ip* ip;
    const sniff_tcp* tcp;

    NormalizedPacket np;

    /* ================= Capture Metadata ================= */
    np.capture_sequence_number = global_packet_counter++;
    np.capture_timestamp_sec = header->ts.tv_sec;
    np.capture_timestamp_usec = header->ts.tv_usec;

    cout << "Sequence no. #" << np.capture_sequence_number
    << " | Time: " << np.capture_timestamp_sec << "." << np.capture_timestamp_usec << "\n";

    /* ================= L1 ================= */
    ethernet = (sniff_ethernet*)(packet);

    auto mac_to_string = [](const u_char* mac) {
        stringstream ss;
        for (int i = 0; i < 6; i++) {
            ss << hex << setw(2) << setfill('0') << (int)mac[i];
            if (i != 5) ss << ":";
        }
        return ss.str();
    };

    np.src_mac = mac_to_string(ethernet->ether_shost);
    np.dst_mac = mac_to_string(ethernet->ether_dhost);
    np.ether_type = ntohs(ethernet->ether_type);

    cout << "L1: " << np.src_mac << " -> " << np.dst_mac << "\n";

    /* ================= L2 ================= */
    ip = (sniff_ip*)(packet + SIZE_ETHERNET);

    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        cout << "Invalid IP header length\n";
        return;
    }

    np.ip_version = IP_V(ip);
    np.src_ip = inet_ntoa(ip->ip_src);
    np.dst_ip = inet_ntoa(ip->ip_dst);
    np.ttl = ip->ip_ttl;
    np.header_checksum = ntohs(ip->ip_sum);
    np.identification = ntohs(ip->ip_id);

    uint16_t offset_field = ntohs(ip->ip_off);
    np.flags = offset_field >> 13;
    np.fragment_offset = offset_field & 0x1FFF;

    np.total_length = ntohs(ip->ip_len);
    np.protocol = ip->ip_p;

    cout << "L2: " << np.src_ip << " -> " << np.dst_ip
    << " | TTL: " << (int)np.ttl
    << " | Protocol: " << (int)np.protocol
    << "\n";

    if (np.protocol != IPPROTO_TCP) {
        cout << "Not TCP — skipping\n";
        cout << "-----------------------------------\n";
        return;
    }

    /* ================= L3 ================= */
    tcp = (sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        cout << "Invalid TCP header length\n";
        return;
    }

    np.src_port = ntohs(tcp->th_sport);
    np.dst_port = ntohs(tcp->th_dport);
    np.sequence_number = ntohl(tcp->th_seq);
    np.acknowledgment_number = ntohl(tcp->th_ack);
    np.window_size = ntohs(tcp->th_win);
    np.tcp_flags = tcp->th_flags;

    cout << "L3: "
    << np.src_port << " -> " << np.dst_port
    << " | Seq: " << np.sequence_number
    << " | Ack: " << np.acknowledgment_number
    << "\n";

    /* ================= Payload ================= */
    const u_char* payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
    int size_payload = np.total_length - (size_ip + size_tcp);

    if (size_payload > 0) {
        np.payload.assign(payload, payload + size_payload);
        cout << "Payload size: " << size_payload << " bytes\n";
    } else {
        cout << "No Payload\n";
    }

    cout << "-----------------------------------\n";
	PushToJsonDB(np);
	auto serialized = SerializePacket(np);
	SendToPEP(serialized);
}

string FindInterface(){
    pcap_if_t *alldevices;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevices, errbuf) == -1) {
        cerr << "Error finding devices: " <<  errbuf << '\n';
    }

    if (!alldevices) {
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
	InitPEPSocket();
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