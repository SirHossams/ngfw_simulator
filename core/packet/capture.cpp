#include <iostream>
#include "../shared-headers/packet.h"
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sys/un.h>
#include <sys/socket.h>
#include <cstring>

using namespace std;

// 				Prototypes              //
/*______________________________________*/

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void PushToJsonDB(const NormalizedPacket& np, uint8_t protocol);
vector<uint8_t> SerializePacket(const NormalizedPacket& np, uint8_t protocol);
string DetectAppProtocol(uint8_t protocol, uint16_t src_port,uint16_t dst_port);
bool InitPEPSocket();
bool SendToPEP(const vector<uint8_t>& data);

/*______________________________________*/

// -1 is Default (not connected)
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
    strncpy(addr.sun_path, "/tmp/pep.sock", sizeof(addr.sun_path) - 1);

    if (connect(pep_socket, (sockaddr*)&addr, sizeof(addr)) < 0)
        return false;

    return true;
}

string DetectAppProtocol(uint8_t protocol, uint16_t src_port,uint16_t dst_port){
    if (protocol == IPPROTO_TCP) {
        if (src_port == 80 || dst_port == 80)
            return "HTTP";
        if (src_port == 443 || dst_port == 443)
            return "HTTPS";
        if (src_port == 22 || dst_port == 22)
            return "SSH";
        return "TCP-UNKNOWN";
    }
    else if (protocol == IPPROTO_UDP) {
        if (src_port == 53 || dst_port == 53)
            return "DNS";
        return "UDP-UNKNOWN";
    }
    else if (protocol == IPPROTO_ICMP)
        return "ICMP";
    else
        return "ARP";
}

vector<uint8_t> SerializePacket(const NormalizedPacket& np, uint8_t protocol){
    vector<uint8_t> buffer;

    // Function to set a place for data's size in buffer/data
    auto append = [&](const void* data, size_t size) {
        const uint8_t* ptr = static_cast<const uint8_t*>(data);
        buffer.insert(buffer.end(), ptr, ptr + size);
    };
    append(&np.capture_sequence_number, sizeof(np.capture_sequence_number));
    append(&np.capture_timestamp_sec, sizeof(np.capture_timestamp_sec));
    append(&np.capture_timestamp_usec, sizeof(np.capture_timestamp_usec));
    append(&np.ether_type, sizeof(np.ether_type));

    // ================= TCP =================
    if(protocol == IPPROTO_TCP){

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
    }

    // ================= UDP =================
    else if(protocol == IPPROTO_UDP){

        append(&np.ip_version, sizeof(np.ip_version));
        append(&np.ttl, sizeof(np.ttl));
        append(&np.total_length, sizeof(np.total_length));
        append(&np.protocol, sizeof(np.protocol));

        append(&np.src_port, sizeof(np.src_port));
        append(&np.dst_port, sizeof(np.dst_port));
        append(&np.udp_length, sizeof(np.udp_length));
    }

    // ================= ICMP =================
    else if(protocol == IPPROTO_ICMP){

        append(&np.ip_version, sizeof(np.ip_version));
        append(&np.ttl, sizeof(np.ttl));
        append(&np.total_length, sizeof(np.total_length));
        append(&np.protocol, sizeof(np.protocol));

        append(&np.icmp_type, sizeof(np.icmp_type));
        append(&np.icmp_code, sizeof(np.icmp_code));
    }

    // ================= ARP =================
    else{
        append(&np.arp_opcode, sizeof(np.arp_opcode));

        uint32_t src_ip_len = np.arp_src_ip.size();
        append(&src_ip_len, sizeof(src_ip_len));
        append(np.arp_src_ip.data(), src_ip_len);

        uint32_t dst_ip_len = np.arp_dst_ip.size();
        append(&dst_ip_len, sizeof(dst_ip_len));
        append(np.arp_dst_ip.data(), dst_ip_len);
    }

    // ================= Payload =================
    uint32_t payload_size = np.payload.size();
    append(&payload_size, sizeof(payload_size));

    if (!np.payload.empty())
        append(np.payload.data(), np.payload.size());

    return buffer;
}

void PushToJsonDB(const NormalizedPacket& np, uint8_t protocol){
    using ordered_json = nlohmann::ordered_json;

    ordered_json packet;

    packet["frame"] = np.capture_sequence_number;
    packet["timestamp_sec"] = np.capture_timestamp_sec;
    packet["timestamp_usec"] = np.capture_timestamp_usec;

    packet["src_mac"] = np.src_mac;
    packet["dst_mac"] = np.dst_mac;
    packet["ether_type"] = np.ether_type;

    if(np.ether_type != 0x0806){
        packet["src_ip"] = np.src_ip;
        packet["dst_ip"] = np.dst_ip;
    }
    
    packet["ttl"] = np.ttl;
    packet["protocol"] = np.protocol;

    if (protocol == IPPROTO_TCP) {
        packet["src_port"] = np.src_port;
        packet["dst_port"] = np.dst_port;
        packet["seq"] = np.sequence_number;
        packet["ack"] = np.acknowledgment_number;
        packet["flags"] = np.tcp_flags;
        packet["window"] = np.window_size;
        packet["app_protocol"] = np.app_protocol;
    }
    else if (protocol == IPPROTO_UDP) {
        packet["src_port"] = np.src_port;
        packet["dst_port"] = np.dst_port;
        packet["udp_length"] = np.udp_length;
        packet["app_protocol"] = np.app_protocol;
    }
    else if (protocol == IPPROTO_ICMP) {
        packet["icmp_type"] = np.icmp_type;
        packet["icmp_code"] = np.icmp_code;
    }
    else { // ARP
        packet["arp_opcode"] = np.arp_opcode;
        packet["arp_src_ip"] = np.arp_src_ip;
        packet["arp_dst_ip"] = np.arp_dst_ip;
    }

    packet["payload_size"] = np.payload.size();

    ordered_json database = ordered_json::array();

    ifstream in("core/databases/subject-database.json");
    if (in.good()) {
        try { in >> database; }
        catch (...) { database = ordered_json::array(); }
    }

    database.push_back(packet);

    ofstream out("core/databases/subject-database.json");
    out << database.dump(4);

}

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

    /* ================= ARP (Non-IP) ================= */
    if (np.ether_type == 0x0806) {
        const sniff_arp* arp =
            (sniff_arp*)(packet + SIZE_ETHERNET);

        np.arp_opcode = ntohs(arp->arp_op);

        np.arp_src_ip = inet_ntoa(*(in_addr*)arp->arp_spa);

        np.arp_dst_ip = inet_ntoa(*(in_addr*)arp->arp_tpa);

        cout << "ARP: " << np.arp_src_ip << " -> " << np.arp_dst_ip << " | Opcode: " << np.arp_opcode << "\n";

        PushToJsonDB(np, 0);
        auto serialized = SerializePacket(np, 0);
        SendToPEP(serialized);
        return;
    }

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

    /* ================= L3 ================= */

    // Case 1: TCP
    if (np.protocol == IPPROTO_TCP) {
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

        cout << "L3: TCP "
        << np.src_port << " -> " << np.dst_port
        << " | Seq: " << np.sequence_number
        << " | Ack: " << np.acknowledgment_number
        << "\n";

        /* ================= Payload ================= */
        const u_char* payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
        int size_payload = np.total_length - (size_ip + size_tcp);
        if (size_payload <= 0) {
            cout << "No Payload\n";
        }
        else {
            np.payload.assign(payload, payload + size_payload);
            cout << "Payload size: " << size_payload << " bytes\n";
        }
            
    }
    // Case 2 UDP
    else if(np.protocol == IPPROTO_UDP){
        const sniff_udp* udp =
            (sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

        np.src_port = ntohs(udp->uh_sport);
        np.dst_port = ntohs(udp->uh_dport);
        np.udp_length = ntohs(udp->uh_ulen);

        cout << "L3: UDP "
        << np.src_port << " -> " << np.dst_port
        << "\n";

        const u_char* payload =packet + SIZE_ETHERNET + size_ip + 8;

        int size_payload = np.udp_length - 8;

        if (size_payload > 0){
            np.payload.assign(payload, payload + size_payload);
            cout << "Payload size: " << size_payload << " bytes \n";
        }
        else{
            cout << "No payload";
        }
    }
    // Case 3 ICMP
    else if(np.protocol == IPPROTO_ICMP){
         const sniff_icmp* icmp =
            (sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

        np.icmp_type = icmp->icmp_type;
        np.icmp_code = icmp->icmp_code;

        cout << "L3: ICMP type = " << (int)np.icmp_type
        << " code = " << (int)np.icmp_code
        << "\n";

        const int icmp_header_len = sizeof(sniff_icmp);
        const u_char* payload = packet + SIZE_ETHERNET + size_ip + icmp_header_len;
        int size_payload = np.total_length - (size_ip + icmp_header_len);

        if (size_payload > 0)
            np.payload.assign(payload, payload + size_payload);
    }

    cout << "-----------------------------------\n";
    np.app_protocol = DetectAppProtocol(np.protocol,np.src_port,np.dst_port);
	PushToJsonDB(np,np.protocol);
	auto serialized = SerializePacket(np, np.protocol);
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
    pcap_t* handle = pcap_open_live(name.c_str(), 65535, true, 100, errbuf);

    // Could happen due to fault in configurations of interface or lack of permissions
    if(handle == NULL){
        cerr << "Couldn't open device " << name << " for sniffing \n"  << errbuf << endl;
        return;
    }
    // Not all interfaces manufactured support Ethernet/pcap headers
    if (pcap_datalink(handle) != DLT_EN10MB){
	    cerr << "Device " << name << "doesn't support/provide Ethernet headers (not supported)";
        pcap_close(handle);
        return;
    }
    if (pcap_lookupnet(name.c_str(), &net, &mask, errbuf) != 0) {
		cerr << "Couldn't get properties of device " << name << '\n' <<  errbuf;
		net = 0;
		mask = 0;
	}

    // Trying to connect to PEP via unix socket
    if(!InitPEPSocket()){
        cout << "Exiting because of unix socket failure...\n";
        return;
    }
    else{
        cout << "Packet Capture connect to Policy Enforcement Point succesfully!\n";
    }

    // Starting infinite loop of capture
    pcap_loop(handle, 0, PacketHandler, nullptr);
    // Close Session (only called if we capture finite number of packets, so it's not necessary called)
    pcap_close(handle);
}

int main(int argc, char *argv[]){
    const string device = FindInterface();
    cout << device << endl;
    Sniff(device);
    return 0;
}