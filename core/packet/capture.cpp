#include <iostream>
#include "../shared-headers/packet.h"
#include <netinet/in.h>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sys/un.h>
#include <sys/socket.h>
#include <cstring>
#include <sstream>
#include <iomanip>

using namespace std;

//              Prototypes              //
/*______________________________________*/

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void PushToJsonDB(const NormalizedPacket& np, uint8_t protocol);
vector<uint8_t> SerializePacket(const NormalizedPacket& np, uint8_t protocol);
string DetectAppProtocol(uint8_t protocol, uint16_t src_port,uint16_t dst_port);
bool InitPEPSocket();
bool SendToPEP(const vector<uint8_t>& data);
vector<uint8_t> ExtractSSLCertificate(const vector<uint8_t>& payload);

/*______________________________________*/

// -1 is Default (not connected)
int pep_socket = -1;

bool SendToPEP(const vector<uint8_t>& data){
    if (pep_socket < 0)
        return false;

    uint32_t size = data.size();

    // MSG_NOSIGNAL prevents the capture program from crashing if PEP disconnects
    if (send(pep_socket, &size, sizeof(size), MSG_NOSIGNAL) <= 0)
        return false;

    if (send(pep_socket, data.data(), data.size(), MSG_NOSIGNAL) <= 0)
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

vector<uint8_t> ExtractSSLCertificate(const vector<uint8_t>& payload) {
    if (payload.size() < 5) return {};

    size_t i = 0;
    while (i + 5 <= payload.size()) {
        // TLS Record header: Content Type (1 byte), Version (2 bytes), Length (2 bytes)
        uint8_t content_type = payload[i];
        
        // 0x16 is the Handshake Content Type
        if (content_type != 0x16) {
            break; 
        }

        uint16_t record_len = (payload[i+3] << 8) | payload[i+4];
        
        if (i + 5 + record_len > payload.size()) {
            break; // Incomplete record, packet might be fragmented
        }

        // Parse Handshake messages within this specific TLS record
        size_t hs_offset = i + 5;
        size_t hs_end = i + 5 + record_len;

        while (hs_offset + 4 <= hs_end) {
            uint8_t hs_type = payload[hs_offset];
            uint32_t hs_len = (payload[hs_offset+1] << 16) | (payload[hs_offset+2] << 8) | payload[hs_offset+3];

            if (hs_offset + 4 + hs_len > hs_end) {
                break; // Incomplete handshake message
            }

            // Handshake Type 11 (0x0b) is the Certificate message
            if (hs_type == 0x0b) { 
                return vector<uint8_t>(payload.begin() + hs_offset, payload.begin() + hs_offset + 4 + hs_len);
            }

            // Move to the next handshake message in this record
            hs_offset += 4 + hs_len;
        }
        
        // Move to the next TLS record in the TCP payload
        i += 5 + record_len; 
    }
    return {};
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

        // Append SSL Certificate
        uint32_t cert_size = np.ssl_certificate.size();
        append(&cert_size, sizeof(cert_size));
        if (!np.ssl_certificate.empty()) {
            append(np.ssl_certificate.data(), np.ssl_certificate.size());
        }
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
    else if(np.ether_type == 0x0806){
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
        
        if (!np.ssl_certificate.empty()) {
            stringstream hex_cert;
            for (auto b : np.ssl_certificate) {
                hex_cert << hex << setw(2) << setfill('0') << (int)b;
            }
            packet["ssl_certificate_hex"] = hex_cert.str();
        }
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
    else if (np.ether_type == 0x0806) { // ARP
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

void PacketHandler(u_char *, const struct pcap_pkthdr *header, const u_char *packet) {

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

    /* ======== ARP (Non-IP) ======== */
    if (np.ether_type == 0x0806) {
        const sniff_arp* arp = (sniff_arp*)(packet + SIZE_ETHERNET); 

        np.arp_opcode = ntohs(arp->arp_op);
        np.arp_src_ip = inet_ntoa(*(in_addr*)arp->arp_spa); 
        np.arp_dst_ip = inet_ntoa(*(in_addr*)arp->arp_tpa);

        cout << "ARP: " << np.arp_src_ip << " -> " << np.arp_dst_ip << " | Opcode: " << np.arp_opcode << "\n";

        PushToJsonDB(np, 0);
        auto serialized = SerializePacket(np, 0);
        SendToPEP(serialized);
        return;
    }
    
    /* ======== IP Protocol ======== */
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

        /* ================= L4 (Payload) ================= */
        const u_char* payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
        int size_payload = np.total_length - (size_ip + size_tcp);
        
        if (size_payload > 0) {
            np.payload.assign(payload, payload + size_payload);
            cout << "Payload size: " << size_payload << " bytes\n";
        } else {
            cout << "No Payload\n";
        }
        
        np.app_protocol = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
        
        // Extract SSL Certificate for HTTPS traffic
        if (np.app_protocol == "HTTPS" && size_payload > 0) {
            np.ssl_certificate = ExtractSSLCertificate(np.payload);
            if (!np.ssl_certificate.empty()) {
                cout << "Extracted SSL Certificate: " << np.ssl_certificate.size() << " bytes\n";
                return;
            }
        }
    }
    else if(np.protocol == IPPROTO_UDP){
        const sniff_udp* udp = (sniff_udp*)(packet + SIZE_ETHERNET + size_ip);

        np.src_port = ntohs(udp->uh_sport);
        np.dst_port = ntohs(udp->uh_dport);
        np.udp_length = ntohs(udp->uh_ulen);

        cout << "L3: UDP " << np.src_port << " -> " << np.dst_port << "\n";

        const u_char* payload = packet + SIZE_ETHERNET + size_ip + 8;
        int size_payload = np.udp_length - 8;

        if (size_payload > 0){
            np.payload.assign(payload, payload + size_payload);
            cout << "Payload size: " << size_payload << " bytes \n";
        } else {
            cout << "No payload\n";
        }
        
        np.app_protocol = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
    }
    else if(np.protocol == IPPROTO_ICMP){
        const sniff_icmp* icmp = (sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);

        np.icmp_type = icmp->icmp_type;
        np.icmp_code = icmp->icmp_code;

        cout << "L3: ICMP type = " << (int)np.icmp_type
        << " code = " << (int)np.icmp_code << "\n";

        const int icmp_header_len = sizeof(sniff_icmp);
        const u_char* payload = packet + SIZE_ETHERNET + size_ip + icmp_header_len;
        int size_payload = np.total_length - (size_ip + icmp_header_len);

        if (size_payload > 0) {
            np.payload.assign(payload, payload + size_payload);
        }
        
        np.app_protocol = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
    }

    cout << "-----------------------------------\n";
    PushToJsonDB(np, np.protocol);
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
    
    pcap_t* handle = pcap_open_live(name.c_str(), 65535, true, 100, errbuf);

    if(handle == NULL){
        cerr << "Couldn't open device " << name << " for sniffing \n"  << errbuf << endl;
        return;
    }
    if (pcap_datalink(handle) != DLT_EN10MB){
        cerr << "Device " << name << " doesn't support/provide Ethernet headers (not supported)";
        pcap_close(handle);
        return;
    }
    if (pcap_lookupnet(name.c_str(), &net, &mask, errbuf) != 0) {
        cerr << "Couldn't get properties of device " << name << '\n' <<  errbuf;
        net = 0;
        mask = 0;
    }

    if(!InitPEPSocket()){
        cout << "Exiting because of unix socket failure...\n";
        return;
    }
    else{
        cout << "Packet Capture connect to Policy Enforcement Point succesfully!\n";
    }

    pcap_loop(handle, 0, PacketHandler, nullptr);
    pcap_close(handle);
}

int main(){
    const string device = FindInterface();
    cout << "Sniffing on: " << device << endl;
    Sniff(device);
    return 0;
}