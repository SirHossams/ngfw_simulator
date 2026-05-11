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
#include <thread>
#include <mutex>
#include <atomic>
#include <pcap.h>

using namespace std;



void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void PushToJsonDB(const NormalizedPacket& np, uint8_t protocol);
string DetectAppProtocol(uint8_t protocol, uint16_t src_port,uint16_t dst_port);
bool InitPEPSocket();
bool SendToPEP(const NormalizedPacket& np);
void ExtractSSLCertificate(NormalizedPacket& np);


int pep_socket = -1;
mutex pep_mutex; 
mutex db_mutex;  

string global_interface_1 = "";
string global_interface_2 = "";

atomic<uint64_t> global_packet_counter{1}; 

bool SendToPEP(const NormalizedPacket& np){
    lock_guard<mutex> lock(pep_mutex); 

    if (pep_socket < 0) return false;

    uint32_t size = sizeof(NormalizedPacket);

    if (send(pep_socket, &size, sizeof(size), MSG_NOSIGNAL) <= 0) return false;
    if (send(pep_socket, &np, sizeof(NormalizedPacket), MSG_NOSIGNAL) <= 0) return false;
    
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

void ExtractSSLCertificate(NormalizedPacket& np) {
    if (np.payload_size < 5) return;

    size_t i = 0;
    while (i + 5 <= np.payload_size) {
        uint8_t content_type = np.payload[i];
        if (content_type != 0x16) break; 

        uint16_t record_len = (np.payload[i+3] << 8) | np.payload[i+4];
        if (i + 5 + record_len > np.payload_size) break; 

        size_t hs_offset = i + 5;
        size_t hs_end = i + 5 + record_len;

        while (hs_offset + 4 <= hs_end) {
            uint8_t hs_type = np.payload[hs_offset];
            uint32_t hs_len = (np.payload[hs_offset+1] << 16) | (np.payload[hs_offset+2] << 8) | np.payload[hs_offset+3];

            if (hs_offset + 4 + hs_len > hs_end) break;

            if (hs_type == 0x0b) { 
                np.ssl_cert_size = hs_len <= MAX_CERT_SIZE ? hs_len : MAX_CERT_SIZE;
                memcpy(np.ssl_certificate, &np.payload[hs_offset + 4], np.ssl_cert_size);
                return;
            }
            hs_offset += 4 + hs_len;
        }
        i += 5 + record_len; 
    }
}

string DetectAppProtocol(uint8_t protocol, uint16_t src_port,uint16_t dst_port){
    if (protocol == IPPROTO_TCP) {
        if (src_port == 80 || dst_port == 80) return "HTTP";
        if (src_port == 443 || dst_port == 443) return "HTTPS";
        if (src_port == 22 || dst_port == 22) return "SSH";
        return "TCP-UNKNOWN";
    }
    else if (protocol == IPPROTO_UDP) {
        if (src_port == 53 || dst_port == 53) return "DNS";
        return "UDP-UNKNOWN";
    }
    else if (protocol == IPPROTO_ICMP) return "ICMP";
    else return "ARP";
}

void PushToJsonDB(const NormalizedPacket& np, uint8_t protocol){
    lock_guard<mutex> lock(db_mutex); 

    using ordered_json = nlohmann::ordered_json;
    ordered_json packet;

    packet["interface"] = string(np.interface);
    packet["frame"] = np.capture_sequence_number;
    packet["timestamp_sec"] = np.capture_timestamp_sec;
    packet["timestamp_usec"] = np.capture_timestamp_usec;

    packet["src_mac"] = string(np.src_mac);
    packet["dst_mac"] = string(np.dst_mac);
    packet["ether_type"] = np.ether_type;

    if(np.ether_type != 0x0806){
        packet["src_ip"] = string(np.src_ip);
        packet["dst_ip"] = string(np.dst_ip);
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
        packet["app_protocol"] = string(np.app_protocol);
        
        if (np.ssl_cert_size > 0) {
            stringstream hex_cert;
            for (uint32_t i = 0; i < np.ssl_cert_size; i++) {
                hex_cert << hex << setw(2) << setfill('0') << (int)np.ssl_certificate[i];
            }
            packet["ssl_certificate_hex"] = hex_cert.str();
        }
    }
    else if (protocol == IPPROTO_UDP) {
        packet["src_port"] = np.src_port;
        packet["dst_port"] = np.dst_port;
        packet["udp_length"] = np.udp_length;
        packet["app_protocol"] = string(np.app_protocol);
    }
    else if (protocol == IPPROTO_ICMP) {
        packet["icmp_type"] = np.icmp_type;
        packet["icmp_code"] = np.icmp_code;
    }
    else if (np.ether_type == 0x0806) {
        packet["arp_opcode"] = np.arp_opcode;
        packet["arp_src_ip"] = string(np.arp_src_ip);
        packet["arp_dst_ip"] = string(np.arp_dst_ip);
    }

    packet["payload_size"] = np.payload_size;

    ordered_json database = ordered_json::array();
    ifstream in("core/databases/subject-database.json");
    if (in.good()) {
        try { in >> database; }
        catch (...) { database = ordered_json::array(); }
    }
    in.close();

    database.push_back(packet);

    ofstream out("core/databases/subject-database.json");
    out << database.dump(4);
}

void PacketHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const char* iface_name = (const char*)args;

    const sniff_ethernet* ethernet;
    const sniff_ip* ip;
    const sniff_tcp* tcp;

    NormalizedPacket np = {}; 

    strncpy(np.interface, iface_name, INTERFACE_STR_LEN - 1);
    np.capture_sequence_number = global_packet_counter++;
    np.capture_timestamp_sec = header->ts.tv_sec;
    np.capture_timestamp_usec = header->ts.tv_usec;

    cout << "[" << np.interface << "] Seq #" << np.capture_sequence_number << "\n";

    ethernet = (sniff_ethernet*)(packet); 

    auto format_mac = [](char* dest, const u_char* mac) {
        sprintf(dest, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    };

    format_mac(np.src_mac, ethernet->ether_shost);
    format_mac(np.dst_mac, ethernet->ether_dhost);
    np.ether_type = ntohs(ethernet->ether_type);

    if (np.ether_type == 0x0806) {
        const sniff_arp* arp = (sniff_arp*)(packet + SIZE_ETHERNET); 
        np.arp_opcode = ntohs(arp->arp_op);
        strncpy(np.arp_src_ip, inet_ntoa(*(in_addr*)arp->arp_spa), IP_ADDR_STR_LEN - 1); 
        strncpy(np.arp_dst_ip, inet_ntoa(*(in_addr*)arp->arp_tpa), IP_ADDR_STR_LEN - 1);

        PushToJsonDB(np, 0);
        SendToPEP(np);
        return;
    }
    
    ip = (sniff_ip*)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) return;

    np.ip_version = IP_V(ip);
    strncpy(np.src_ip, inet_ntoa(ip->ip_src), IP_ADDR_STR_LEN - 1); 
    strncpy(np.dst_ip, inet_ntoa(ip->ip_dst), IP_ADDR_STR_LEN - 1);
    np.ttl = ip->ip_ttl;
    np.header_checksum = ntohs(ip->ip_sum); 
    np.identification = ntohs(ip->ip_id);

    uint16_t offset_field = ntohs(ip->ip_off);
    np.flags = offset_field >> 13;
    np.fragment_offset = offset_field & 0x1FFF;

    np.total_length = ntohs(ip->ip_len);
    np.protocol = ip->ip_p;

    if (np.protocol == IPPROTO_TCP) {
        tcp = (sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        int size_tcp = TH_OFF(tcp) * 4;
        if (size_tcp < 20) return;

        np.src_port = ntohs(tcp->th_sport);
        np.dst_port = ntohs(tcp->th_dport);
        np.sequence_number = ntohl(tcp->th_seq);
        np.acknowledgment_number = ntohl(tcp->th_ack);
        np.window_size = ntohs(tcp->th_win);
        np.tcp_flags = tcp->th_flags;

        const u_char* payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
        int size_payload = np.total_length - (size_ip + size_tcp);
        
        if (size_payload > 0) {
            np.payload_size = size_payload <= MAX_PAYLOAD_SIZE ? size_payload : MAX_PAYLOAD_SIZE;
            memcpy(np.payload, payload, np.payload_size);
        }
        
        string proto = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
        strncpy(np.app_protocol, proto.c_str(), APP_PROTO_STR_LEN - 1);
        
        if (proto == "HTTPS" && np.payload_size > 0) {
            ExtractSSLCertificate(np);
        }
    }
    else if(np.protocol == IPPROTO_UDP){
        const sniff_udp* udp = (sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
        np.src_port = ntohs(udp->uh_sport);
        np.dst_port = ntohs(udp->uh_dport);
        np.udp_length = ntohs(udp->uh_ulen);

        const u_char* payload = packet + SIZE_ETHERNET + size_ip + 8;
        int size_payload = np.udp_length - 8;

        if (size_payload > 0){
            np.payload_size = size_payload <= MAX_PAYLOAD_SIZE ? size_payload : MAX_PAYLOAD_SIZE;
            memcpy(np.payload, payload, np.payload_size);
        }
        
        string proto = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
        strncpy(np.app_protocol, proto.c_str(), APP_PROTO_STR_LEN - 1);
    }
    else if(np.protocol == IPPROTO_ICMP){
        const sniff_icmp* icmp = (sniff_icmp*)(packet + SIZE_ETHERNET + size_ip);
        np.icmp_type = icmp->icmp_type;
        np.icmp_code = icmp->icmp_code;

        const int icmp_header_len = sizeof(sniff_icmp);
        const u_char* payload = packet + SIZE_ETHERNET + size_ip + icmp_header_len;
        int size_payload = np.total_length - (size_ip + icmp_header_len);

        if (size_payload > 0) {
            np.payload_size = size_payload <= MAX_PAYLOAD_SIZE ? size_payload : MAX_PAYLOAD_SIZE;
            memcpy(np.payload, payload, np.payload_size);
        }
        
        string proto = DetectAppProtocol(np.protocol, np.src_port, np.dst_port);
        strncpy(np.app_protocol, proto.c_str(), APP_PROTO_STR_LEN - 1);
    }

    PushToJsonDB(np, np.protocol);
    SendToPEP(np);
}

void FindInterfaces(){
    if (!global_interface_1.empty() && !global_interface_2.empty()) {
        return; 
    }

    pcap_if_t *alldevices;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevices, errbuf) == -1) {
        cerr << "Error finding devices: " << errbuf << '\n';
        return;
    }

    for(pcap_if_t *d = alldevices; d != NULL; d = d->next) {
        if (string(d->name) == "lo" || string(d->name) == "any") continue; 

        if (global_interface_1.empty()) {
            global_interface_1 = d->name;
        } 
        else if (global_interface_2.empty() && global_interface_1 != d->name) {
            global_interface_2 = d->name;
        }

        if (!global_interface_1.empty() && !global_interface_2.empty()) {
            break;
        }
    }

    pcap_freealldevs(alldevices);
}

void Sniff(string name){
    if (name.empty()) return;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(name.c_str(), 65535, true, 100, errbuf);

    if(handle == NULL){
        cerr << "Couldn't open device " << name << ": " << errbuf << endl;
        return;
    }

    cout << "Started sniffing on interface: " << name << endl;
    
    pcap_loop(handle, 0, PacketHandler, (u_char*)name.c_str());
    
    pcap_close(handle);
}

int main(){
    FindInterfaces();

    if (global_interface_1.empty()) {
        cerr << "No interfaces found to sniff on!\n";
        return 1;
    }

    if(!InitPEPSocket()){
        cout << "Exiting because of unix socket failure...\n";
        return 1;
    }
    cout << "Capture module connected to PEP!\n";

    thread t1;
    thread t2;

    if (!global_interface_1.empty()) {
        t1 = thread(Sniff, global_interface_1);
    }
    if (!global_interface_2.empty()) {
        t2 = thread(Sniff, global_interface_2);
    }

    if (t1.joinable()) t1.join();
    if (t2.joinable()) t2.join();

    return 0;
}