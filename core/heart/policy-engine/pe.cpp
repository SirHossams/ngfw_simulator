#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <nlohmann/json.hpp>
#include "../../shared-headers/packet.h"

using namespace std;

int sock = -1, connection = -1;
#define PORT 9000

// ================= Prototypes =================
int InitPEPSocket();
NormalizedPacket DeserializePacket(const vector<uint8_t>& buffer);
NormalizedPacket ReceiveFromPEP();
void SendVerdictToPEP(uint64_t seq_num, bool allow);
void CreateSession(const NormalizedPacket& pkt);

// ================= Architecture Classes =================

class IPAndPortChecker {
public:
    IPAndPortChecker() {}

    bool CheckACL(const NormalizedPacket& pkt) {
        ifstream in("core/databases/acl.json"); 
        if (!in.is_open()) return false; 

        nlohmann::json acl_db;
        try { in >> acl_db; } 
        catch(...) { return false; }

        for (const auto& rule : acl_db) {
            // Thanks to your JSON edits, we can now safely read these directly as strings
            string ip1 = rule.value("ip_address_1", "0");
            string ip2 = rule.value("ip_address_2", "0");
            string mac1 = rule.value("mac_address_1", "0");
            string mac2 = rule.value("mac_address_2", "0");
            
            uint16_t port1 = rule.value("port_1", 0);
            uint16_t port2 = rule.value("port_2", 0);
            int type = rule.value("type", 0);

            // Forward Match: 1 is Source, 2 is Destination. (Ignore if the rule value is "0" or 0)
            bool match_forward = 
                (ip1 == "0" || ip1 == pkt.src_ip) &&
                (ip2 == "0" || ip2 == pkt.dst_ip) &&
                (mac1 == "0" || mac1 == pkt.src_mac) &&
                (mac2 == "0" || mac2 == pkt.dst_mac) &&
                (port1 == 0  || port1 == pkt.src_port) &&
                (port2 == 0  || port2 == pkt.dst_port);

            // Backward Match: 2 is Source, 1 is Destination. (Ignore if the rule value is "0" or 0)
            bool match_backward = 
                (ip2 == "0" || ip2 == pkt.src_ip) &&
                (ip1 == "0" || ip1 == pkt.dst_ip) &&
                (mac2 == "0" || mac2 == pkt.src_mac) &&
                (mac1 == "0" || mac1 == pkt.dst_mac) &&
                (port2 == 0  || port2 == pkt.src_port) &&
                (port1 == 0  || port1 == pkt.dst_port);

            // Rule 1: HTTP, HTTPS, or DNS allow bidirectional matching regardless of "type"
            if (pkt.app_protocol == "HTTP" || pkt.app_protocol == "HTTPS" || pkt.app_protocol == "DNS") {
                if (match_forward || match_backward) return true;
            } 
            // Rule 2: Other protocols strictly follow "type" (-1 Inbound, 1 Outbound, 0 Both)
            else {
                // Outbound (1) or Both (0)
                if ((type == 1 || type == 0) && match_forward) return true;
                
                // Inbound (-1) or Both (0)
                if ((type == -1 || type == 0) && match_backward) return true;
            }
        }
        return false; // Default block if no rules match
    }

    bool CheckStateTable(const NormalizedPacket& pkt) {
        ifstream in("core/databases/state.json");
        if (!in.is_open()) return false;

        nlohmann::json state_db;
        try { in >> state_db; } 
        catch(...) { return false; }

        for (const auto& session : state_db) {
            string src_ip = session.value("src_ip", "");
            string dst_ip = session.value("dst_ip", "");
            uint16_t src_port = session.value("src_port", 0);
            uint16_t dst_port = session.value("dst_port", 0);
            string app_protocol = session.value("app_protocol", "");

            // Check forward direction
            if (src_ip == pkt.src_ip && dst_ip == pkt.dst_ip &&
                src_port == pkt.src_port && dst_port == pkt.dst_port &&
                app_protocol == pkt.app_protocol) {
                return true;
            }
            // Check reverse direction (response packets from the session)
            if (src_ip == pkt.dst_ip && dst_ip == pkt.src_ip &&
                src_port == pkt.dst_port && dst_port == pkt.src_port &&
                app_protocol == pkt.app_protocol) {
                return true;
            }
        }
        return false;
    }
};

class TrustAlgorithm {
public:
    TrustAlgorithm() {}

    double Evaluate(const NormalizedPacket& pkt) {
        // TODO: Implement Page 2 logic (Payload Investigator, Metadata Investigator)
        double risk_score = 0.0;
        return risk_score;
    }
};

// ================= Networking & Serialization =================

int InitPEPSocket(){
    struct sockaddr_in address;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock==-1){
        cerr << "Socket failed!";
        return 1;
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if(bind(sock, (struct sockaddr*)&address, sizeof(address)) < 0){
        cerr << "Bind failed!";
        return 1;
    }

    if(listen(sock, 3) < 0){
        cerr << "Listen failed!";
        return 1;
    }

    cout << "PE Server listening on port " << PORT << "...\n";

    socklen_t addrlen = sizeof(address);
    connection = accept(sock, (struct sockaddr*)&address, &addrlen);
    if(connection < 0){
        cerr << "Connection couldn't be accepted!";
        return 1;
    }
    
    cout << "PEP connected to PE!\n";
    return 0;
}

NormalizedPacket DeserializePacket(const vector<uint8_t>& buffer) {
    NormalizedPacket np;
    size_t offset = 0;

    auto read_data = [&](void* dest, size_t size) {
        if (offset + size <= buffer.size()) {
            memcpy(dest, buffer.data() + offset, size);
            offset += size;
        }
    };

    auto read_string = [&]() -> string {
        uint32_t len = 0;
        read_data(&len, sizeof(len));
        if (len > 0 && offset + len <= buffer.size()) {
            string str((char*)(buffer.data() + offset), len);
            offset += len;
            return str;
        }
        return "";
    };

    read_data(&np.capture_sequence_number, sizeof(np.capture_sequence_number));
    read_data(&np.capture_timestamp_sec, sizeof(np.capture_timestamp_sec));
    read_data(&np.capture_timestamp_usec, sizeof(np.capture_timestamp_usec));

    np.src_mac = read_string();
    np.dst_mac = read_string();

    read_data(&np.ether_type, sizeof(np.ether_type));

    if (np.ether_type == 0x0806) {
        read_data(&np.arp_opcode, sizeof(np.arp_opcode));
        np.arp_src_ip = read_string();
        np.arp_dst_ip = read_string();
    } 
    else {
        read_data(&np.ip_version, sizeof(np.ip_version));
        np.src_ip = read_string();
        np.dst_ip = read_string();
        read_data(&np.ttl, sizeof(np.ttl));
        read_data(&np.header_checksum, sizeof(np.header_checksum));
        read_data(&np.identification, sizeof(np.identification));
        read_data(&np.flags, sizeof(np.flags));
        read_data(&np.fragment_offset, sizeof(np.fragment_offset));
        read_data(&np.total_length, sizeof(np.total_length));
        read_data(&np.protocol, sizeof(np.protocol));

        if (np.protocol == IPPROTO_TCP) {
            read_data(&np.src_port, sizeof(np.src_port));
            read_data(&np.dst_port, sizeof(np.dst_port));
            read_data(&np.sequence_number, sizeof(np.sequence_number));
            read_data(&np.acknowledgment_number, sizeof(np.acknowledgment_number));
            read_data(&np.window_size, sizeof(np.window_size));
            read_data(&np.tcp_flags, sizeof(np.tcp_flags));
            np.app_protocol = read_string();

            uint32_t cert_size = 0;
            read_data(&cert_size, sizeof(cert_size));
            if (cert_size > 0 && offset + cert_size <= buffer.size()) {
                np.ssl_certificate.assign(buffer.begin() + offset, buffer.begin() + offset + cert_size);
                offset += cert_size;
            }
        } 
        else if (np.protocol == IPPROTO_UDP) {
            read_data(&np.src_port, sizeof(np.src_port));
            read_data(&np.dst_port, sizeof(np.dst_port));
            read_data(&np.udp_length, sizeof(np.udp_length));
            np.app_protocol = read_string();
        } 
        else if (np.protocol == IPPROTO_ICMP) {
            read_data(&np.icmp_type, sizeof(np.icmp_type));
            read_data(&np.icmp_code, sizeof(np.icmp_code));
            np.app_protocol = read_string();
        }
    }

    uint32_t payload_size = 0;
    read_data(&payload_size, sizeof(payload_size));
    if (payload_size > 0 && offset + payload_size <= buffer.size()) {
        np.payload.assign(buffer.begin() + offset, buffer.begin() + offset + payload_size);
        offset += payload_size;
    }

    return np;
}

NormalizedPacket ReceiveFromPEP() {
    uint32_t size = 0;

    int bytes_received = recv(connection, &size, sizeof(size), 0);
    if (bytes_received <= 0) {
        NormalizedPacket empty_packet;
        empty_packet.capture_sequence_number = 0; 
        return empty_packet;
    }

    vector<uint8_t> buffer(size);
    uint32_t total_read = 0;

    while (total_read < size) {
        int bytes_read = recv(connection, buffer.data() + total_read, size - total_read, 0);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }

    return DeserializePacket(buffer);
}

void SendVerdictToPEP(uint64_t seq_num, bool allow) {
    // Pack the sequence number and the verdict together for asynchronous tracking
    struct VerdictReply {
        uint64_t seq;
        uint8_t verdict;
    } reply = {seq_num, allow ? (uint8_t)1 : (uint8_t)0};
    
    send(connection, &reply, sizeof(reply), MSG_NOSIGNAL);
}

void CreateSession(const NormalizedPacket& pkt) {
    cout << "   -> Session created for " << pkt.src_ip << ":" << pkt.src_port << "\n";
    
    // Automatically write the new session to the state table
    using ordered_json = nlohmann::ordered_json;
    ordered_json state_db = ordered_json::array();
    
    ifstream in("core/databases/state.json");
    if (in.good()) {
        try { in >> state_db; } 
        catch (...) { state_db = ordered_json::array(); }
    }
    in.close();

    ordered_json new_session;
    new_session["src_ip"] = pkt.src_ip;
    new_session["dst_ip"] = pkt.dst_ip;
    new_session["src_port"] = pkt.src_port;
    new_session["dst_port"] = pkt.dst_port;
    new_session["app_protocol"] = pkt.app_protocol;
    
    state_db.push_back(new_session);
    
    ofstream out("core/databases/state.json");
    out << state_db.dump(4);
}

// ================= Main =================

int main() {
    if (InitPEPSocket() != 0) 
        return 1;

    IPAndPortChecker checker;
    TrustAlgorithm trust_engine;

    while (true) {
        NormalizedPacket pkt = ReceiveFromPEP();
        
        if (pkt.capture_sequence_number == 0) {
            cout << "PEP disconnected or error receiving.\n";
            break;
        }

        cout << "PE Evaluated Frame #" << pkt.capture_sequence_number << "\n";
        bool isAllowed = false;
        
        // 1. IP and Port Checker (ACL)
        if (!checker.CheckACL(pkt)) {
            cout << "   -> Dropped by ACL\n";
            isAllowed = false;
        } else {
            // 2. State Table (Metadata Check)
            if (checker.CheckStateTable(pkt)) {
                cout << "   -> Passed (Existing Session in State Table)\n";
                isAllowed = true;
            } else {
                // 3. Trust Algorithm (Complex Algorithm)
                double risk_score = trust_engine.Evaluate(pkt);
                
                if (risk_score > 80.0) {
                    cout << "   -> Dropped by Trust Algorithm (Score: " << risk_score << ")\n";
                    isAllowed = false;
                } else {
                    cout << "   -> Passed Trust Algorithm (Score: " << risk_score << ")\n";
                    CreateSession(pkt);
                    isAllowed = true;
                }
            }
        }

        SendVerdictToPEP(pkt.capture_sequence_number, isAllowed);
        cout << "-----------------------------------\n";
    }

    close(connection);
    close(sock);
    return 0;
}