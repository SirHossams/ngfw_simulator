#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <fstream>
#include <nlohmann/json.hpp>
#include "../../shared-headers/packet.h"

using namespace std;

// Globals
int pep_server_socket = -1;
int capture_client_socket = -1;
int pe_network_socket = -1;
atomic<bool> keep_running{true};

unordered_map<uint64_t, NormalizedPacket> pending_packets;
mutex pending_mutex;

struct VerdictReply {
    uint64_t seq_num;
    uint8_t verdict; 
};

// ================= IP And Port Checker =================

class IPAndPortChecker {
private:
    nlohmann::json acl_db;

    string GetSafeString(const nlohmann::json& rule, const string& key) {
        if (!rule.contains(key)) return "0";
        if (rule[key].is_string()) return rule[key].get<string>();
        if (rule[key].is_number()) return to_string(rule[key].get<int>());
        return "0";
    }

    uint16_t GetSafePort(const nlohmann::json& rule, const string& key) {
        if (!rule.contains(key)) return 0;
        if (rule[key].is_number()) return rule[key].get<uint16_t>();
        if (rule[key].is_string()) {
            try { return stoi(rule[key].get<string>()); } catch(...) { return 0; }
        }
        return 0;
    }

    int GetSafeType(const nlohmann::json& rule, const string& key) {
        if (!rule.contains(key)) return 0;
        if (rule[key].is_number()) return rule[key].get<int>();
        if (rule[key].is_string()) {
            try { return stoi(rule[key].get<string>()); } catch(...) { return 0; }
        }
        return 0;
    }

public:
    IPAndPortChecker() {
        // PRELOAD ACL into memory to prevent file I/O bottlenecks!
        ifstream in("core/databases/acl.json"); 
        if (in.is_open()) {
            try { in >> acl_db; } 
            catch(...) { cerr << "Failed to parse acl.json\n"; }
            in.close();
        } else {
            cerr << "Warning: Could not open acl.json\n";
        }
    }

    bool CheckACL(const NormalizedPacket& pkt) {
        if (!acl_db.is_array()) return false;

        for (const auto& rule : acl_db) {
            string ip1 = GetSafeString(rule, "ip_address_1");
            string ip2 = GetSafeString(rule, "ip_address_2");
            string mac1 = GetSafeString(rule, "mac_address_1");
            string mac2 = GetSafeString(rule, "mac_address_2");
            
            uint16_t port1 = GetSafePort(rule, "port_1");
            uint16_t port2 = GetSafePort(rule, "port_2");
            int type = GetSafeType(rule, "type");

            bool match_forward = 
                (ip1 == "0" || ip1 == pkt.src_ip) &&
                (ip2 == "0" || ip2 == pkt.dst_ip) &&
                (mac1 == "0" || mac1 == pkt.src_mac) &&
                (mac2 == "0" || mac2 == pkt.dst_mac) &&
                (port1 == 0  || port1 == pkt.src_port) &&
                (port2 == 0  || port2 == pkt.dst_port);

            bool match_backward = 
                (ip2 == "0" || ip2 == pkt.src_ip) &&
                (ip1 == "0" || ip1 == pkt.dst_ip) &&
                (mac2 == "0" || mac2 == pkt.src_mac) &&
                (mac1 == "0" || mac1 == pkt.dst_mac) &&
                (port2 == 0  || port2 == pkt.src_port) &&
                (port1 == 0  || port1 == pkt.dst_port);

            if (strcmp(pkt.app_protocol, "HTTP") == 0 || strcmp(pkt.app_protocol, "HTTPS") == 0 || strcmp(pkt.app_protocol, "DNS") == 0) {
                if (match_forward || match_backward) return true;
            } 
            else {
                if ((type == 1 || type == 0) && match_forward) return true;
                if ((type == -1 || type == 0) && match_backward) return true;
            }
        }
        return false; 
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

            if (src_ip == pkt.src_ip && dst_ip == pkt.dst_ip &&
                src_port == pkt.src_port && dst_port == pkt.dst_port &&
                app_protocol == pkt.app_protocol) {
                return true;
            }
            if (src_ip == pkt.dst_ip && dst_ip == pkt.src_ip &&
                src_port == pkt.dst_port && dst_port == pkt.src_port &&
                app_protocol == pkt.app_protocol) {
                return true;
            }
        }
        return false;
    }
};

void CreateSession(const NormalizedPacket& pkt) {
    using ordered_json = nlohmann::ordered_json;
    ordered_json state_db = ordered_json::array();
    
    ifstream in("core/databases/state.json");
    if (in.good()) {
        try { in >> state_db; } 
        catch (...) { state_db = ordered_json::array(); }
    }
    in.close();

    ordered_json new_session;
    new_session["src_ip"] = string(pkt.src_ip);
    new_session["dst_ip"] = string(pkt.dst_ip);
    new_session["src_port"] = pkt.src_port;
    new_session["dst_port"] = pkt.dst_port;
    new_session["app_protocol"] = string(pkt.app_protocol);
    
    state_db.push_back(new_session);
    
    ofstream out("core/databases/state.json");
    out << state_db.dump(4);
}

// ================= Networking =================

bool InitPktCapSocket(){
    pep_server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (pep_server_socket < 0) return false;

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/pep.sock", sizeof(addr.sun_path) - 1);
    unlink("/tmp/pep.sock");

    if (bind(pep_server_socket, (sockaddr*)&addr, sizeof(addr)) < 0) return false;
    if (listen(pep_server_socket, 5) < 0) return false;

    cout << "PEP waiting for capture module to connect via Unix Socket...\n";
    capture_client_socket = accept(pep_server_socket, nullptr, nullptr);
    if (capture_client_socket < 0) return false;

    cout << "Capture module connected to PEP!\n";
    return true;
}

bool ConnectToPE() {
    pe_network_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (pe_network_socket < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9000);
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(pe_network_socket, (sockaddr*)&addr, sizeof(addr)) < 0) return false;
    cout << "PEP connected to Policy Engine!\n";
    return true;
}

bool ReceiveFromPC(NormalizedPacket& pkt) {
    uint32_t size = 0;
    int bytes_received = recv(capture_client_socket, &size, sizeof(size), 0);
    if (bytes_received <= 0) return false;

    int total_read = 0;
    auto* ptr = reinterpret_cast<uint8_t*>(&pkt);
    while (total_read < size) {
        int bytes_read = recv(capture_client_socket, ptr + total_read, size - total_read, 0);
        if (bytes_read <= 0) return false;
        total_read += bytes_read;
    }
    return true;
}

bool SendToPE(const NormalizedPacket& pkt) {
    if (pe_network_socket < 0) return false;
    uint32_t size = sizeof(NormalizedPacket);
    if (send(pe_network_socket, &size, sizeof(size), MSG_NOSIGNAL) <= 0) return false;
    if (send(pe_network_socket, &pkt, sizeof(NormalizedPacket), MSG_NOSIGNAL) <= 0) return false;
    return true;
}

// ================= Background Thread for Verdicts =================
void VerdictReceiverLoop() {
    while (keep_running) {
        VerdictReply reply{0, 0};
        int bytes_read = recv(pe_network_socket, &reply, sizeof(reply), 0);
        
        if (bytes_read <= 0) {
            if (keep_running) {
                cout << "PE disconnected. Shutting down verdict thread...\n";
                keep_running = false;
            }
            break;
        }

        NormalizedPacket pkt;
        bool found = false;
        
        {
            lock_guard<mutex> lock(pending_mutex);
            auto it = pending_packets.find(reply.seq_num);
            if (it != pending_packets.end()) {
                pkt = it->second;
                pending_packets.erase(it);
                found = true;
            }
        }

        if (reply.verdict == 1) {
            cout << "[VERDICT] Frame #" << reply.seq_num << " -> ALLOW. Packet forwarded.\n";
            if (found) {
                CreateSession(pkt); 
            }
        } else {
            cout << "[VERDICT] Frame #" << reply.seq_num << " -> DROP. Packet destroyed.\n";
        }
    }
}

// ================= Main =================
int main() {
    if (!ConnectToPE()) {
        cerr << "Failed to connect to PE.\n";
        return 1;
    }

    if (!InitPktCapSocket()) {
        return 1;
    }

    IPAndPortChecker checker;
    thread verdict_thread(VerdictReceiverLoop);

    while (keep_running) {
        NormalizedPacket pkt;
        if (!ReceiveFromPC(pkt)) {
            cout << "Capture module disconnected. Exiting PEP...\n";
            keep_running = false;
            break;
        }

        // 1. IP and Port Checker (ACL)
        if (!checker.CheckACL(pkt)) {
            // Enhanced logging to show EXACTLY what is dropping
            string proto = strlen(pkt.app_protocol) > 0 ? pkt.app_protocol : "UNKNOWN/L2";
            cout << "[PEP] Frame #" << pkt.capture_sequence_number 
                 << " -> Dropped by ACL | Proto: " << proto 
                 << " | " << pkt.src_ip << " -> " << pkt.dst_ip << "\n";
            continue;
        } 
        
        // 2. State Table (Metadata Check)
        if (checker.CheckStateTable(pkt)) {
            cout << "[PEP] Frame #" << pkt.capture_sequence_number << " -> Passed (Existing Session in State Table)\n";
            continue;
        } 
        
        // 3. Send to PE and wait...
        {
            lock_guard<mutex> lock(pending_mutex);
            pending_packets[pkt.capture_sequence_number] = pkt;
        }

        if (!SendToPE(pkt)) {
            cout << "PE disconnected or error forwarding. Exiting PEP...\n";
            keep_running = false;
            break;
        }
    }

    keep_running = false;
    shutdown(pe_network_socket, SHUT_RDWR);
    if (verdict_thread.joinable()) verdict_thread.join();

    close(capture_client_socket);
    close(pep_server_socket);
    close(pe_network_socket);
    unlink("/tmp/pep.sock");
    
    return 0;
}