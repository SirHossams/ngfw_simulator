#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <csignal>
#include <mutex>
#include <atomic>
#include <nlohmann/json.hpp>
#include "../../shared-headers/packet.h"

using namespace std;

int sock = -1, connection = -1;
#define PORT 9000

atomic<bool> reload_requested{false};
atomic<bool> keep_running{true};

void signal_handler(int signum) {
    if (signum == SIGUSR1) {
        reload_requested = true;
    }
}

// ================= Prototypes =================
int InitPEPSocket();
int ReceiveFromPEP(NormalizedPacket& pkt);
void SendVerdictToPEP(uint64_t seq_num, bool allow);

// ================= Trust Algorithm =================

class TrustAlgorithm {
private:
    nlohmann::json ip_rep_db;
    nlohmann::json fp_db;
    nlohmann::json anom_db;
    mutex db_mutex;

public:
    TrustAlgorithm() {
        Reload();
    }

    void Reload() {
        lock_guard<mutex> lock(db_mutex);
        nlohmann::json temp_ip, temp_fp, temp_anom;

        ifstream in_ip("core/databases/ip_reputation.json");
        if (in_ip.is_open()) {
            try { in_ip >> temp_ip; ip_rep_db = temp_ip; } 
            catch(...) { cerr << "[!] Failed to parse ip_reputation.json\n"; }
            in_ip.close();
        }

        ifstream in_fp("core/databases/fingerprints.json");
        if (in_fp.is_open()) {
            try { in_fp >> temp_fp; fp_db = temp_fp; } 
            catch(...) { cerr << "[!] Failed to parse fingerprints.json\n"; }
            in_fp.close();
        }

        ifstream in_anom("core/databases/anomalies.json");
        if (in_anom.is_open()) {
            try { in_anom >> temp_anom; anom_db = temp_anom; } 
            catch(...) { cerr << "[!] Failed to parse anomalies.json\n"; }
            in_anom.close();
        }
        
        cout << "[System] PE successfully hot-reloaded Intelligence Databases.\n";
    }

    double Evaluate(const NormalizedPacket& pkt) {
        lock_guard<mutex> lock(db_mutex);
        double risk_score = 0.0;

        if (ip_rep_db.is_array()) {
            for (const auto& rep : ip_rep_db) {
                if (rep.value("ip_address", "") == string(pkt.src_ip)) {
                    risk_score += rep.value("score", 0.0);
                    break; 
                }
            }
        }

        if (anom_db.is_array()) {
            for (const auto& anom : anom_db) {
                string name = anom.value("name", "");
                double score = anom.value("score", 0.0);

                if (name == "TCP_NULL_SCAN" && pkt.protocol == IPPROTO_TCP && pkt.tcp_flags == 0) {
                    risk_score += score;
                } else if (name == "TCP_SYN_FIN" && pkt.protocol == IPPROTO_TCP && (pkt.tcp_flags & 0x03) == 0x03) {
                    risk_score += score;
                } else if (name == "TCP_SYN_RST" && pkt.protocol == IPPROTO_TCP && (pkt.tcp_flags & 0x06) == 0x06) {
                    risk_score += score;
                } else if (name == "LAND_ATTACK" && strcmp(pkt.src_ip, pkt.dst_ip) == 0 && pkt.src_port == pkt.dst_port) {
                    risk_score += score;
                } else if (name == "LOW_TTL" && pkt.ttl < anom.value("ttl_less_than", 5)) {
                    risk_score += score;
                } else if (name == "ZERO_WINDOW" && pkt.protocol == IPPROTO_TCP && pkt.window_size == 0) {
                    risk_score += score;
                } else if (name == "INVALID_PORT_ZERO" && (pkt.src_port == 0 || pkt.dst_port == 0)) {
                    risk_score += score;
                } else if (name == "LARGE_TOTAL_LENGTH" && pkt.total_length > anom.value("total_length_greater_than", 2000)) {
                    risk_score += score;
                }
            }
        }

        if (fp_db.is_array() && pkt.payload_size > 0) {
            string payload_str(pkt.payload, pkt.payload + pkt.payload_size);
            string pkt_app_proto(pkt.app_protocol);
            
            for (const auto& fp : fp_db) {
                string app_proto = fp.value("app_protocol", "");
                
                if (app_proto == pkt_app_proto || app_proto == "ANY") {
                    if (fp.contains("payload") && fp["payload"].is_array()) {
                        for (const auto& pattern_val : fp["payload"]) {
                            string pattern = pattern_val.get<string>();
                            
                            if (payload_str.find(pattern) != string::npos) {
                                risk_score += fp.value("score", 0.0);
                                cout << "      -> Found Signature Match: " << fp.value("description", "") << "\n";
                                break; 
                            }
                        }
                    }
                }
            }
        }

        return risk_score;
    }
};

// ================= Networking =================

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
    
    // Timeout prevents infinite freezing
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms timeout
    setsockopt(connection, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    cout << "PEP connected to PE!\n";
    return 0;
}

int ReceiveFromPEP(NormalizedPacket& pkt) {
    uint32_t size = 0;
    int bytes_received = recv(connection, &size, sizeof(size), 0);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0; // Timeout
        return -1; // Error
    }
    if (bytes_received == 0) return -1; // Disconnect

    int total_read = 0;
    auto* ptr = reinterpret_cast<uint8_t*>(&pkt);
    while (total_read < size) {
        int bytes_read = recv(connection, ptr + total_read, size - total_read, 0);
        if (bytes_read <= 0) return -1;
        total_read += bytes_read;
    }
    return 1;
}

void SendVerdictToPEP(uint64_t seq_num, bool allow) {
    struct VerdictReply {
        uint64_t seq;
        uint8_t verdict;
    } reply = {seq_num, allow ? (uint8_t)1 : (uint8_t)0};
    
    send(connection, &reply, sizeof(reply), MSG_NOSIGNAL);
}

// ================= Main Loop =================

int main() {
    signal(SIGUSR1, signal_handler);

    if (InitPEPSocket() != 0) 
        return 1;

    TrustAlgorithm trust_engine;

    while (keep_running) {
        if (reload_requested) {
            trust_engine.Reload();
            reload_requested = false;
        }

        NormalizedPacket pkt;
        int status = ReceiveFromPEP(pkt);
        
        if (status == -1) {
            cout << "PEP disconnected or error receiving.\n";
            break;
        }
        if (status == 0) {
            continue;
        }

        cout << "PE Evaluated Frame #" << pkt.capture_sequence_number << "\n";
        
        double risk_score = trust_engine.Evaluate(pkt);
        bool isAllowed = (risk_score <= 80.0); 
        
        if (isAllowed) {
            cout << "   -> Passed Trust Algorithm (Risk Score: " << risk_score << ")\n";
        } else {
            cout << "   -> Dropped by Trust Algorithm (Risk Score: " << risk_score << ")\n";
        }

        SendVerdictToPEP(pkt.capture_sequence_number, isAllowed);
        cout << "-----------------------------------\n";
    }

    close(connection);
    close(sock);
    return 0;
}