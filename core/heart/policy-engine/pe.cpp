#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <vector>
#include <fstream>
#include <thread>
#include <mutex>
#include <atomic>
#include <csignal>
#include <nlohmann/json.hpp>
#include "../../shared-headers/packet.h"

using namespace std;

atomic<bool> keep_running{true};
atomic<bool> reload_requested{false};
int data_connection = -1;

// Signal Handler for Hot Reload
void signal_handler_pe(int signum) {
    if (signum == SIGUSR1) reload_requested = true;
}

void ControlPlaneLoop() {
    int control_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/module-body.sock", sizeof(addr.sun_path)-1);
    unlink("/tmp/module-body.sock");
    bind(control_sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(control_sock, 1);
    
    cout << "[PE] Waiting for ModuleHead to connect to Control Plane...\n";
    int mh_client = accept(control_sock, nullptr, nullptr);
    
    if (mh_client >= 0) {
        cout << "[PE] ModuleHead Connected. Waiting for JSON Instructions...\n";
        char buffer[8192];
        int bytes = recv(mh_client, buffer, sizeof(buffer)-1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string raw_msg(buffer, bytes);
            size_t start = raw_msg.find('{');
            if (start != std::string::npos) {
                cout << "[PE] Instructions Successfully Extracted and Loaded.\n";
            }
        }
        
        while (keep_running) {
            std::string status = "{\"Status\": \"Active\", \"Module\": \"Policy Engine\", \"Analyzed_Packets\": \"Nominal\"}";
            send(mh_client, status.c_str(), status.length(), 0);
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    close(mh_client);
    close(control_sock);
}

int InitPEDataSocket() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/pe-data.sock", sizeof(addr.sun_path)-1);
    unlink("/tmp/pe-data.sock");
    bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    listen(sock, 3);
    
    cout << "[PE] Waiting for ModuleHead Data Proxy to connect...\n";
    int conn = accept(sock, nullptr, nullptr);
    cout << "[PE] ModuleHead Data Plane connected successfully!\n";

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000; 
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    return conn;
}

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

        ifstream in_ip("core/databases/ip-reputation.json");
        if (in_ip.is_open()) { try { in_ip >> temp_ip; ip_rep_db = temp_ip; } catch(...) {} in_ip.close(); }

        ifstream in_fp("core/databases/fingerprints.json");
        if (in_fp.is_open()) { try { in_fp >> temp_fp; fp_db = temp_fp; } catch(...) {} in_fp.close(); }

        ifstream in_anom("core/databases/anomalies.json");
        if (in_anom.is_open()) { try { in_anom >> temp_anom; anom_db = temp_anom; } catch(...) {} in_anom.close(); }
        
        cout << "[System] PE successfully hot-reloaded Intelligence Databases.\n";
    }

    double Evaluate(const NormalizedPacket& pkt) {
        lock_guard<mutex> lock(db_mutex);
        double risk_score = 0.0;

        if (ip_rep_db.is_array()) {
            for (const auto& rep : ip_rep_db) {
                string bad_ip = rep.value("ip_address", "");
                
                if (bad_ip == string(pkt.src_ip) || bad_ip == string(pkt.dst_ip)) {
                    risk_score += rep.value("score", 0.0);
                    cout << "      -> IP Reputation Match on: " << bad_ip << "\n";
                    break; 
                }
            }
        }

        if (anom_db.is_array()) {
            for (const auto& anom : anom_db) {
                string name = anom.value("name", "");
                double score = anom.value("score", 0.0);

                if (name == "TCP_NULL_SCAN" && pkt.protocol == IPPROTO_TCP && pkt.tcp_flags == 0) risk_score += score;
                else if (name == "LAND_ATTACK" && strcmp(pkt.src_ip, pkt.dst_ip) == 0 && pkt.src_port == pkt.dst_port) risk_score += score;
                else if (name == "LOW_TTL" && pkt.ttl < anom.value("ttl_less_than", 5)) risk_score += score;
                else if (name == "ZERO_WINDOW" && pkt.protocol == IPPROTO_TCP && pkt.window_size == 0) risk_score += score;
                else if (name == "INVALID_PORT_ZERO" && (pkt.src_port == 0 || pkt.dst_port == 0)) risk_score += score;
            }
        }

        if (fp_db.is_array() && pkt.payload_size > 0) {
            string payload_str(pkt.payload, pkt.payload + pkt.payload_size);
            string pkt_app_proto(pkt.app_protocol);
            
            for (const auto& fp : fp_db) {
                // string app_proto = fp.value("app_protocol", "");
                // if (app_proto == pkt_app_proto || app_proto == "ANY") {
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
                // }
            }
        }
        return risk_score;
    }
};

int ReceiveFromModuleHead(NormalizedPacket& pkt) {
    uint32_t size = 0;
    int bytes_received = recv(data_connection, &size, sizeof(size), 0);
    
    if (bytes_received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0; 
        return -1; // Error
    }
    if (bytes_received == 0) return -1; 

    uint32_t total_read = 0; 
    auto* ptr = reinterpret_cast<uint8_t*>(&pkt);
    while (total_read < size) {
        int bytes_read = recv(data_connection, ptr + total_read, size - total_read, 0);
        if (bytes_read <= 0) return -1;
        total_read += bytes_read;
    }
    return 1;
}

void SendVerdictToModuleHead(uint64_t seq_num, bool allow) {
    struct VerdictReply {
        uint64_t seq;
        uint8_t verdict;
    } reply = {seq_num, allow ? (uint8_t)1 : (uint8_t)0};
    
    send(data_connection, &reply, sizeof(reply), MSG_NOSIGNAL);
}

int main() {
    signal(SIGUSR1, signal_handler_pe);

    std::thread control_thread(ControlPlaneLoop);

    data_connection = InitPEDataSocket();
    if (data_connection < 0) return 1;

    TrustAlgorithm trust_engine;

    while (keep_running) {
        if (reload_requested) {
            trust_engine.Reload();
            reload_requested = false;
        }

        NormalizedPacket pkt;
        int status = ReceiveFromModuleHead(pkt);
        
        if (status == -1) {
            cout << "ModuleHead disconnected. Exiting...\n";
            break;
        }
        if (status == 0) continue; 

        cout << "PE Evaluated Frame #" << pkt.capture_sequence_number << "\n";
        
        double risk_score = trust_engine.Evaluate(pkt);
        bool isAllowed = (risk_score <= 80.0); 
        
        if (isAllowed) cout << "   -> Passed Trust Algorithm (Risk Score: " << risk_score << ")\n";
        else cout << "   -> Dropped by Trust Algorithm (Risk Score: " << risk_score << ")\n";

        SendVerdictToModuleHead(pkt.capture_sequence_number, isAllowed);
        cout << "-----------------------------------\n";
    }

    keep_running = false;
    close(data_connection);
    if (control_thread.joinable()) control_thread.join();
    return 0;
}