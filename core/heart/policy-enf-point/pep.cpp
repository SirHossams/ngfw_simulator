#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <thread>
#include <atomic>

using namespace std;

// Globals
int pep_server_socket = -1;
int capture_client_socket = -1;
int pe_network_socket = -1;
atomic<bool> keep_running{true};

struct VerdictReply {
    uint64_t seq_num;
    uint8_t verdict; // 1 for Allow, 0 for Drop
};

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

    cout << "PEP attempting to connect to PE on port 9000...\n";
    if (connect(pe_network_socket, (sockaddr*)&addr, sizeof(addr)) < 0) return false;

    cout << "PEP connected to Policy Engine!\n";
    return true;
}

vector<uint8_t> ReceiveFromPC(){
    uint32_t size = 0;
    int bytes_received = recv(capture_client_socket, &size, sizeof(size), 0);
    if (bytes_received <= 0) return {}; 

    vector<uint8_t> buffer(size);
    uint32_t total_read = 0;

    while (total_read < size) {
        int bytes_read = recv(capture_client_socket, buffer.data() + total_read, size - total_read, 0);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }
    return buffer;
}

bool SendToPE(const vector<uint8_t>& data) {
    if (pe_network_socket < 0) return false;

    uint32_t size = data.size();
    if (send(pe_network_socket, &size, sizeof(size), MSG_NOSIGNAL) <= 0) return false;
    if (send(pe_network_socket, data.data(), data.size(), MSG_NOSIGNAL) <= 0) return false;
    return true;
}

void VerdictReceiverLoop() {
    while (keep_running) {
        VerdictReply reply{0, 0};
        int bytes_read = recv(pe_network_socket, &reply, sizeof(reply), 0);
        
        // If recv returns 0 or -1, the socket was closed or an error occurred.
        if (bytes_read <= 0) {
            if (keep_running) {
                cout << "PE disconnected. Shutting down verdict thread...\n";
                keep_running = false;
            }
            break;
        }

        if (reply.verdict == 1) {
            cout << "[VERDICT] Frame #" << reply.seq_num << " -> ALLOW. Packet forwarded.\n";
        } else {
            cout << "[VERDICT] Frame #" << reply.seq_num << " -> DROP. Packet destroyed.\n";
        }
    }
}

int main() {
    if (!ConnectToPE()) {
        cerr << "Failed to connect to PE. Is pe running?\n";
        return 1;
    }

    if (!InitPktCapSocket()) {
        return 1;
    }

    // Start the asynchronous verdict listener thread
    thread verdict_thread(VerdictReceiverLoop);

    // Main Thread Loop: Continuously forward incoming packets
    while (keep_running) {
        vector<uint8_t> packet_data = ReceiveFromPC();
        
        if (packet_data.empty()) {
            cout << "Capture module disconnected. Exiting PEP...\n";
            keep_running = false;
            break;
        }

        if (!SendToPE(packet_data)) {
            cout << "PE disconnected or error forwarding. Exiting PEP...\n";
            keep_running = false;
            break;
        }
    }

    // Clean up and force the background thread to close gracefully
    keep_running = false;
    
    // Shutdown the network socket safely. 
    // This forces the blocking `recv` inside the verdict thread to wake up and return 0.
    shutdown(pe_network_socket, SHUT_RDWR);
    
    // Wait for the background thread to finish its last loop
    if (verdict_thread.joinable()) {
        verdict_thread.join();
    }

    close(capture_client_socket);
    close(pep_server_socket);
    close(pe_network_socket);
    unlink("/tmp/pep.sock");
    
    cout << "PEP Shutdown successfully.\n";
    return 0;
}