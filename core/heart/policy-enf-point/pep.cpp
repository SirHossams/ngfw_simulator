#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <pcap.h>

using namespace std;

int pep_server_socket = -1;
int capture_client_socket = -1;
int pe_network_socket = -1;

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

int main() {
    // 1. Connect to PE first
    if (!ConnectToPE()) {
        cerr << "Failed to connect to PE. Is pe running?\n";
        return 1;
    }

    // 2. Setup Unix server to receive from capture
    if (!InitPktCapSocket()) {
        return 1;
    }

    while (true) {
        vector<uint8_t> packet_data = ReceiveFromPC();
        
        if (packet_data.empty()) {
            cout << "Capture module disconnected. Exiting PEP...\n";
            break;
        }

        cout << "PEP forwarding packet of size: " << packet_data.size() << " bytes\n";
        
        if (!SendToPE(packet_data)) {
            cout << "PE disconnected or error forwarding. Exiting PEP...\n";
            break;
        }
    }

    close(capture_client_socket);
    close(pep_server_socket);
    close(pe_network_socket);
    unlink("/tmp/pep.sock");
    
    return 0;
}