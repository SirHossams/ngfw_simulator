#include <iostream>
#include <sys/socket.h>
#include <sys/un.h>
#include <vector>
#include <unistd.h>
#include <cstring>
#include <pcap.h>

using namespace std;

int pep_server_socket = -1;
int capture_client_socket = -1;

bool InitPCSocket(){
    pep_server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (pep_server_socket < 0){
        cerr << "Socket Error: Couldn't create PEP socket\n";
        return false;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/tmp/pep.sock", sizeof(addr.sun_path) - 1);

    unlink("/tmp/pep.sock");

    if (bind(pep_server_socket, (sockaddr*)&addr, sizeof(addr)) < 0) {
        cerr << "Bind Error: Couldn't bind to /tmp/pep.sock\n";
        return false;
    }

    if (listen(pep_server_socket, 5) < 0) {
        cerr << "Listen Error\n";
        return false;
    }

    cout << "PEP waiting for capture module to connect...\n";
    capture_client_socket = accept(pep_server_socket, nullptr, nullptr);
    
    if (capture_client_socket < 0) {
        cerr << "Accept Error\n";
        return false;
    }

    cout << "Capture module connected to PEP!\n";
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

int main() {
    if (!InitPCSocket()) {
        return 1;
    }

    while (true) {
        vector<uint8_t> packet_data = ReceiveFromPC();
        
        if (packet_data.empty()) {
            cout << "Capture module disconnected or error reading. Exiting PEP...\n";
            break;
        }

        cout << "PEP received packet of size: " << packet_data.size() << " bytes\n";
        
        // Forward packet to PE via network socket here
        // Wait for PE's Allow/Drop decision
    }

    close(capture_client_socket);
    close(pep_server_socket);
    unlink("/tmp/pep.sock");
    
    return 0;
}