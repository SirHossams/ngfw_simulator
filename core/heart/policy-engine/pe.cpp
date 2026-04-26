#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>
#include "../../shared-headers/packet.h"

using namespace std;

int sock = -1, connection = -1;
#define PORT 9000

int InitPEPSocket();
NormalizedPacket DeserializePacket(const vector<uint8_t>& buffer);
NormalizedPacket ReceiveFromPEP();

int InitPEPSocket(){
    struct sockaddr_in address;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock==-1){
        cerr << "Socket failed!";
        return 1;
    }

    // Allow quick restart of the server by reusing the port
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

    // ARP
    if (np.ether_type == 0x0806) {
        read_data(&np.arp_opcode, sizeof(np.arp_opcode));
        np.arp_src_ip = read_string();
        np.arp_dst_ip = read_string();
    } 
    // IP Protocols (TCP, UDP, ICMP)
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
        empty_packet.capture_sequence_number = 0; // Use 0 to indicate failure/disconnect
        return empty_packet;
    }

    vector<uint8_t> buffer(size);
    uint32_t total_read = 0;

    while (total_read < size) {
        int bytes_read = recv(connection, buffer.data() + total_read, size - total_read, 0);
        if (bytes_read <= 0) break;
        total_read += bytes_read;
    }

    // Reconstruct the object safely
    return DeserializePacket(buffer);
}

int main() {
    if (InitPEPSocket() != 0) 
        return 1;

    while (true) {
        NormalizedPacket pkt = ReceiveFromPEP();
        
        // Error or disconnected
        if (pkt.capture_sequence_number == 0) {
            cout << "PEP disconnected or error receiving.\n";
            break;
        }

        cout << "PE Evaluated Frame #" << pkt.capture_sequence_number 
             << " | Protocol: " << (int)pkt.protocol 
             << " | Payload size: " << pkt.payload.size() << " bytes\n";
    }

    close(connection);
    close(sock);
    return 0;
}