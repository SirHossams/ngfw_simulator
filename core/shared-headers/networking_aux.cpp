/**
 * @file networking_aux.cpp
 * @brief Implementation of the Networking AUX socket interface.
 *
 * Implements TCP, UDP, and UNIX domain socket functions as specified
 * in the Networking_AUX diagram.
 */

#include "networking_aux.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <cerrno>
#include <cstdio>
#include <string>



static const int SOCK_TIMEOUT_SEC = 30;

/**
 * @brief 
 * @param socknum
 */
static void set_timeout(int socknum)
{
    struct timeval tv;
    tv.tv_sec  = SOCK_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(socknum, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(socknum, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/**
 * @brief
 * @param socknum
 */
static void clear_timeout(int socknum)
{
    struct timeval tv = {0, 0};
    setsockopt(socknum, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}




void TCP_Open(int &socknum, const char *ip, int port, SOCKET_ROLE role)
{
    socknum = socket(AF_INET, SOCK_STREAM, 0);
    if (socknum < 0) {
        // perror("TCP_Open: socket");
        socknum = -1;
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (role == CLIENT) {
        if (connect(socknum, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            // perror("TCP_Open: connect");
            close(socknum);
            socknum = -1;
            return;
        }
        set_timeout(socknum);
        return;
    }

    int opt = 1;
    setsockopt(socknum, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(socknum, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        // perror("TCP_Open: bind");
        close(socknum);
        socknum = -1;
        return;
    }

    if (listen(socknum, 8) < 0) {
        // perror("TCP_Open: listen");
        close(socknum);
        socknum = -1;
        return;
    }

    int serversock = socknum;

    set_timeout(serversock);

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    socknum = accept(serversock, (struct sockaddr *)&client_addr, &addr_len);
    close(serversock);
    if (socknum < 0) {
        // perror("TCP_Open: accept");
        socknum = -1;
        return;
    }

    set_timeout(socknum);
}

void TCP_Accept(int serversock, int &clientsock)
{
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    clientsock = accept(serversock, (struct sockaddr *)&client_addr, &addr_len);
    if (clientsock < 0) {
        // perror("TCP_Accept: accept");
        clientsock = -1;
        return;
    }

    set_timeout(clientsock);
}

void TCP_Close(int socknum)
{
    if (socknum >= 0) {
        close(socknum);
    }
}

void TCP_Send(int socknum, const std::string &data, int &status)
{
    const char *ptr   = data.c_str();
    int         len   = static_cast<int>(data.size());
    int         total = 0;

    while (total < len) {
        int sent = send(socknum, ptr + total, len - total, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // perror("TCP_Send: timeout");
                status = -1;
                return;
            }
            // perror("TCP_Send: send");
            status = -1;
            return;
        }
        total += sent;
    }

    status = 0;  /* Success. */
}

void TCP_Receive(int socknum, std::string &out, int maxlen)
{
    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // if (errno == EAGAIN || errno == EWOULDBLOCK)
        //     perror("TCP_Receive: timed out waiting for message");
        // else
        //     perror("TCP_Receive: recv");
        out.clear();
    }
    else if (received == 0) {
        /* Peer closed the connection. */
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}

void TCP_ReceiveForever(int socknum, std::string &out, int maxlen)
{
    clear_timeout(socknum);

    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // perror("TCP_ReceiveForever: recv");
        out.clear();
    }
    else if (received == 0) {
        /* Peer closed the connection. */
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}


/* =========================================================================
 * UDP
 * ========================================================================= */

void UDP_Open(int &socknum, const char *ip, int port)
{
    socknum = socket(AF_INET, SOCK_DGRAM, 0);
    if (socknum < 0) {
        // perror("UDP_Open: socket");
        socknum = -1;
        return;
    }

    set_timeout(socknum);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (bind(socknum, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        // perror("UDP_Open: bind");
        close(socknum);
        socknum = -1;
        return;
    }
}

void UDP_Close(int socknum)
{
    if (socknum >= 0) {
        close(socknum);
    }
}

void UDP_Send(int socknum, const std::string &data, int &status)
{
    const char *ptr   = data.c_str();
    int         len   = static_cast<int>(data.size());
    int         total = 0;

    while (total < len) {
        int sent = send(socknum, ptr + total, len - total, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // perror("UDP_Send: timeout");
                status = -1;
                return;
            }
            // perror("UDP_Send: send");
            status = -1;
            return;
        }
        total += sent;
    }

    status = 0;  /* Success. */
}

void UDP_Receive(int socknum, std::string &out, int maxlen)
{
    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // if (errno == EAGAIN || errno == EWOULDBLOCK)
        //     // perror("UDP_Receive: timed out waiting for datagram");
        // else
        //     // perror("UDP_Receive: recv");
        // out.clear();
    }
    else if (received == 0) {
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}

void UDP_ReceiveForever(int socknum, std::string &out, int maxlen)
{
    clear_timeout(socknum);

    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // perror("UDP_ReceiveForever: recv");
        out.clear();
    }
    else if (received == 0) {
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}



void UNIX_Open(int &socknum, const char *path, SOCKET_ROLE role)
{
    socknum = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socknum < 0) {
        // perror("UNIX_Open: socket");
        socknum = -1;
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

    if (role == CLIENT) {
        if (connect(socknum, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            // perror("UNIX_Open: connect");
            close(socknum);
            socknum = -1;
            return;
        }
        set_timeout(socknum);
        return;
    }


    unlink(path);

    if (bind(socknum, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        // perror("UNIX_Open: bind");
        close(socknum);
        socknum = -1;
        return;
    }

    if (listen(socknum, 8) < 0) {
        // perror("UNIX_Open: listen");
        close(socknum);
        socknum = -1;
        return;
    }

    int serversock = socknum;

    set_timeout(serversock);

    struct sockaddr_un client_addr;
    socklen_t addr_len = sizeof(client_addr);
    socknum = accept(serversock, (struct sockaddr *)&client_addr, &addr_len);
    close(serversock);
    if (socknum < 0) {
        // perror("UNIX_Open: accept");
        socknum = -1;
        return;
    }

    set_timeout(socknum);
}

void UNIX_Accept(int serversock, int &clientsock)
{
    struct sockaddr_un client_addr;
    socklen_t addr_len = sizeof(client_addr);

    clientsock = accept(serversock, (struct sockaddr *)&client_addr, &addr_len);
    if (clientsock < 0) {
        // perror("UNIX_Accept: accept");
        clientsock = -1;
        return;
    }

    set_timeout(clientsock);
}

void UNIX_Close(int socknum)
{
    if (socknum >= 0) {
        close(socknum);
    }
}

void UNIX_Send(int socknum, const std::string &data, int &status)
{
    const char *ptr   = data.c_str();
    int         len   = static_cast<int>(data.size());
    int         total = 0;

    while (total < len) {
        int sent = send(socknum, ptr + total, len - total, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // perror("UNIX_Send: timeout");
                status = -1;
                return;
            }
            // perror("UNIX_Send: send");
            status = -1;
            return;
        }
        total += sent;
    }

    status = 0;  /* Success. */
}

void UNIX_Receive(int socknum, std::string &out, int maxlen)
{
    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // if (errno == EAGAIN || errno == EWOULDBLOCK)
        //     // perror("UNIX_Receive: timed out waiting for message");
        // else
        //     // perror("UNIX_Receive: recv");
        out.clear();
    }
    else if (received == 0) {
        /* Peer closed the connection. */
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}

void UNIX_ReceiveForever(int socknum, std::string &out, int maxlen)
{
    clear_timeout(socknum);

    char *buf = new char[maxlen];

    int received = recv(socknum, buf, maxlen, 0);

    if (received < 0) {
        // perror("UNIX_ReceiveForever: recv");
        out.clear();
    }
    else if (received == 0) {
        /* Peer closed the connection. */
        out.clear();
    }
    else {
        out.assign(buf, received);
    }

    delete[] buf;
}
