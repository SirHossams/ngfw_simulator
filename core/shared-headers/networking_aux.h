#ifndef NETWORKING_AUX_H
#define NETWORKING_AUX_H

#include <string>

enum SOCKET_ROLE {
    SERVER,
    CLIENT
};

void TCP_Open(int &socknum, const char *ip, int port, SOCKET_ROLE role);

void TCP_Accept(int serversock, int &clientsock);

void TCP_Close(int socknum);

void TCP_Send(int socknum, const std::string &data, int &status);

void TCP_Receive(int socknum, std::string &out, int maxlen);

void TCP_ReceiveForever(int socknum, std::string &out, int maxlen);

void UDP_Open(int &socknum, const char *ip, int port);

void UDP_Close(int socknum);

void UDP_Send(int socknum, const std::string &data, int &status);

void UDP_Receive(int socknum, std::string &out, int maxlen);

void UDP_ReceiveForever(int socknum, std::string &out, int maxlen);

void UNIX_Open(int &socknum, const char *path, SOCKET_ROLE role);

void UNIX_Accept(int serversock, int &clientsock);

void UNIX_Close(int socknum);

void UNIX_Send(int socknum, const std::string &data, int &status);

void UNIX_Receive(int socknum, std::string &out, int maxlen);

void UNIX_ReceiveForever(int socknum, std::string &out, int maxlen);

#endif