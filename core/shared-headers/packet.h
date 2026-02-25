typedef struct
{
    unsigned char* data;
    unsigned int length;

    unsigned int src_ip;
    unsigned int dst_ip;

    unsigned short src_port;
    unsigned short dst_port;

    unsigned char protocol;

} packet_t;