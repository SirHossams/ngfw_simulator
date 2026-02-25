Each module:

while(true)
{
    receive packet from controller

    decision = process_packet(packet)

    send decision back
}