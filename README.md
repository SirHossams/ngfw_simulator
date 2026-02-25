# Rules

1-Every module should be wrapped with **try** and **catch**, in case of failure it restart
Example:
'''c++
try
{
    module->process_packet(packet);
}
catch(...)
{
    restart_module(module);
}
'''

2- How to compile .so files: (Not gonna be manually anyway so you can skip)
'''shell
g++ -shared -fPIC module1.cpp -o module1.so
'''

To add new terminal functions using the module_scripts, run:-
source module_scripts.bash

# Flow

### System Startup

controller starts
controller spwan all process (fork + exec)
controller creates sockets:
'''
  capture ↔ controller
  controller ↔ module1
  controller ↔ module2
  controller ↔ policy-engine
  controller ↔ pep
  controller ↔ logger
  controller ↔ interface handler
  controller ↔ interface speaker
'''
encryption system initializes (Each process performs key exchange with controller, so each of them have shared key with controller)

### Packet

NIC recieves packet
capture.cpp captures packet, parses it and convert it into packet.h
capture.cpp uses crypto.cpp to encrypt the packet
send it to controller
controller decrypt it
controller logs via logger.cpp and collector.cpp
controller sends packet to module 1, module 2 (if exist), ... and Policy Engine
Policy Engine import all 4 databases
PE evaultes the packet and calcalute it's score from: 4 databases + modules trust score
PE makes it decision and send it to controller
controller send packet + decision to PEP
PEP enforces decision (if dropped ===> packet destroyed: else ===> send to controller again for using more modules or forward to egress interface)
packet leaves firewall in any case
enforcement logs via logger.cpp and collector.cpp


Telemetry Plane:
All components → Collector → External security systems (SIEM or Zeek)

Logging Plane:
All components → Logger → Secure local logs (For application only and developers)