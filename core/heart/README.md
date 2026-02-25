# Controller

### Managing Part

Responsibilities:

• load .so modules using dlopen and provide modules access to their functions at runtime using dynamic linking
• resolve symbols using dlsym
• monitor modules (detect: crashes, freezes, timeouts)
• restart failed modules
• isolate faulty modules
• unload .so using dlclose

### Running Part

Runs modules in parallel.

Thread 1 → Packet capture
Thread 2 → Parser
Thread 3 → Policy engine
Thread 4 → Module execution
Thread 5 → Enforcement

Packet-Flow:
'''
spawn module1

spawn module2

while(true)
{
    packet = receive from pipeline

    send to module1

    receive decision

    forward to policy engine
}
'''

# Encryption flow

Encryption-flow:
Controller
   ↓ encrypt
UNIX socket
   ↓ decrypt
module process
   ↓ encrypt
UNIX socket
   ↓ decrypt
controller


