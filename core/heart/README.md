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

Thread 1 → Controller
Thread 2 → Packet Capture
Thread 3 → PEP
Thread 4 → Enforcement


