External Network
  ↓
Ingress Network Interface
  ↓
Interface Handler (Ingress or entering)
  ↓
Packet Capture
  ↓
Packet Parsing
  ↓
Firewall Pipeline
    ├── Policy Administration (PA)
    │     └── Rule Engine
    │           └── rules.json
    │
    ├── Policy Engine (PE)
    │     ├── Stateful context (from rules)
    │     ├── Module coordination (IDS/IPS, Application Awarness, Sandbox, ...)
    │     └── Intelligence consultation (Threat pool, AI-Agent)
    │
    └── Policy Enforcement Point (PEP)
          ├── Allow
          ├── Drop
          ├── Redirect
          ├── Sandbox
          └── Inspect
  ↓
Interface Handler (Egress or leaving)
  ↓
Egress Network Interface
  ↓
External Network


To add new terminal functions using the module_scripts, run:-
source module_scripts.bash

Testing pushing