# Next-Generation Firewall (NGFW) Simulator

A high-performance, modular Next-Generation Firewall simulator built in C++ and Python. This system utilizes a split-architecture design with a Fast Path (Policy Enforcement Point) for high-speed packet routing and a Slow Path (Policy Engine) for Deep Packet Inspection using a custom Zero-Trust Trust Algorithm.

---

## 🛠️ Prerequisites and Dependencies

To successfully compile and run the simulator, your environment must meet the following requirements:

**System Requirements:**

* **OS:** Linux (Ubuntu 20.04/22.04, Debian, Mint, or WSL2)
* **Privileges:** Root (`sudo`) access is required for binding packet capture to network interfaces.

**Programming Languages & Versions:**

* C++17 (Compiler: `g++` 13.3.0 or higher recommended)
* Python 3.12+

**Required Frameworks, Libraries, and Tools:**

* **C++ Libraries:**
* `libpcap-dev` (For real-time network interface sniffing)
* `nlohmann-json3-dev` (For JSON intelligence database parsing)
* `libssl-dev` / OpenSSL (For cryptographic Controller authentication)


* **Python Libraries:**
* `fastapi` and `uvicorn` (For the Threat Intelligence API)
* `requests`


* **Build Tools:**
* `make`



---

## 🚀 Installation Steps

**1. Clone the repository**

```bash
git clone https://github.com/SirHossams/ngfw-simulator.git
cd ngfw-simulator

```

**2. Install C++ Dependencies**

```bash
sudo apt-get update
sudo apt-get install build-essential libpcap-dev nlohmann-json3-dev libssl-dev python3 python3-pip python3-venv ncat

```

**3. Install Python Dependencies**
Navigate to the Threat Intelligence module to set up the virtual environment:

```bash
cd ./modules/threat-intelligence
python3 -m venv env
source env/bin/activate
pip install fastapi uvicorn requests
deactivate
cd ../..

```

---

## ⚙️ Environment Setup & Configuration

The firewall relies on local JSON databases to enforce routing and security policies. These act as the system's dynamic configuration files and are located in `src/core/databases/`.

* **`acl.json`:** Defines strict Layer 3/Layer 4 IP, MAC, and Port blocking/allowing rules.
* **`ip_reputation.json`:** Contains known malicious IP addresses and their associated risk scores.
* **`anomalies.json`:** Defines threshold scores for malformed packets (e.g., TCP Null Scans).
* **`fingerprints.json`:** Contains deep-packet malicious payload signatures.

**Authentication Setup:**
To use the management console, ensure your `passwords.txt` file (or `login.txt`) is securely located in your working directory with the appropriate plaintext passwords required by the Controller Head.

---

## ▶️ Run Instructions

Because of the modular, distributed nature of the firewall, running the project requires two separate terminal windows: one for the active firewall (Data Plane) and one for the management console (Control Plane).

### Terminal 1: Launch the Firewall

Make the run script executable and run it with `sudo`. This spins up the Python Threat Intel API, the C++ Policy Engine, the Module Head proxy, the PEP, and the Capture module.

```bash
chmod +x run.sh
sudo ./run.sh

```

*Wait until the terminal reads: `[*] System is LIVE. Waiting for Controller Instructions.*`

### Terminal 2: Launch the Management Console

Make the management script executable and launch it to push the startup JSON instructions to the firewall.

```bash
chmod +x manage.sh
sudo ./manage.sh

```

1. You will be prompted to enter a password (e.g., `iop2007`).
2. Upon successful authentication, the Controller Body will push the instructions to the Module Head.
3. The firewall in Terminal 1 will instantly begin capturing and evaluating live network traffic.

### Hot-Reloading

To update security rules without dropping active user connections:

1. Edit any configuration file (e.g., `src/core/databases/acl.json`).
2. Save the file.
3. Go to **Terminal 1** and press **`ENTER`**.
4. A `SIGUSR1` signal will safely lock memory, hot-reload the databases into the active C++ modules, and resume filtering.

### Graceful Shutdown

* In **Terminal 1**, type `q` or `Q` and press `ENTER` to safely unbind all sockets, kill background threads, and terminate the firewall.
* In **Terminal 2**, press `Ctrl+C` to close the management console.