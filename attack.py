import socket, threading
from time import sleep
from scapy.all import IP, TCP, sr1

IP_ADDRESS = "127.0.0.1"
PORT = 5000
MENU = \
r""" 
    
                  _   _  ____ _______        __         
                 | \ | |/ ___|  ___\ \      / /         
                 |  \| | |  _| |_   \ \ /\ / /          
                 | |\  | |_| |  _|   \ V  V /           
          ____  _|_| \_|\____|_|  _   \_/\_/            
         / ___|(_)_ __ ___  _   _| | __ _| |_ ___  _ __ 
         \___ \| | '_ ` _ \| | | | |/ _` | __/ _ \| '__|
          ___) | | | | | | | |_| | | (_| | || (_) | |   
         |____/|_|_| |_| |_|\__,_|_|\__,_|\__\___/|_|   
                                                

Pick your attack scenario:

1. XSS
2. SQL Injection
3. TCP NULL Scan (Active Recon.)
4. Unsecure Authentication

"""

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)


# ---- Attack Scenarios ----

def UnsecureAuth():
    pass

def SQLi():
    pass

def XSS():
    print("(Hacker) Sending XSS payload...\n")
    client.send("<script>".encode())

def TCPNUllScan():
    null_packet = IP(dst=IP_ADDRESS) / TCP(dport=PORT, flags="")
    
    print("(Hacker) Sending TCP Null Packets...\n")
    response = sr1(null_packet, timeout=2, verbose=0)


# ---- Server ----

def Server():
    global server
    server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
    server.bind((IP_ADDRESS,PORT))
    server.listen(1)
    print(f"[+] Server is created successfully (Listening on {IP_ADDRESS}:{PORT})")
    client, addr = server.accept()
    sleep(0.1)
    print("[+] (Server): Waiting for payload...")
    while True:
        payload = client.recv(1024)
        if payload:
            print(f"[x] Recieved Payload: {payload.decode()}\n")
    
# ---- Client ----

def Client():
    global client

    while True:
        try:
            client.connect((IP_ADDRESS,PORT))
            print("[+] Hacker connected to server successfully")
            break
        except:
            continue
    
# ---- Cleanup ----

def cleanup():
    global server, client
    if server:
        try:
            server.close()
        except:
            pass
    if client:
        try:
            client.close()
        except:
            pass


# ---- First function to start ----

def Start():
    print("[+] Creating TCP Server...")

    thread1 = threading.Thread(target=Server,daemon=True)
    thread1.start()
    
    sleep(0.3)

    print("[+] Creating TCP Client")

    Client()
    sleep(0.3)

    print(MENU)

    while True:
        option = int(input("Enter your option (e.g., 1):\n"))
        if option == 1:
            XSS()
        elif option == 2:
            SQLi()
        elif option == 3:
            TCPNUllScan()
        elif option == 4:
            UnsecureAuth()
        sleep(0.2)



if __name__ == "__main__":
    try:
        Start()
    except KeyboardInterrupt:
        cleanup()
        print("\n")