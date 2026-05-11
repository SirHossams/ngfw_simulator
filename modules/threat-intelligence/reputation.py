from dotenv import load_dotenv
from os import getenv
import requests
import ipaddress
from time import sleep


load_dotenv()

API_KEY = getenv("API")
API = "https://api.abuseipdb.com/api/v2/check"
DUMP_API = "http://127.0.0.1:8000"
JSON_DB = "test.json"

Headers = {
    "Key":API_KEY,
    "Accept": "application/json"
}

generated_ip = [
    "185.91.78.42",
    "142.250.183.14",
    "23.94.61.120",
    "51.81.203.77",
    "198.51.100.34",
    "104.244.76.29",
    "91.198.174.192",
    "176.58.121.45",
    "203.0.113.88",
    "45.33.32.156",
    "8.8.8.8",
    "1.1.1.1",
    "170.64.145.200",
    "64.233.160.0",
    "13.107.21.200"
]

def GetIP(n):
    # generated_ip = ipaddress.IPv4Address(n)

    # if not generated_ip.is_global:
        # return None
    
    check_ip = generated_ip[n]
    # del generated_ip

    while True:
        try:
            response = requests.get(API,
                headers=Headers,
                params={
                    "ipAddress":check_ip,
                    "maxAgeInDays":90
                },
                timeout=5
            )
            if response.status_code != 200:
                print("[!] Unexpected response\n\t Retrying...")
                continue
            
            data = response.json()
            checked_ip = check_ip
            del check_ip
            name = data["data"]["domain"]
            score = data["data"]["abuseConfidenceScore"]
            
            return [name, checked_ip, score]

        except requests.exceptions.Timeout:
            print("[!] Timeout exceeded\n\t Retrying...")
            continue

        except requests.exceptions.RequestException as e:
            print(f"[!] {e}")
            continue

def Fetch():
    while True:
        try:
            response = requests.post(DUMP_API + "/ip-reputations", json=Data, timeout = 5)

            if response.status_code != 200:
                print("[!] Unexpected response\n\t Retrying...")
                continue
            
            return response
        
        except requests.exceptions.timeout:
            print("[!] Timeout exceeded\n\t Retrying...")
            continue

        except requests.exceptions.ReadTimeout as e:
            print(f"[!] {e}")
            continue


for i in range(0,1000):
    result = GetIP(i)

    if result is None:
        continue

    name, checked_ip, score = result

    # if score >= 80:
    Data = {
        "name":name,
        "ip_address":checked_ip,
        "score": score
    }

    response = Fetch()

    # print(f"""
    #     {response.status_code} {response.reason}

    #     {response.text}
    # """)        

    sleep(90)