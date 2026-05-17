#!/bin/bash

cleanup() {
    echo
    echo "[*] Shutting down NGFW modules (C++ and Python)..."
    sudo kill $PID_CAP 2>/dev/null
    kill $PID_PEP 2>/dev/null
    kill $PID_PEHEAD 2>/dev/null
    kill $PID_PE 2>/dev/null
    kill $PID_UVICORN 2>/dev/null
    kill $PID_REP 2>/dev/null
    
    wait $PID_CAP 2>/dev/null
    wait $PID_PEP 2>/dev/null
    wait $PID_PEHEAD 2>/dev/null
    wait $PID_PE 2>/dev/null
    wait $PID_UVICORN 2>/dev/null
    wait $PID_REP 2>/dev/null
    echo "[*] Done."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[*] Compiling project..."
make
if [ $? -ne 0 ]; then
    echo "[!] Compilation failed! Exiting."
    exit 1
fi

echo "[*] Starting modules in sequence..."

echo "[*] Starting Python Threat Intelligence Modules (Silent Mode)..."

source ./modules/threat-intelligence/env/bin/activate

(cd modules/threat-intelligence && uvicorn main:app --reload > /dev/null 2>&1) &
PID_UVICORN=$!
sleep 1

(cd modules/threat-intelligence && python3 reputation.py > /dev/null 2>&1) &
PID_REP=$!
sleep 1

./build/pe > /dev/null 2>&1 &
PID_PE=$!
sleep 1

echo "[*] Listening to the controller body on port 8080...";
ncat -l 8080;
sleep 1;

echo "[*] Receiving the file...";
ncat -l 8080 > arguments_list.txt;
echo "[*] Files Received!"
sleep 1;

./build/pehead 8080 2145 initial_settings_file.conf arguments_list.txt &
PID_PEHEAD=$!
sleep 1

./build/pep &
PID_PEP=$!
sleep 1

sudo ./build/capture > /dev/null 2>&1 &
PID_CAP=$!

cat logo.txt
cat text.txt

echo "--------------------------------------------------------"
echo "[*] System is LIVE. Waiting for Controller Instructions."
echo "[*] -> Type 'q' and press [ENTER] to Quit."
echo "[*] -> Press [ENTER] to Hot-Reload Databases."
echo "--------------------------------------------------------"

while true; do
    read -r user_input
    if [[ "$user_input" == "q" || "$user_input" == "Q" ]]; then
        break
    elif [[ -z "$user_input" ]]; then
        echo "[*] Sending Hot Reload signal to PEP and PE..."
        curl -s http://127.0.0.1:8000/convert > /dev/null
        sleep 0.2
        kill -SIGUSR1 $PID_PEP 2>/dev/null
        kill -SIGUSR1 $PID_PE 2>/dev/null
    fi
done

cleanup
