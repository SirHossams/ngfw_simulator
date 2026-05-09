#!/bin/bash

# Cleanup function
cleanup() {
    echo
    echo "[*] Shutting down all modules..."

    sudo kill $PID_CAP 2>/dev/null
    kill $PID_PEP 2>/dev/null
    kill $PID_PE 2>/dev/null

    wait $PID_CAP 2>/dev/null
    wait $PID_PEP 2>/dev/null
    wait $PID_PE 2>/dev/null

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

./build/pe &
PID_PE=$!
sleep 1

./build/pep &
PID_PEP=$!
sleep 1

sudo ./build/capture > /dev/null 2>&1 &
PID_CAP=$!

echo "--------------------------------------------------------"
echo "[*] System is LIVE."
echo "[*] -> Press [ENTER] at any time to trigger a Hot Reload."
echo "[*] -> Type 'q' and press [ENTER] to Quit."
echo "--------------------------------------------------------"

while true; do
    read -r user_input
    
    if [[ "$user_input" == "q" || "$user_input" == "Q" ]]; then
        break
    fi

    echo "[*] Initiating Hot Reload..."
    pkill -SIGUSR1 -f "./build/pe$"
    pkill -SIGUSR1 -f "./build/pep$"
done

cleanup