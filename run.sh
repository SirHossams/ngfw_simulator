#!/bin/bash

# Cleanup function
cleanup() {
    echo
    echo "[*] Shutting down all modules..."

    # Kill processes safely
    sudo kill $PID_CAP 2>/dev/null
    kill $PID_PEP 2>/dev/null
    kill $PID_PE 2>/dev/null

    wait $PID_CAP 2>/dev/null
    wait $PID_PEP 2>/dev/null
    wait $PID_PE 2>/dev/null

    echo "[*] Done."
    exit 0
}

# Trap Ctrl+C (SIGINT) and script termination (SIGTERM)
trap cleanup SIGINT SIGTERM

# 1. Compile the project
echo "[*] Compiling project..."
make
if [ $? -ne 0 ]; then
    echo "[!] Compilation failed! Exiting."
    exit 1
fi

echo "[*] Starting modules in sequence..."

# 2. Start Policy Engine (PE)
./build/pe &
PID_PE=$!

sleep 1

# 3. Start PEP
./build/pep > /dev/null 2>&1 &
PID_PEP=$!

sleep 1

# 4. Start Capture
sudo ./build/capture > /dev/null 2>&1 &
PID_CAP=$!

# 5. Run for 10 seconds OR until Ctrl+C
echo "[*] System running. Displaying PE output for 10 seconds..."
echo "--------------------------------------------------------"

# Wait 10 seconds, but allow interruption
sleep 10

echo "--------------------------------------------------------"

# 6. Trigger cleanup after timeout
echo "[*] 10 seconds passed."
cleanup