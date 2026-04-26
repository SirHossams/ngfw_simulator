#!/bin/bash

# 1. Compile the project
echo "[*] Compiling project..."
make
if [ $? -ne 0 ]; then
    echo "[!] Compilation failed! Exiting."
    exit 1
fi

echo "[*] Starting modules in sequence..."

# 2. Start Policy Engine (PE) first so it can bind port 9000.
# We run it in the background, but do NOT redirect its output so you can see it.
./build/pe &
PID_PE=$!

# Brief pause to let PE socket initialize
sleep 1 

# 3. Start PEP second. Hide its output.
./build/pep > /dev/null 2>&1 &
PID_PEP=$!

# Brief pause to let PEP connect to PE and bind /tmp/pep.sock
sleep 1 

# 4. Start Capture last. Hide its output.
sudo ./build/capture > /dev/null 2>&1 &
PID_CAP=$!

# 5. Let the script sit for 10 seconds while PE prints to the screen
echo "[*] System running. Displaying PE output for 10 seconds..."
echo "--------------------------------------------------------"
sleep 10
echo "--------------------------------------------------------"

# 6. Cleanup
echo "[*] 10 seconds passed. Shutting down all modules..."

# Sudo is required to kill capture because it was launched with sudo
sudo kill $PID_CAP 2>/dev/null
kill $PID_PEP 2>/dev/null
kill $PID_PE 2>/dev/null

echo "[*] Done."