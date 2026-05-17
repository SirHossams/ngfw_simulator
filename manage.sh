#!/bin/bash

cleanup() {
    echo
    echo "[*] Shutting down Controller Body..."
    kill $PID_BODY 2>/dev/null
    wait $PID_BODY 2>/dev/null
    echo "[*] Management Console Closed."
    exit 0
}

trap cleanup SIGINT SIGTERM

echo "[*] Starting the Controller Body...";
./build/body &
PID_BODY=$!

sleep 1

echo "--------------------------------------------------------"
echo "[*] Executing Controller Head Instructions"
echo "--------------------------------------------------------"

./build/head policy_engine.json database_of_modules.txt manager_database.json;

./build/jsonexpvalues instructions.json keyvalues.txt;
echo "[*] Sending the file to the other devices...";

sleep 3
ncat 127.0.0.1 8080 < keyvalues.txt;
echo "[*] Keyvalues sent!"

echo
echo "[*] Instructions sent. Press Ctrl+C to terminate the Controller Body."

while true; do
    sleep 1
done
