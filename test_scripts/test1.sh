#!/bin/bash
echo "--- TEST 1: Basic process creation and termination ---"
./procman << EOF
create sleep 3
list
wait
create sleep 100
list
quit
EOF
