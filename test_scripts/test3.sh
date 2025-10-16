#!/bin/bash
echo "--- TEST 3: Process Tree with multiple levels ---"
# Crea un proceso que a su vez crea otros dos hijos.
./procman << EOF
create bash -c "sleep 5 & sleep 10 & wait"
sleep 1
tree
wait
quit
EOF


