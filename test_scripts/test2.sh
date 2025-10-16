#!/bin/bash
echo "--- TEST 2: Signal handling (SIGCHLD) and Zombie prevention ---"
# El handler SIGCHLD debe limpiar el proceso sin el 'wait' explícito
./procman << EOF
create bash -c "sleep 1 && exit 42"
list
# Esperar un momento para que el proceso termine y SIGCHLD se active
sleep 2
list # Debe mostrar Terminated y luego ser removido por la limpieza de la tabla
quit
EOF

# Prueba de Zombie (ps aux | grep Z):
echo "Checking for zombie processes..."
# El PID del procman debe ser usado para verificar si hay hijos zombis.
ps aux | grep Z | grep procman
if [ $? -ne 1 ]; then
    echo "SUCCESS: No zombies found."
else
    echo "WARNING: Check for zombies manually."
fi

