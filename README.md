📂 Process Manager (procman)
📋 Información de la Entrega
Campo	Detalle
Autor	Luis Felipe Ramírez Torres
Materia	Sistemas Operativos
Asignación	Gestión Básica de Procesos en C (System Calls & Process Management)

Exportar a Hojas de cálculo

🚀 Compilación y Ejecución
Requisitos
El programa está escrito en C (C99) y utiliza llamadas al sistema POSIX/Linux. Requiere la herramienta gcc y el acceso a las bibliotecas estándar.

🛠️ Compilación
Para construir el ejecutable procman, usa el Makefile proporcionado:

Bash

make
🏃 Uso
El programa se ejecuta como un shell interactivo:

Bash

./procman
Comandos Disponibles
Comando	Descripción	Ejemplo
help	Muestra la lista de comandos disponibles.	ProcMan> help
create <cmd> [args...]	Crea y ejecuta un nuevo proceso hijo.	ProcMan> create sleep 10
list	Lista los procesos gestionados (PID, comando, tiempo de ejecución, estado).	ProcMan> list
kill <pid> [force]	Termina un proceso. force=0 (SIGTERM, por defecto) o force=1 (SIGKILL).	ProcMan> kill 1234 1
tree	Muestra la jerarquía de procesos que dependen de procman.	ProcMan> tree
wait	Espera y limpia todos los procesos gestionados que sigan activos.	ProcMan> wait
quit	Cierra el shell, enviando SIGTERM a todos los hijos antes de salir.	ProcMan> quit

Exportar a Hojas de cálculo

🧠 Diseño e Implementación
El proyecto está diseñado en torno a la gestión de recursos del sistema mediante llamadas al sistema Unix/Linux.

procman.h
Define la estructura de datos clave process_info_t y todos los prototipos de las funciones principales y auxiliares, así como variables globales con el keyword extern.

procman.c
Contiene la lógica principal, organizada por las partes del requerimiento:

Parte 1: Gestión Básica de Procesos
create_process(): Implementa la secuencia fork() -> execvp(). El proceso padre bloquea SIGCHLD durante la bifurcación y el registro en la tabla para prevenir race conditions si el hijo termina inmediatamente.

terminate_process(): Utiliza kill() para enviar SIGTERM o SIGKILL y luego waitpid(pid, ..., 0) para cosechar al proceso inmediatamente, garantizando la limpieza del zombie.

Parte 2: Process Table (process_table)
Se utiliza un array estático process_table de estructuras process_info_t.

Las funciones auxiliares (add_process_to_table, update_process_status, remove_process_from_table) gestionan la inserción, actualización y eliminación de entradas, usando pid == 0 para marcar una entrada como libre.

list_processes() formatea y muestra la información, calculando el tiempo de ejecución con time() y difftime().

Parte 3: Signal Handling (Prevención de Zombies)
sigchld_handler(): Usa un bucle while (waitpid(-1, &status, WNOHANG) > 0) para cosechar todos los hijos que hayan terminado, previniendo la creación de procesos zombies.

Diseño de Seguridad: En lugar de modificar directamente la process_table (lo cual no es async-signal-safe), el handler solo activa el flag atómico global children_terminated.

reap_terminated_children(): Es la función segura que se llama desde el loop principal del shell. Esta función se encarga de recorrer la tabla y remover las entradas de los procesos que el handler ya ha cosechado, reseteando el flag al finalizar.

sigint_handler(): Muestra un mensaje seguro (write()), envía SIGTERM a todos los hijos activos y luego llama a un loop de waitpid(-1, ..., 0) para cosechar a todos antes de un exit(EXIT_SUCCESS) limpio.

Parte 4: Process Tree Visualization
La función print_process_tree() utiliza la recursión y lee directamente del filesystem /proc (/proc/[pid]/stat).

get_ppid_comm() extrae el PID del padre (PPID) y el nombre del comando (COMM) de un proceso.

La función recursiva implementa la lógica de recolección de hijos en cada nivel y luego los imprime usando los conectores jerárquicos (├─ y └─) para generar el formato de árbol solicitado.

Parte 5: Interactive Shell
run_interactive_shell() maneja el loop principal, el parsing de comandos (parse_command()) y la ejecución de las funciones del gestor de procesos.

🚧 Desafíos y Limitaciones Conocidas
Desafíos Superados
Anti-Zombie Robustez: Se implementó el patrón de manejo de señales con un flag atómico (children_terminated) para separar la cosecha inmediata de zombies (en el handler, que es inseguro para I/O) de la actualización de la tabla (en el loop principal, que es seguro).

Jerarquía del Árbol: Se implementó una lógica de recursión y una lectura del filesystem /proc para generar la jerarquía de procesos, que es más complejo que un simple listado.

Limitaciones
Seguridad en SIGINT: Aunque el diseño de sigint_handler() es común en asignaciones académicas, la iteración sobre process_table para enviar SIGTERM no es técnicamente async-signal-safe, ya que accede a estructuras de datos globales sin protección atómica en un contexto de señal.

Lógica del Árbol de Procesos: La implementación del tree asume que malloc y realloc funcionan correctamente. Un error en la lectura de /proc (ej. si un proceso termina entre la lectura de /proc y la llamada a stat) podría generar inconsistencias o errores.

🧪 Testing
Se proporcionan tres scripts de shell en el directorio test_scripts/ para validar las funcionalidades clave.

Para ejecutar el test suite completo:

Bash

make test
Casos de Prueba
Archivo	Objetivo	Funcionalidades Validadas
test1.sh	Flujo básico de creación, listado y espera.	create, list, wait, quit.
test2.sh	Prevención de zombies con procesos de corta duración.	SIGCHLD handler (prevención), create, list.
test3.sh	Comprobación de la estructura del árbol con múltiples hijos.	create, sleep, tree, wait.
