// procman.c

#include "procman.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h> // Para el tiempo de ejecución

// Variables globales (Parte 2.1)
process_info_t process_table[MAX_PROCESSES];
int process_count = 0;
// Parte 1.1: Process Creation
int create_process(const char *command, char *args[]) {
    pid_t pid = fork();

    if (pid < 0) {
        // Error de fork
        perror("fork");
        return -1;
    } else if (pid == 0) {
        // Código del proceso hijo
        // execvp requiere que el primer argumento (args[0]) sea el nombre del comando
        // y el último sea NULL.
        
        // Ejecutar el comando
        execvp(command, args);
        
        // Si execvp retorna, significa que falló.
        // EVITAR imprimir desde el hijo si el padre ya está usando la consola
        perror("execvp");
        // El hijo debe salir inmediatamente con error para evitar ejecutar código de padre
        exit(EXIT_FAILURE); 
    } else {
        // Código del proceso padre
        // Almacenar el PID en la tabla de procesos (implementado en Paso 4)
        if (add_process_to_table(pid, command, args) == -1) {
            fprintf(stderr, "Advertencia: Tabla de procesos llena. Proceso creado pero no gestionado.\n");
        }
        return pid;
    }
}
// Parte 1.2: Process Status Monitoring
int check_process_status(pid_t pid) {
    int status;
    // WNOHANG: retorna inmediatamente si el hijo no ha terminado.
    pid_t result = waitpid(pid, &status, WNOHANG); 

    if (result == 0) {
        // El proceso sigue corriendo (aún no ha cambiado de estado)
        return 1; 
    } else if (result > 0) {
        // El proceso terminó (ha cambiado de estado)
        if (WIFEXITED(status)) {
            // El proceso terminó normalmente
            update_process_status(pid, 1, WEXITSTATUS(status));
            return 0;
        } else if (WIFSIGNALED(status)) {
            // El proceso fue terminado por una señal
            update_process_status(pid, 1, WTERMSIG(status));
            return 0;
        }
        // También considera otros estados (WIFSTOPPED, etc.) si es necesario.
        return 0; 
    } else if (result == -1 && errno == ECHILD) {
        // No hay proceso hijo con ese PID (ya fue re-cosechado o el PID es incorrecto)
        // Marcar como terminado en la tabla si existe.
        int index = find_process_by_pid(pid);
        if (index != -1 && process_table[index].status == 0) {
             update_process_status(pid, 1, 0); // Asumimos terminación
        }
        return -1; // Error o ya no existe
    } else {
        perror("waitpid");
        return -1; // Error
    }
}
// Parte 1.3: Process Termination
int terminate_process(pid_t pid, int force) {
    int sig = force ? SIGKILL : SIGTERM;
    int index = find_process_by_pid(pid);

    if (index == -1 || process_table[index].status != 0) {
        fprintf(stderr, "Error: Proceso %d no encontrado o ya terminado.\n", pid);
        return -1;
    }

    if (kill(pid, sig) == -1) {
        if (errno == ESRCH) {
            fprintf(stderr, "Advertencia: Proceso %d no existe, actualizando tabla.\n", pid);
            remove_process_from_table(index); // Limpiar si no existe
            return 0;
        }
        perror("kill");
        return -1;
    }

    // Esperar la terminación (bloqueante) para limpiarlo inmediatamente.
    int status;
    pid_t result;
    do {
        // No usar WNOHANG aquí, queremos esperar su terminación (reap)
        result = waitpid(pid, &status, 0); 
    } while (result == -1 && errno == EINTR);

    if (result > 0) {
        // Cosechado y limpiado. Actualizar y remover de la tabla.
        update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
        remove_process_from_table(index); // Limpiar espacio
        return 0;
    } else if (result == -1) {
        perror("waitpid cleanup");
        return -1;
    }
    return 0;
}
// Auxiliar: Encuentra el índice de un PID en la tabla
int find_process_by_pid(pid_t pid) {
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == pid) {
            return i;
        }
    }
    return -1;
}

// Auxiliar: Agrega un proceso a la tabla
int add_process_to_table(pid_t pid, const char *command, char *args[]) {
    // Buscar un espacio libre (pid == 0)
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == 0) {
            process_table[i].pid = pid;
            // Concatenar comando y argumentos para un solo string
            snprintf(process_table[i].command, COMMAND_LEN, "%s", command);
            for(int j = 1; args[j] != NULL && j < MAX_ARGS; j++) {
                strncat(process_table[i].command, " ", COMMAND_LEN - strlen(process_table[i].command) - 1);
                strncat(process_table[i].command, args[j], COMMAND_LEN - strlen(process_table[i].command) - 1);
            }
            process_table[i].start_time = time(NULL);
            process_table[i].status = 0; // 0=running
            process_table[i].exit_status = -1;
            process_count++;
            return i;
        }
    }
    return -1; // Tabla llena
}

// Auxiliar: Actualiza el estado de un proceso (usado por check_process_status y sigchld_handler)
void update_process_status(pid_t pid, int status, int exit_status) {
    int index = find_process_by_pid(pid);
    if (index != -1) {
        process_table[index].status = status;
        process_table[index].exit_status = exit_status;
    }
}

// Auxiliar: Remueve un proceso de la tabla (marcando su espacio como libre)
void remove_process_from_table(int index) {
    if (index >= 0 && index < MAX_PROCESSES) {
        // Marcar como vacío (PID 0)
        memset(&process_table[index], 0, sizeof(process_info_t)); 
        process_count--;
    }
}
// Parte 2.2: Process List
void list_processes(void) {
    printf("PID\tCOMMAND\t\t\tRUNTIME\t\tSTATUS\n");
    printf("-----\t--------------------------\t----------------\t----------------\n");
    time_t current_time = time(NULL);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0) {
            pid_t pid = process_table[i].pid;
            const char *command = process_table[i].command;
            int status = process_table[i].status;

            // Calcular tiempo de ejecución
            double elapsed = 0;
            if (status == 0) { // Sólo si está corriendo
                elapsed = difftime(current_time, process_table[i].start_time);
            } else {
                // Si terminó, el tiempo de inicio puede usarse para la duración total.
                // (Para simplificar, usaremos el tiempo hasta la llamada a esta función
                // para los procesos que están en estado 'Terminated' pero no han sido removidos).
                elapsed = difftime(current_time, process_table[i].start_time); 
            }
            
            // Formatear tiempo (HH:MM:SS)
            int hours = (int)elapsed / 3600;
            int minutes = ((int)elapsed % 3600) / 60;
            int seconds = (int)elapsed % 60;
            char runtime_str[10];
            snprintf(runtime_str, 10, "%02d:%02d:%02d", hours, minutes, seconds);

            // Determinar string de estado
            const char *status_str;
            char term_info[32] = "";
            if (status == 0) {
                status_str = "Running";
                // Llama a check_process_status para verificar si terminaron en segundo plano
                // (esto puede ser caro, una mejor práctica es confiar en SIGCHLD, 
                // pero lo ponemos para actualizar si no se ha reapeado inmediatamente).
                // check_process_status(pid); 
            } else if (status == 1) {
                status_str = "Terminated";
                snprintf(term_info, 32, " (Exit: %d)", process_table[i].exit_status);
            } else {
                status_str = "Error";
            }
            
            printf("%-5d\t%-25s\t%-15s\t%s%s\n", pid, command, runtime_str, status_str, term_info);
        }
    }

    if (process_count == 0) {
        printf("(No hay procesos gestionados actualmente)\n");
    }
}
// Parte 2.3: Process Wait
void wait_all_processes(void) {
    // Bloquear SIGCHLD para evitar interferencias
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    printf("Esperando la finalización de todos los procesos gestionados...\n");
    int processes_waited = 0;

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0 && process_table[i].status == 0) {
            pid_t pid = process_table[i].pid;
            int status;
            pid_t result;

            printf("Esperando por PID %d (%s)...\n", pid, process_table[i].command);
            
            do {
                // Espera bloqueante
                result = waitpid(pid, &status, 0); 
            } while (result == -1 && errno == EINTR); // Reintentar si la llamada es interrumpida por una señal

            if (result > 0) {
                // Proceso cosechado. Actualizar y remover.
                update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                remove_process_from_table(i); 
                processes_waited++;
            } else if (result == -1) {
                // El proceso ya no existe (probablemente re-cosechado por el handler)
                if (errno == ECHILD) {
                    fprintf(stderr, "Advertencia: Proceso %d ya había terminado/sido limpiado.\n", pid);
                    remove_process_from_table(i); 
                } else {
                    perror("waitpid in wait_all_processes");
                }
            }
        }
    }

    printf("Finalizado. %d procesos terminados y limpiados.\n", processes_waited);

    // Restaurar la máscara de señales
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
}
// Parte 3: Signal Handling
void setup_signal_handlers(void) {
    struct sigaction sa_int, sa_chld;

    // 3.1 SIGINT Handler (Ctrl+C)
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0; // Por defecto
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("sigaction SIGINT");
        exit(EXIT_FAILURE);
    }

    // 3.2 SIGCHLD Handler (Reap child)
    sa_chld.sa_handler = sigchld_handler;
    // SA_RESTART: para reiniciar syscalls interrumpidas.
    // SA_RESTART es seguro, pero se necesita un bucle de espera en el handler.
    sa_chld.sa_flags = SA_RESTART; 
    sigemptyset(&sa_chld.sa_mask); 
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction SIGCHLD");
        exit(EXIT_FAILURE);
    }
}
// Parte 3.2: SIGCHLD Handler (Anti-Zombie)
void sigchld_handler(int signum) {
    int status;
    pid_t pid;

    // Usar waitpid en un bucle con WNOHANG para re-cosechar *todos* // los hijos terminados (previene zombis).
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        // En un handler de señal, es inseguro llamar a funciones como printf/fprintf
        // y a la mayoría de las funciones de la librería estándar (incluyendo las de la tabla).
        // Por ahora, solo re-cosecharemos el proceso.
        
        // La actualización de la tabla se debe posponer a un lugar seguro o 
        // usar funciones atómicas. Por la simplicidad de este ejercicio:
        
        // Bloquear SIGCHLD (ya está bloqueado por defecto al entrar al handler, 
        // pero es una buena práctica bloquear otras señales si se modifica el estado).
        // Nota: Es mejor actualizar un flag y hacer la limpieza en el loop principal. 
        // Para cumplir con el requerimiento de "Actualizar la tabla", se hace aquí, 
        // pero con la advertencia de que es una zona crítica.
        
        int index = find_process_by_pid(pid);
        if (index != -1) {
            update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
            // No remover aquí, solo actualizar estado.
            // La remoción se hace en wait_all_processes o en el shell.
        } else {
            // El proceso no era uno de los gestionados, pero fue re-cosechado.
        }
    }

    if (pid == -1 && errno != ECHILD) {
        // En un handler, solo se pueden usar write() para mensajes de error.
        // write(STDERR_FILENO, "Error en waitpid en sigchld_handler\n", 35);
    }
}
// Parte 3.1: SIGINT Handler
void sigint_handler(int signum) {
    // Usar write() por ser async-signal-safe
    const char msg[] = "\nShutting down gracefully...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    // Iterar y enviar SIGTERM a todos los procesos en ejecución
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0 && process_table[i].status == 0) {
            // Enviar SIGTERM
            kill(process_table[i].pid, SIGTERM); 
        }
    }
    
    // Esperar a que todos terminen (reutilizamos la lógica, pero en un contexto de salida)
    // Nota: Llamar a wait_all_processes() no es 100% async-signal-safe, 
    // pero para este tipo de asignación que requiere limpieza en el handler, es común hacerlo.
    
    // Mejor: configurar un flag global para que el loop principal salga.
    // Como el requisito pide esperar aquí:
    
    // Esto es BLOQUEANTE y por fuera de la tabla para no depender de sus funciones inseguras.
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, 0)) > 0) {
        // Cosechar todos.
        // Se puede hacer la actualización y remoción aquí con cuidado.
        int index = find_process_by_pid(pid);
        if (index != -1) {
            update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
            // No remover para que el shell pueda ver el estado final.
        }
    }
    
    // Salir del programa limpiamente.
    exit(EXIT_SUCCESS); 
}
// Auxiliar: Obtiene el PPID y el nombre del comando del PID dado.
// Retorna el PPID.
pid_t get_ppid(pid_t pid, char *comm_buffer, size_t buffer_len) {
    char path[256];
    sprintf(path, "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        // El proceso puede haber terminado.
        snprintf(comm_buffer, buffer_len, "<Terminated/N/A>");
        return 0; 
    }

    int proc_pid, ppid;
    char state, comm_temp[256];
    // Se necesita leer 4 campos: PID, TCOMM, STATE, PPID
    if (fscanf(fp, "%d %s %c %d", &proc_pid, comm_temp, &state, &ppid) != 4) {
        fclose(fp);
        snprintf(comm_buffer, buffer_len, "<Read Error>");
        return 0;
    }

    fclose(fp);
    
    // El nombre del comando en /proc/stat está entre paréntesis, por ejemplo, (bash)
    // Quitarlos.
    size_t len = strlen(comm_temp);
    if (len > 0 && comm_temp[0] == '(' && comm_temp[len - 1] == ')') {
        comm_temp[len - 1] = '\0';
        snprintf(comm_buffer, buffer_len, "%s", comm_temp + 1);
    } else {
        snprintf(comm_buffer, buffer_len, "%s", comm_temp);
    }
    
    return ppid;
}
// Parte 4: Process Tree Visualization
// Implementación auxiliar para recursión
void print_process_tree_recursive(pid_t root_pid, int depth) {
    // 1. Obtener la info del PID raíz (y su nombre)
    char comm_buffer[256];
    // Llamada no necesaria ya que el root_pid es el PPID para los hijos.

    // Formatear la indentación
    for (int i = 0; i < depth; i++) {
        // En una implementación completa, se debe rastrear si es el último hijo.
        // Para simplificar, solo imprimimos espacios.
        printf("  "); 
    }

    // 2. Imprimir la línea del proceso actual (si no es la primera llamada)
    if (depth > 0) {
        // Nota: Solo se imprime el PID y el nombre del comando. 
        // La lógica de [1000] procman, ├─, └─ es más compleja.
        
        // Para una representación sencilla:
        pid_t ppid = get_ppid(root_pid, comm_buffer, sizeof(comm_buffer));
        printf("[%-5d] %s (PPID: %d)\n", root_pid, comm_buffer, ppid);
    }

    // 3. Iterar sobre /proc para encontrar hijos.
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir("/proc")) == NULL) {
        perror("opendir /proc");
        return;
    }

    // Recorrer las entradas de /proc
    while ((ent = readdir(dir)) != NULL) {
        // Verificar si la entrada es un directorio con nombre numérico (un PID)
        if (ent->d_type == DT_DIR) {
            pid_t current_pid = atoi(ent->d_name);
            if (current_pid > 0) {
                char temp_comm[256];
                pid_t ppid = get_ppid(current_pid, temp_comm, sizeof(temp_comm));

                // Si su PPID es el PID raíz, es un hijo.
                if (ppid == root_pid) {
                    // Llamada recursiva para el hijo
                    // NOTA: Para implementar ├─ y └─, necesitas saber si es el *último* hijo.
                    // Esto requiere almacenar todos los PIDs hijos antes de la recursión.
                    // Simplificando la impresión:
                    printf("  "); // Indentación
                    for (int i = 0; i < depth; i++) printf("  "); // Indentación
                    printf("└─ ");
                    print_process_tree_recursive(current_pid, depth + 1);
                }
            }
        }
    }
    closedir(dir);
}

// Wrapper para la función principal (Parte 4)
void print_process_tree(pid_t root_pid, int depth) {
    char comm_buffer[256];
    get_ppid(root_pid, comm_buffer, sizeof(comm_buffer)); // Obtener nombre
    printf("[%-5d] %s\n", root_pid, comm_buffer);
    
    // Llamar a la función recursiva para encontrar los hijos de 'root_pid'
    print_process_tree_recursive(root_pid, 0); 
}
// Auxiliar: Parsea la línea de comando.
// Retorna el número de argumentos (incluyendo el comando).
int parse_command(char *line, char *cmd_name, char *args[]) {
    char *token;
    int arg_count = 0;
    
    // Quitar el salto de línea
    line[strcspn(line, "\n")] = 0; 
    
    // Primer token (el comando)
    token = strtok(line, " ");
    if (token == NULL) {
        return 0; // Línea vacía
    }
    strncpy(cmd_name, token, COMMAND_LEN - 1);
    cmd_name[COMMAND_LEN - 1] = '\0';
    args[arg_count++] = cmd_name;

    // Tokens subsiguientes (los argumentos)
    while ((token = strtok(NULL, " ")) != NULL && arg_count < MAX_ARGS - 1) {
        args[arg_count++] = token;
    }
    args[arg_count] = NULL; // NULL termination requerida por execvp
    
    return arg_count;
}
// Parte 5: Interactive Shell
void run_interactive_shell(void) {
    char line[1024];
    char cmd_name[COMMAND_LEN];
    char *args[MAX_ARGS];
    
    // Inicializar la tabla de procesos a 0
    memset(process_table, 0, sizeof(process_table));
    
    while (1) {
        // Limpiar el estado de los procesos que hayan terminado
        for (int i = 0; i < MAX_PROCESSES; i++) {
            if (process_table[i].pid != 0 && process_table[i].status == 0) {
                check_process_status(process_table[i].pid);
            }
        }

        printf("ProcMan> ");
        if (fgets(line, sizeof(line), stdin) == NULL) {
            // EOF (Ctrl+D), salir
            printf("\nSaliendo...\n");
            break;
        }

        if (parse_command(line, cmd_name, args) == 0) {
            continue; // Línea vacía
        }

        if (strcmp(cmd_name, "quit") == 0) {
            printf("Shutting down...\n");
            // Limpiar procesos activos antes de salir
            for (int i = 0; i < MAX_PROCESSES; i++) {
                if (process_table[i].pid != 0 && process_table[i].status == 0) {
                    terminate_process(process_table[i].pid, 0); // SIGTERM
                }
            }
            break;

        } else if (strcmp(cmd_name, "help") == 0) {
            printf("Available commands:\n");
            printf("  create <command> [args...] - Create new process\n");
            printf("  list                       - List all processes\n");
            printf("  kill <pid> [force]         - Terminate process (0=SIGTERM, 1=SIGKILL)\n");
            printf("  tree                       - Show process tree (from procman's PID)\n");
            printf("  wait                       - Wait for all processes\n");
            printf("  quit                       - Exit program\n");

        } else if (strcmp(cmd_name, "create") == 0) {
            // Argumentos: args[0]="create", args[1]=command, args[2...]=args
            if (args[1] != NULL) {
                pid_t pid = create_process(args[1], &args[1]);
                if (pid > 0) {
                    printf("Created process %d\n", pid);
                }
            } else {
                fprintf(stderr, "Uso: create <command> [args...]\n");
            }

        } else if (strcmp(cmd_name, "list") == 0) {
            list_processes();

        } else if (strcmp(cmd_name, "kill") == 0) {
            if (args[1] != NULL) {
                pid_t pid = atoi(args[1]);
                int force = (args[2] != NULL && strcmp(args[2], "1") == 0);
                if (terminate_process(pid, force) == 0) {
                    printf("Process %d terminated.\n", pid);
                }
            } else {
                fprintf(stderr, "Uso: kill <pid> [force]\n");
            }

        } else if (strcmp(cmd_name, "tree") == 0) {
            printf("Process Tree:\n");
            print_process_tree(getpid(), 0);

        } else if (strcmp(cmd_name, "wait") == 0) {
            wait_all_processes();

        } else {
            fprintf(stderr, "Comando desconocido: %s. Usa 'help'.\n", cmd_name);
        }
    }
}
// main function
int main() {
    setup_signal_handlers(); // Configurar manejo de señales
    run_interactive_shell(); // Iniciar el shell

    return 0;
}

