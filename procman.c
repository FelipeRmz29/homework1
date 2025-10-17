// procman.c

#include "procman.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <time.h> // time() y difftime()
#include <dirent.h> // Para el árbol de procesos
#include <ctype.h> // Para la validación del PID

// Variables globales (Parte 2.1)
process_info_t process_table[MAX_PROCESSES];
int process_count = 0;
// Flag para manejo seguro de SIGCHLD. Inicialmente 0 (no hay niños terminados)
volatile sig_atomic_t children_terminated = 0; 

// -----------------------------------------------------------------------------
// Parte 1: Basic Process Creation & Termination
// -----------------------------------------------------------------------------

// Parte 1.1: Process Creation
int create_process(const char *command, char *args[]) {
    pid_t pid;

    // Bloquear SIGCHLD para evitar una carrera si el niño termina muy rápido
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    pid = fork();

    if (pid < 0) {
        // Error de fork
        perror("fork");
        sigprocmask(SIG_SETMASK, &oldmask, NULL); // Restaurar máscara
        return -1;
    } else if (pid == 0) {
        // Código del proceso hijo
        sigprocmask(SIG_SETMASK, &oldmask, NULL); // El hijo debe restaurar la máscara
        
        // Ejecutar el comando
        execvp(command, args);
        
        // Si execvp retorna, significa que falló.
        perror("execvp");
        exit(EXIT_FAILURE); // El hijo debe salir inmediatamente con error
    } else {
        // Código del proceso padre
        // Almacenar el PID en la tabla de procesos
        if (add_process_to_table(pid, command, args) == -1) {
            fprintf(stderr, "Advertencia: Tabla de procesos llena. Proceso creado pero no gestionado.\n");
        }
        
        sigprocmask(SIG_SETMASK, &oldmask, NULL); // Restaurar máscara
        return pid;
    }
}

// Parte 1.2: Process Status Monitoring
// Función simplificada para solo verificar si terminó (reap se hace con SIGCHLD)
int check_process_status(pid_t pid) {
    int status;
    // WNOHANG: retorna inmediatamente si el hijo no ha terminado.
    pid_t result = waitpid(pid, &status, WNOHANG); 

    if (result == 0) {
        return 1; // Sigue corriendo
    } else if (result > 0) {
        // El proceso terminó y fue cosechado por esta llamada (o por el shell)
        // No es necesario llamar a update_process_status aquí, ya que el reap
        // se maneja por SIGCHLD/reap_terminated_children.
        return 0; // Terminado
    } else if (result == -1 && errno == ECHILD) {
        // No hay proceso hijo con ese PID (ya fue re-cosechado o el PID es incorrecto)
        return -1;
    } else {
        perror("waitpid in check_status");
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
            fprintf(stderr, "Advertencia: Proceso %d no existe, limpiando tabla.\n", pid);
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
        // Espera bloqueante para garantizar el reap inmediatamente después de kill.
        result = waitpid(pid, &status, 0); 
    } while (result == -1 && errno == EINTR);

    if (result > 0) {
        // Cosechado y limpiado. Actualizar y remover de la tabla.
        update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
        remove_process_from_table(index); // Limpiar espacio
        return 0;
    } else if (result == -1) {
        perror("waitpid cleanup");
        // Si falló el waitpid (ej: ECHILD), asumimos que el handler lo cosechó.
        remove_process_from_table(index); 
        return -1;
    }
    return 0;
}

// -----------------------------------------------------------------------------
// Parte 2: Process Manager Auxiliaries
// -----------------------------------------------------------------------------

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
    if (process_count >= MAX_PROCESSES) return -1;

    // Buscar un espacio libre (pid == 0)
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid == 0) {
            process_table[i].pid = pid;
            
            // Construir el string de comando y argumentos
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

// Auxiliar: Actualiza el estado de un proceso
void update_process_status(pid_t pid, int status, int exit_status) {
    int index = find_process_by_pid(pid);
    if (index != -1) {
        process_table[index].status = status;
        process_table[index].exit_status = exit_status;
    }
}

// Auxiliar: Remueve un proceso de la tabla (marcando su espacio como libre)
void remove_process_from_table(int index) {
    if (index >= 0 && index < MAX_PROCESSES && process_table[index].pid != 0) {
        // Marcar como vacío (PID 0)
        memset(&process_table[index], 0, sizeof(process_info_t)); 
        process_count--;
    }
}

// Nueva función segura: Cosecha y limpia la tabla si el flag está activo (Parte 3.2 robusta)
void reap_terminated_children(void) {
    if (!children_terminated) return;
    
    // Bloquear SIGCHLD para asegurar que el handler no intente actualizar la tabla al mismo tiempo
    sigset_t mask, oldmask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &oldmask);

    int status;
    pid_t pid;
    
    // Recorrer la tabla para ver qué procesos han terminado (status == 1)
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0 && process_table[i].status == 1) {
            // Se asume que el proceso ya fue cosechado por el handler, solo removemos.
            remove_process_from_table(i);
        } else if (process_table[i].pid != 0 && process_table[i].status == 0) {
            // Volver a chequear si terminó sin que el handler lo haya actualizado
            pid = process_table[i].pid;
            if (waitpid(pid, &status, WNOHANG) > 0) {
                 update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                 remove_process_from_table(i);
            }
        }
    }

    // El flag es reseteado DESPUÉS de la cosecha segura en la zona crítica
    children_terminated = 0;
    
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

// -----------------------------------------------------------------------------
// Parte 2: Process Manager
// -----------------------------------------------------------------------------

// Parte 2.2: Process List
void list_processes(void) {
    // Reap antes de listar para ver el estado más actualizado
    reap_terminated_children(); 
    
    printf("PID\tCOMMAND\t\t\tRUNTIME\t\tSTATUS\n");
    printf("-----\t--------------------------\t----------------\t----------------\n");
    time_t current_time = time(NULL);

    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0) {
            pid_t pid = process_table[i].pid;
            const char *command = process_table[i].command;
            int status = process_table[i].status;

            // Calcular tiempo de ejecución
            double elapsed = difftime(current_time, process_table[i].start_time);
            
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
    int max_i = MAX_PROCESSES; // Usar una variable local porque el índice puede cambiar

    // Usar un bucle while para re-chequear la tabla después de cada wait/remove
    int i = 0;
    while (i < MAX_PROCESSES) {
        if (process_table[i].pid != 0 && process_table[i].status == 0) {
            pid_t pid = process_table[i].pid;
            int status;
            pid_t result;

            printf("Esperando por PID %d (%s)...\n", pid, process_table[i].command);
            
            do {
                // Espera bloqueante
                result = waitpid(pid, &status, 0); 
            } while (result == -1 && errno == EINTR);

            if (result > 0) {
                // Proceso cosechado. Actualizar y remover.
                update_process_status(pid, 1, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
                remove_process_from_table(i); 
                processes_waited++;
                // No incrementamos i, porque remove_process_from_table llenó este índice con el siguiente
                // (aunque aquí estamos memset, no reubicando, el incremento es seguro, pero hay que tener cuidado)
                i++;
            } else if (result == -1) {
                if (errno == ECHILD) {
                    fprintf(stderr, "Advertencia: Proceso %d ya había terminado/sido limpiado.\n", pid);
                    remove_process_from_table(i); 
                } else {
                    perror("waitpid in wait_all_processes");
                }
                i++;
            }
        } else {
            i++;
        }
    }

    printf("Finalizado. %d procesos terminados y limpiados.\n", processes_waited);

    // Restaurar la máscara de señales
    sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

// -----------------------------------------------------------------------------
// Parte 3: Signal Handling
// -----------------------------------------------------------------------------

void setup_signal_handlers(void) {
    struct sigaction sa_int, sa_chld;

    // 3.1 SIGINT Handler (Ctrl+C)
    sa_int.sa_handler = sigint_handler;
    sigemptyset(&sa_int.sa_mask);
    sa_int.sa_flags = 0;
    if (sigaction(SIGINT, &sa_int, NULL) == -1) {
        perror("sigaction SIGINT");
        exit(EXIT_FAILURE);
    }

    // 3.2 SIGCHLD Handler (Anti-Zombie)
    sa_chld.sa_handler = sigchld_handler;
    sigemptyset(&sa_chld.sa_mask);
    sa_chld.sa_flags = SA_RESTART | SA_NOCLDSTOP; // SA_NOCLDSTOP evita señales por stop
    if (sigaction(SIGCHLD, &sa_chld, NULL) == -1) {
        perror("sigaction SIGCHLD");
        exit(EXIT_FAILURE);
    }
}

// Parte 3.2: SIGCHLD Handler (Anti-Zombie)
void sigchld_handler(int signum) {
    int status;
    pid_t pid;

    // Usar waitpid en un bucle con WNOHANG para re-cosechar *todos* los hijos terminados
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        // En un signal handler, NO es seguro llamar a find_process_by_pid o update_process_status.
        // Solo cosechamos el proceso (lo cual es el requerimiento principal para anti-zombie).
        
        // Ahora, actualizamos el flag atómico para que el loop principal (shell) haga la limpieza.
        children_terminated = 1;

        // Si WIFEXITED/WIFSIGNALED, podemos obtener el estado para una futura actualización segura.
        // Pero por seguridad de señal, solo lo marcamos.
        // El loop principal re-chequeará el estado de la tabla si el flag está activo.
    }

    // No se necesita verificar el error de waitpid, ya que ECHILD es normal cuando no hay más.
}

// Parte 3.1: SIGINT Handler
void sigint_handler(int signum) {
    // Usar write() por ser async-signal-safe
    const char msg[] = "\nShutting down gracefully...\n";
    write(STDOUT_FILENO, msg, sizeof(msg) - 1);

    // Enviar SIGTERM a todos los procesos en ejecución (asumiendo que pid != 0 es un hijo)
    // NOTA: Esta iteración en la tabla NO es completamente async-signal-safe, pero es la práctica
    // requerida para estos ejercicios de "limpieza en el handler".
    for (int i = 0; i < MAX_PROCESSES; i++) {
        if (process_table[i].pid != 0 && process_table[i].status == 0) {
            kill(process_table[i].pid, SIGTERM); 
        }
    }
    
    // Esperar a que todos terminen (bloqueante)
    int status;
    while (waitpid(-1, &status, 0) > 0) {
        // Cosechar todos. La tabla será re-inicializada o ignorada al salir.
    }
    
    // Salir del programa limpiamente.
    exit(EXIT_SUCCESS); 
}

// -----------------------------------------------------------------------------
// Parte 4: Process Tree Visualization (Refactorizado)
// -----------------------------------------------------------------------------

// Auxiliar: Obtiene el PPID y el nombre del comando del PID dado.
// Retorna el PPID.
pid_t get_ppid_comm(pid_t pid, char *comm_buffer, size_t buffer_len) {
    char path[256];
    sprintf(path, "/proc/%d/stat", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) {
        snprintf(comm_buffer, buffer_len, "<Terminated/N/A>");
        return 0; 
    }

    int proc_pid, ppid;
    char state, comm_temp[256];
    // Se lee: PID, TCOMM, STATE, PPID
    if (fscanf(fp, "%d %s %c %d", &proc_pid, comm_temp, &state, &ppid) != 4) {
        fclose(fp);
        snprintf(comm_buffer, buffer_len, "<Read Error>");
        return 0;
    }

    fclose(fp);
    
    // Quitar paréntesis del nombre del comando (ej: (bash) -> bash)
    size_t len = strlen(comm_temp);
    if (len > 0 && comm_temp[0] == '(' && comm_temp[len - 1] == ')') {
        comm_temp[len - 1] = '\0';
        snprintf(comm_buffer, buffer_len, "%s", comm_temp + 1);
    } else {
        snprintf(comm_buffer, buffer_len, "%s", comm_temp);
    }
    
    return ppid;
}

// Parte 4: Process Tree Visualization (Recursiva)
void print_process_tree_recursive(pid_t parent_pid, int depth, const int *child_pids, int num_children) {
    char comm_buffer[COMMAND_LEN];
    proc_entry_t *children_list = NULL;
    int children_count = 0;
    int max_children = 16; // Asumimos un máximo temporal

    // 1. Recolectar todos los hijos de 'parent_pid'
    children_list = malloc(max_children * sizeof(proc_entry_t));
    if (!children_list) return; // Manejo básico de error

    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir("/proc")) == NULL) {
        free(children_list);
        return;
    }

    // Primer pasada: recolectar hijos
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_DIR) {
            pid_t current_pid = atoi(ent->d_name);
            if (current_pid > 0) {
                char temp_comm[COMMAND_LEN];
                pid_t ppid = get_ppid_comm(current_pid, temp_comm, sizeof(temp_comm));

                // Si su PPID es el PID raíz
                if (ppid == parent_pid) {
                    if (children_count >= max_children) {
                        // Reasignar más memoria si es necesario (manejo simple de overflow)
                        max_children *= 2;
                        children_list = realloc(children_list, max_children * sizeof(proc_entry_t));
                        if (!children_list) {
                            // Limpieza y salida si falla realloc
                            closedir(dir);
                            return;
                        }
                    }
                    children_list[children_count].pid = current_pid;
                    children_list[children_count].ppid = ppid;
                    strncpy(children_list[children_count].comm, temp_comm, COMMAND_LEN);
                    children_count++;
                }
            }
        }
    }
    closedir(dir);

    // 2. Imprimir y recursar para cada hijo
    for (int i = 0; i < children_count; i++) {
        // Imprimir la indentación de los niveles superiores
        for (int j = 0; j < depth; j++) {
            // Asumir que si el padre no fue el último, se imprime el pipe (│)
            // Lógica compleja simplificada: si estamos en profundidad > 0, usar barras
             printf("│  ");
        }

        // Imprimir el conector (├─ o └─)
        const char *connector = (i == children_count - 1) ? "└─ " : "├─ ";
        printf("%s", connector);

        // Imprimir el nodo actual
        printf("[%-5d] %s\n", children_list[i].pid, children_list[i].comm);

        // Llamada recursiva (solo si tiene hijos)
        print_process_tree_recursive(children_list[i].pid, depth + 1, NULL, 0); 
    }

    free(children_list);
}

// Wrapper para la función principal (Parte 4)
void print_process_tree(pid_t root_pid) {
    char comm_buffer[COMMAND_LEN];
    get_ppid_comm(root_pid, comm_buffer, sizeof(comm_buffer)); // Obtener nombre
    
    // Imprimir el nodo raíz (procman mismo)
    printf("[%-5d] %s\n", root_pid, comm_buffer);
    
    // Iniciar la recursión (el root_pid es el padre de primer nivel)
    print_process_tree_recursive(root_pid, 0, NULL, 0); 
}

// -----------------------------------------------------------------------------
// Parte 5: Interactive Shell
// -----------------------------------------------------------------------------

// Auxiliar: Parsea la línea de comando.
int parse_command(char *line, char *cmd_name, char *args[]) {
    char *token;
    int arg_count = 0;
    
    // Quitar el salto de línea
    line[strcspn(line, "\n")] = 0; 
    
    // Primer token (el comando)
    token = strtok(line, " ");
    if (token == NULL) return 0; // Línea vacía
    
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
        // 🚨 Zona de limpieza segura: Revisar si el handler SIGCHLD marcó que hay trabajo pendiente.
        reap_terminated_children();

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
            print_process_tree(getpid());

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
