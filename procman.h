// procman.h

#ifndef PROCMAN_H
#define PROCMAN_H

#include <sys/types.h>
#include <time.h>

// Definiciones
#define MAX_PROCESSES 10
#define COMMAND_LEN 256
#define MAX_ARGS 32

// Estructura para la tabla de procesos (Parte 2.1)
typedef struct {
    pid_t pid;
    char command[COMMAND_LEN];
    time_t start_time;
    int status;  // 0=running, 1=terminated, -1=error
    int exit_status; // Almacenar el estado de salida para procesos terminados
} process_info_t;

// Variables globales (declaradas en procman.c, definidas aquí como 'extern')
extern process_info_t process_table[MAX_PROCESSES];
extern int process_count;

// Prototipos de funciones (Partes 1, 2, 3 y 4)
// Parte 1: Basic Process Creation
int create_process(const char *command, char *args[]);
int check_process_status(pid_t pid);
int terminate_process(pid_t pid, int force);

// Funciones auxiliares para la tabla de procesos
int find_process_by_pid(pid_t pid);
int add_process_to_table(pid_t pid, const char *command, char *args[]);
void update_process_status(pid_t pid, int status, int exit_status);
void remove_process_from_table(int index);

// Parte 2: Process Manager
void list_processes(void);
void wait_all_processes(void);

// Parte 3: Signal Handling
void setup_signal_handlers(void);
void sigint_handler(int signum);
void void sigchld_handler(int signum);

// Parte 4: Process Tree Visualization
void print_process_tree(pid_t root_pid, int depth);

// Parte 5: Interactive Shell
void run_interactive_shell(void);
int parse_command(char *line, char *cmd_name, char *args[]);

#endif // PROCMAN_H

