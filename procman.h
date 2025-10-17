// procman.h

#ifndef PROCMAN_H
#define PROCMAN_H

#include <sys/types.h>
#include <time.h>
#include <signal.h> // Necesario para sig_atomic_t
#include <dirent.h> // Necesario para la función de árbol

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
    int exit_status; // Almacenar el estado de salida
} process_info_t;

// Variables globales (declaradas en procman.c, definidas aquí como 'extern')
extern process_info_t process_table[MAX_PROCESSES];
extern int process_count;

// Flag atómico para indicar que SIGCHLD se disparó y necesita limpieza segura
extern volatile sig_atomic_t children_terminated;

// Estructura para almacenar información de /proc (auxiliar para el árbol)
typedef struct proc_entry {
    pid_t pid;
    pid_t ppid;
    char comm[COMMAND_LEN];
} proc_entry_t;

// Prototipos de funciones
// Parte 1: Basic Process Creation
int create_process(const char *command, char *args[]);
int check_process_status(pid_t pid);
int terminate_process(pid_t pid, int force);

// Funciones auxiliares para la tabla de procesos
int find_process_by_pid(pid_t pid);
int add_process_to_table(pid_t pid, const char *command, char *args[]);
void update_process_status(pid_t pid, int status, int exit_status);
void remove_process_from_table(int index);
void reap_terminated_children(void); // Nueva función segura de cosecha

// Parte 2: Process Manager
void list_processes(void);
void wait_all_processes(void);

// Parte 3: Signal Handling
void setup_signal_handlers(void);
void sigint_handler(int signum);
void sigchld_handler(int signum);

// Parte 4: Process Tree Visualization
pid_t get_ppid_comm(pid_t pid, char *comm_buffer, size_t buffer_len); // Renombrada para ser más precisa
void print_process_tree(pid_t root_pid); // Se simplificó la firma
void print_process_tree_recursive(pid_t parent_pid, int depth, const int *child_pids, int num_children);

// Parte 5: Interactive Shell
void run_interactive_shell(void);
int parse_command(char *line, char *cmd_name, char *args[]);

#endif // PROCMAN_H
