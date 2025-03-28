#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <termios.h>

#define MAX_SYSCALLS 512
#define MAX_NAME_LEN 64
#define MAX_DESC_LEN 256

// Estructura para almacenar información de las llamadas al sistema
struct Syscall {
    int rax;
    char name[MAX_NAME_LEN];
    char description[MAX_DESC_LEN];
};

struct Syscall syscall_table[MAX_SYSCALLS];         // Tabla de llamadas al sistema
int syscall_count[MAX_SYSCALLS] = {0};              // Contador de llamadas al sistema

/*
Función para esperar una pulsación de tecla
*/
void wait_for_keypress() {
    struct termios oldt, newt;                      // Estructuras para la configuración del terminal
    tcgetattr(STDIN_FILENO, &oldt);                 // Obtener la configuración actual
    newt = oldt;                                    // Copiar la configuración
    newt.c_lflag &= ~(ICANON | ECHO);               // Desactivar el modo canónico y el eco
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);        // Aplicar la nueva configuración
    getchar();                                      // Esperar a que se pulse una tecla
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);        // Restaurar la configuración original
}

/*
Función para cargar la tabla de llamadas al sistema desde un archivo CSV
*/
void load_syscalls_table(const char *filename) {
    FILE *file = fopen(filename, "r");              // Abrir el archivo CSV
    if (!file) {
        perror("Error al abrir el archivo CSV");
        exit(1);
    }
    char line[512];                                 // Buffer para leer líneas del archivo
    fgets(line, sizeof(line), file);                // Leer la primera línea (encabezados)
    int index = 0;                                  // Índice para la tabla de llamadas al sistema

    // Leer cada línea del archivo y llenar la tabla de llamadas al sistema
    while (fgets(line, sizeof(line), file) && index < MAX_SYSCALLS) {
        char rax_str[16], name[MAX_NAME_LEN], manual[16], entry_point[16], description[MAX_DESC_LEN];
        sscanf(line, "%15[^,],%63[^,],%15[^,],%15[^,],%255[^.]", rax_str, name, manual, entry_point, description);
        syscall_table[index].rax = atol(rax_str);   // Convertir el número de llamada al sistema a long
        strncpy(syscall_table[index].name, name, MAX_NAME_LEN);
        strncpy(syscall_table[index].description, description, MAX_DESC_LEN);
        index++;
    }
    fclose(file);                                   // Cerrar el archivo
}

/*
Función para encontrar una llamada al sistema en la tabla
*/
const struct Syscall* find_syscall_in_table(long rax) {
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_table[i].rax == rax) {
            return &syscall_table[i];
        }
    }
    return NULL;
}

/*
Función principal
*/
int main(int argc, char *argv[]) {
    if (argc < 1) {
        fprintf(stderr, "Uso: %s [-v|-V] <programa> [argumentos]\n", argv[0]);
        return 1;
    }
    
    load_syscalls_table("syscalls.csv");
    
    int verbose = 0, pause_mode = 0, prog_index = 1;    // Variables para el modo detallado y pausa

    // Comprobar si se ha especificado el modo detallado o pausa
    if (strcmp(argv[1], "-v") == 0) {
        verbose = 1;
        prog_index = 2;
    } else if (strcmp(argv[1], "-V") == 0) {
        verbose = 1;
        pause_mode = 1;
        prog_index = 2;
    } else {
        verbose = 0;
    }
    
    if (prog_index >= argc) {
        fprintf(stderr, "Error: No se ha especificado un programa a ejecutar.\n");
        return 1;
    }
    
    pid_t child = fork();                               // Crear un nuevo proceso

    // Si el proceso hijo es 0, se ejecuta el programa
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);          // Indicar al kernel que el hijo será rastreado
        execvp(argv[prog_index], &argv[prog_index]);    // Ejecutar el programa
        perror("execvp");                               // Si execvp falla, imprimir error
        return 1;
    } else if (child < 0) {
        perror("fork");                                 // Si fork falla, imprimir error
        return 1;
    }
    
    int status;                                         // Variable para almacenar el estado del proceso hijo
    struct user_regs_struct regs;                       // Estructura para almacenar los registros del proceso hijo
    waitpid(child, &status, 0);                         // Esperar a que el hijo esté listo para ser rastreado
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD); // Configura las opciones de ptrace
    
    // Bucle principal para rastrear las llamadas al sistema
    while (1) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1) break; // Esperar a que el hijo haga una llamada al sistema
        waitpid(child, &status, 0);                     // Esperar a que el hijo termine la llamada al sistema
        if (WIFEXITED(status)) break;                   // Si el hijo ha terminado, salir del bucle
        
        // Si el hijo ha hecho una llamada al sistema
        if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
            long syscall_num = regs.orig_rax;           // Obtener el número de la llamada al sistema
            syscall_count[syscall_num]++;               // Incrementar el contador de la llamada al sistema

            // Si el modo detallado está activado
            if (verbose) {
                const struct Syscall *sys = find_syscall_in_table(syscall_num);
                if (sys) {
                    printf("System call %ld: %s - %s\n", syscall_num, sys->name, sys->description);
                } else {
                    printf("System call desconocida: %ld\n", syscall_num);
                }
                if (pause_mode) wait_for_keypress();    // Esperar a que se pulse una tecla si el modo pausa está activado
            }
        }
    }
    
    // Muestra el resumen de llamadas al sistema al final
    printf("\n===Resumen de llamadas al sistema===\n");
    for (int i = 0; i < MAX_SYSCALLS; i++) {
        if (syscall_count[i] > 0) {
            const struct Syscall *sys = find_syscall_in_table(i);
            if (sys) {
                printf("   Syscall %s (%d): %d veces\n", sys->name, sys->rax, syscall_count[i]);
            } else {
                printf("   Syscall desconocida (%d): %d veces\n", i, syscall_count[i]);
            }
        }
    }
    return 0;
}