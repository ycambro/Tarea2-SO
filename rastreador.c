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
#include <map>
#include <iostream>

using namespace std;

void wait_for_keypress() {
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Uso: %s [-v|-V] <programa> [argumentos]\n", argv[0]);
        return 1;
    }

    bool verbose = false, pause_mode = false;
    int prog_index = 1;
    if (strcmp(argv[1], "-v") == 0) {
        verbose = true;
        prog_index = 2;
    } else if (strcmp(argv[1], "-V") == 0) {
        verbose = true;
        pause_mode = true;
        prog_index = 2;
    }

    if (prog_index >= argc) {
        fprintf(stderr, "Error: No se ha especificado un programa a ejecutar.\n");
        return 1;
    }

    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[prog_index], &argv[prog_index]);
        perror("execvp");
        return 1;
    } else if (child < 0) {
        perror("fork");
        return 1;
    }

    int status;
    map<long, int> syscall_count;
    struct user_regs_struct regs;

    waitpid(child, &status, 0);
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    while (1) {
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) == -1) break;
        waitpid(child, &status, 0);
        if (WIFEXITED(status)) break;

        if (ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
            long syscall_num = regs.orig_rax;
            syscall_count[syscall_num]++;
            if (verbose) {
                printf("System call: %ld\n", syscall_num);
                if (pause_mode) wait_for_keypress();
            }
        }
    }

    printf("\nResumen de llamadas al sistema:\n");
    for (const auto &entry : syscall_count) {
        printf("Syscall %ld: %d veces\n", entry.first, entry.second);
    }

    return 0;
}
