#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[]) {
    pid_t target;

    if (argc < 2) {
        printf("Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    target = atoi(argv[1]);
    printf("[*] Attempting ptrace(PTRACE_ATTACH, %d) ...\n", target);

    long ret = ptrace(PTRACE_ATTACH, target, NULL, NULL);
    if (ret == -1) {
        printf("[-] ptrace ATTACH failed: errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }

    printf("[+] ptrace ATTACH succeeded! ret=%ld\n", ret);

    int status;
    waitpid(target, &status, 0);
    printf("[*] waitpid status: 0x%x\n", status);

    ret = ptrace(PTRACE_DETACH, target, NULL, NULL);
    printf("[*] ptrace DETACH: ret=%ld errno=%d (%s)\n", ret, errno, strerror(errno));

    printf("[+] ptrace works on this system!\n");
    return 0;
}
