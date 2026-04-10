// trigger.c
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main() {
    void *handle = dlopen("./libvuln.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror());
        return 1;
    }
    void (*vuln)(const char*) = dlsym(handle, "vulnerable_function");
    if (!vuln) {
        fprintf(stderr, "dlsym error: %s\n", dlerror());
        return 1;
    }

    // 从标准输入读取 payload（最大 512 字节）
    char payload[512];
    ssize_t n = read(STDIN_FILENO, payload, sizeof(payload) - 1);
    if (n <= 0) {
        fprintf(stderr, "Failed to read payload\n");
        return 1;
    }
    payload[n] = '\0';
    vuln(payload);
    dlclose(handle);
    return 0;
}