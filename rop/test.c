// test.c
#include <dlfcn.h>
#include <stdio.h>

int main() {
    void *handle = dlopen("./libvuln.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Error: %s\n", dlerror());
        return 1;
    }
    void (*vuln)(const char*) = dlsym(handle, "vulnerable_function");
    if (!vuln) {
        fprintf(stderr, "Symbol not found\n");
        return 1;
    }
    // 构造超长输入触发栈溢出
    char payload[200];
    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload)-1] = '\0';
    vuln(payload);
    dlclose(handle);
    return 0;
}