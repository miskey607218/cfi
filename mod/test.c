// test.c - 用于 CFI 监控测试的共享库
// 涵盖四种验证类型：
// 1. 模块内部函数调用/跳转
// 2. 模块内部数据访问（全局变量、静态变量）
// 3. 模块外部函数调用/跳转（libc 函数等）
// 4. 模块外部数据访问（errno, stdout 等）

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

// 内部全局变量（数据访问）
int internal_global = 0x1234;
static int internal_static = 0x5678;

// 内部函数声明（用于直接/间接调用）
static void internal_func1(void);
static void internal_func2(int x);
static void internal_func3(const char *msg);

// 外部数据：使用 libc 的全局变量（errno, stdout）
extern int errno;
extern FILE *stdout;

// 外部函数指针（用于间接调用外部函数）
static void (*ext_func_ptr)(const char*) = (void(*)(const char*))puts;

// 内部函数指针（用于间接调用内部函数）
static void (*int_func_ptr)(void) = internal_func1;

// 内部函数定义
static void internal_func1(void) {
    printf("[internal_func1] called\n");
}

static void internal_func2(int x) {
    printf("[internal_func2] x = %d\n", x);
}

static void internal_func3(const char *msg) {
    printf("[internal_func3] %s\n", msg);
}

// 演示内部数据访问（读写全局/静态变量）
static void internal_data_access(void) {
    // 读内部全局变量
    int a = internal_global;
    // 写内部全局变量
    internal_global = a + 1;
    // 读静态变量
    int b = internal_static;
    // 写静态变量
    internal_static = b + 2;
    printf("[internal_data] global=%d, static=%d\n", internal_global, internal_static);
}

// 演示外部数据访问（读写 errno、stdout 等）
static void external_data_access(void) {
    // 读外部变量 errno
    int old_errno = errno;
    // 写外部变量 errno
    errno = 0;
    // 使用外部变量 stdout（FILE*）
    fprintf(stdout, "[external_data] old_errno=%d, new_errno=%d\n", old_errno, errno);
}

// 演示外部函数调用（直接和间接）
static void external_func_call(void) {
    // 直接调用外部函数
    printf("[external_direct] calling puts\n");
    puts("Hello from puts (external direct)");
    
    // 间接调用外部函数（通过函数指针）
    ext_func_ptr("Hello from puts via external pointer");
    
    // 调用 libc 分配内存
    void *p = malloc(64);
    if (p) {
        strcpy(p, "malloc test");
        printf("[external_direct] malloc returned %p\n", p);
        free(p);
    }
}

// 演示内部函数调用（直接、间接、返回）
static void internal_func_call(void) {
    // 直接调用内部函数
    internal_func1();
    internal_func2(42);
    internal_func3("direct call");
    
    // 间接调用内部函数（通过函数指针）
    int_func_ptr();
    
    // 使用函数指针数组间接调用
    void (*funcs[])(void) = {internal_func1, internal_func1};
    funcs[0]();
    
    // 返回指令（由编译器自动生成 ret）
}

// 演示各种跳转指令（jmp, jcc, call, ret）
// 注意：条件跳转通过 if 语句生成
static void jump_instructions(void) {
    int x = 0;
    // 条件跳转 (jcc)
    if (x == 0) {
        printf("[jcc] x is zero\n");
    } else {
        printf("[jcc] x is non-zero\n");
    }
    
    // 直接跳转（通过 goto）
    goto label;
    printf("This line should be skipped\n");
label:
    printf("[jmp] after goto\n");
    
    // 间接跳转（通过函数指针，但实际为 call，可使用 tail call 优化？）
    // 为了产生间接 jmp，可以使用函数指针并设置为 __attribute__((noreturn))
    // 简单起见，间接 jmp 可通过 setjmp/longjmp 产生，但较复杂。
    // 这里用一个间接调用（已由 internal_func_call 覆盖）
}

// 导出函数：供外部调用，依次执行所有测试
__attribute__((visibility("default")))
void test_all(void) {
    printf("\n=== Testing internal function calls ===\n");
    internal_func_call();
    
    printf("\n=== Testing internal data access ===\n");
    internal_data_access();
    
    printf("\n=== Testing external function calls ===\n");
    external_func_call();
    
    printf("\n=== Testing external data access ===\n");
    external_data_access();
    
    printf("\n=== Testing jump instructions ===\n");
    jump_instructions();
    
    printf("\nAll tests completed.\n");
}

// 额外导出一些单独函数，以便单独测试（可选）
__attribute__((visibility("default")))
void test_internal_call(void) {
    internal_func_call();
}

__attribute__((visibility("default")))
void test_internal_data(void) {
    internal_data_access();
}

__attribute__((visibility("default")))
void test_external_call(void) {
    external_func_call();
}

__attribute__((visibility("default")))
void test_external_data(void) {
    external_data_access();
}

__attribute__((visibility("default")))
void test_jumps(void) {
    jump_instructions();
}