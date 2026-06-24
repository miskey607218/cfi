/* test.c — 丰富的间接跳转测试模块
 * 编译为 .so 后，包含多种 x86-64 间接控制流转移模式，
 * 用于验证三层 DFI 数据流追踪 + CFI 校验。
 *
 * 编译: gcc -shared -fPIC -O0 -o test.so test.c
 * 反汇编: objdump -d test.so > test.txt
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  基础目标函数 — 作为间接跳转/调用的合法目标
 * ================================================================ */

void test_target_a(void) { printf("  -> [A] reached\n"); }
void test_target_b(void) { printf("  -> [B] reached\n"); }
void test_target_c(void) { printf("  -> [C] reached\n"); }
void test_target_d(void) { printf("  -> [D] reached\n"); }

int  test_target_ret_int(int x)  { return x * 2; }
void test_target_arg(int a, int b, int c) {
    printf("  -> arg sum = %d\n", a + b + c);
}

/* ================================================================
 *  01 — 全局函数指针间接调用 (FF /2 through GOT)
 *      call *indirect_call_ptr(%rip)  → GOT → 函数地址
 * ================================================================ */

void (*g_callback)(void) = test_target_a;

void test01_global_fptr_call(void) {
    printf("[01] global function pointer call\n");
    g_callback();          // call *g_callback(%rip)  — GOT 间接
}

/* ================================================================
 *  02 — 局部函数指针间接调用 (寄存器间接)
 *      mov $target, %rax  →  call *%rax  (FF D0)
 *      数据流: L3=立即数赋值 → L2=无 → L1=call *%rax
 * ================================================================ */

void test02_local_fptr_call(void) {
    printf("[02] local function pointer call\n");
    void (*fp)(void) = test_target_b;
    fp();                 // call *%rax (局部变量加载到 rax)
}

/* ================================================================
 *  03 — 从数组取出函数指针然后调用 (内存 → 寄存器 → 间接调用)
 *      mov array(%rip), %rax  →  call *%rax
 *      数据流: L3=RIP_REL读数组 → L2=无 → L1=call *%rax
 * ================================================================ */

static void (*g_fptr_table[4])(void) = {
    test_target_a, test_target_b, test_target_c, test_target_d
};

void test03_table_fptr_call(int idx) {
    printf("[03] function pointer table call [%d]\n", idx);
    if (idx >= 0 && idx < 4)
        g_fptr_table[idx]();   // mov g_fptr_table(,%rax,8), %rax → call *%rax
}

/* ================================================================
 *  04 — 栈上函数指针 (RBP 相对寻址) 间接调用
 *      mov -N(%rbp), %rax  →  call *%rax
 *      数据流: L3=RBP_REL读栈 → L2=无 → L1=call *%rax
 * ================================================================ */

void test04_stack_fptr_call(void) {
    printf("[04] stack-based function pointer call\n");
    void (*fp)(void) = test_target_c;
    void (*volatile fp2)(void) = fp;  // 强制放入栈
    fp2();                 // mov -0xN(%rbp), %rax → call *%rax
}

/* ================================================================
 *  05 — 结构体中的函数指针 (vtable 模拟)
 *      mov OFFSET(%rax), %rax  →  call *%rax
 *      数据流: 解引用结构体成员 → L1
 * ================================================================ */

struct vtable {
    void (*do_a)(void);
    void (*do_b)(void);
    int data;
};

void test05_vtable_call(void) {
    printf("[05] vtable-style indirect call\n");
    struct vtable vt;
    vt.do_a = test_target_a;
    vt.do_b = test_target_b;
    vt.data = 42;
    vt.do_a();             // mov (%rbp+N), %rax → call *%rax
    vt.do_b();
}

/* ================================================================
 *  06 — 回调函数指针作为参数传递 (寄存器参数 → 间接调用)
 *      rdi 传入函数指针 → mov %rdi, %rax → call *%rax
 * ================================================================ */

static void call_via_fp(void (*fp)(void)) {
    fp();                  // 参数在 rdi → call *%rdi (FF D7)
}

void test06_callback_arg(void) {
    printf("[06] callback via function argument\n");
    call_via_fp(test_target_d);
}

/* ================================================================
 *  07 — 间接跳转 (jmp *%reg, FF E0)
 *      jmp 而非 call — 不返回，直接转移
 * ================================================================ */

void test07_indirect_jump(int selector) {
    printf("[07] indirect jump (tail)\n");
    void (*targets[2])(void) = {test_target_a, test_target_b};
    void (*fp)(void) = targets[selector & 1];
    fp();                  // call *%rax — 但从数据流角度等价于间接跳转
    /* 额外的 jmp *%rax 场景: */
    void (*volatile jp)(void) = test_target_c;
    jp();                  // 编译器可能生成为 jmp *%rax (尾调用优化)
}

/* ================================================================
 *  08 — 间接调用返回 int (验证 rax 返回值被覆盖)
 *      call *%rax 后 rax 为返回值，然后 rax 又被修改
 * ================================================================ */

void test08_indirect_call_with_retval(int n) {
    printf("[08] indirect call with return value\n");
    int (*fp)(int) = test_target_ret_int;
    int result = fp(n);    // call *%rax → rax = 返回值
    printf("  -> result = %d\n", result);
}

/* ================================================================
 *  09 — 多参数间接调用 (rdi/rsi/rdx 传参)
 * ================================================================ */

void test09_indirect_call_multiarg(void) {
    printf("[09] indirect call with multiple args\n");
    void (*fp)(int, int, int) = test_target_arg;
    fp(10, 20, 30);        // call *%rax  with rdi=10, rsi=20, rdx=30
}

/* ================================================================
 *  10 — 通过 volatile 阻止编译器优化 (强制内存读写)
 *      volatile 确保函数指针一定走栈/内存，产生完整的
 *      L3(load) → L2(不适用) → L1(call *%reg) 数据流
 * ================================================================ */

void test10_volatile_fptr(void) {
    printf("[10] volatile function pointer (forced memory path)\n");
    volatile void (*fp)(void) = test_target_a;
    fp();                  // 必从栈加载 → call *%rax
}

/* ================================================================
 *  11 — 条件选择间接调用 (产生 jcc + 间接调用混合)
 * ================================================================ */

void test11_conditional_indirect(int cond) {
    printf("[11] conditional indirect call (cond=%d)\n", cond);
    void (*fp)(void);
    if (cond)
        fp = test_target_a;
    else
        fp = test_target_b;
    fp();
}

/* ================================================================
 *  12 — switch-case 风格 (模拟跳转表)
 *      不同 case 对应不同函数指针
 * ================================================================ */

void test12_switch_style(int code) {
    printf("[12] switch-style dispatch (code=%d)\n", code);
    void (*fp)(void) = NULL;
    switch (code) {
        case 0: fp = test_target_a; break;
        case 1: fp = test_target_b; break;
        case 2: fp = test_target_c; break;
        default:fp = test_target_d; break;
    }
    if (fp) fp();
}

/* ================================================================
 *  13 — 运行时计算目标地址 (lea + 间接调用)
 *      lea target(%rip), %rax → call *%rax
 *      验证 LEA 指令 (DIRECT type) 的数据流追踪
 * ================================================================ */

void test13_runtime_computed_target(void) {
    printf("[13] runtime computed target address\n");
    void (*targets[3])(void) = {test_target_a, test_target_b, test_target_c};
    /* 动态索引 */
    int idx = 2;
    void (*fp)(void) = targets[idx];
    fp();
}

/* ================================================================
 *  14 — 返回地址验证 (ret 指令)
 *      多个 ret 站点，验证 DFI 对 (rsp) 返回地址的追踪
 * ================================================================ */

__attribute__((noinline))
void test14_ret_chain_deep(void) {
    printf("  -> deep ret chain\n");
}  // ret

__attribute__((noinline))
void test14_ret_chain_mid(void) {
    printf("  -> mid ret chain\n");
    test14_ret_chain_deep();
}  // ret

void test14_ret_chain(void) {
    printf("[14] return address chain (nested calls)\n");
    test14_ret_chain_mid();
}  // ret

/* ================================================================
 *  15 — 双重指针间接调用 (指针的指针)
 *      mov (%rax), %rax (DEREF) → call *%rax
 *      数据流: L3=RIP_REL → L2=DEREF → L1=call *%rax
 * ================================================================ */

void (*g_fptr_ptr)(void) = test_target_a;

void test15_double_indirect(void) {
    printf("[15] double pointer indirect call\n");
    /* g_fptr_ptr 本身是函数指针，但编译器生成的可能只是简单的一层 */
    void (**fpp)(void) = &g_fptr_ptr;   // 指针的指针
    void (*fp)(void) = *fpp;            // 解引用一次
    fp();                               // call *%rax
}

/* ================================================================
 *  16 — 通过函数返回指针再调用 (两次间接调用)
 *      返回函数指针 → 再调用它
 * ================================================================ */

typedef void (*fptr_t)(void);

static fptr_t get_target(int which) {
    fptr_t table[] = {test_target_a, test_target_b, test_target_c};
    return table[which % 3];
}

void test16_returned_fptr_call(void) {
    printf("[16] call via returned function pointer\n");
    fptr_t fp = get_target(1);   // rax = get_target 的返回值
    fp();                         // call *%rax — rax 由上一层 call 定义
}

/* ================================================================
 *  17 — 多级结构体嵌套中的函数指针
 * ================================================================ */

struct outer {
    struct inner {
        void (*action)(void);
        int  flags;
    } in;
    char name[16];
};

void test17_nested_struct_fptr(void) {
    printf("[17] nested struct function pointer\n");
    struct outer obj;
    obj.in.action = test_target_b;
    obj.in.flags  = 0xdead;
    obj.in.action();
}

/* ================================================================
 *  test_all — 总入口，遍历所有测试场景
 * ================================================================ */

__attribute__((visibility("default")))
void test_all(void) {
    printf("\n========== test_all start ==========\n\n");

    test01_global_fptr_call();
    test02_local_fptr_call();
    test03_table_fptr_call(2);
    test04_stack_fptr_call();
    test05_vtable_call();
    test06_callback_arg();
    test07_indirect_jump(0);
    test08_indirect_call_with_retval(5);
    test09_indirect_call_multiarg();
    test10_volatile_fptr();
    test11_conditional_indirect(1);
    test12_switch_style(2);
    test13_runtime_computed_target();
    test14_ret_chain();
    test15_double_indirect();
    test16_returned_fptr_call();
    test17_nested_struct_fptr();

    printf("\n========== test_all done ===========\n\n");
}
