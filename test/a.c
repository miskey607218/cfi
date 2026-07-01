/* a.c — DFI/ROP 综合测试与攻击验证模块
 * ==========================================
 * 同时包含正常间接跳转场景 + DFI 确定性违规攻击，
 * 可通过 test_all() / run_attack(id) / run_safe(id) 入口调用。
 *
 * 设计原理:
 *   DFI 探针在"首次从内存读取函数指针"的指令处保存目标值(saved_rax)。
 *   在间接调用指令处(L1)，比较 saved_rax 与当前 rax。
 *   SAFE  → saved==rax (正确)
 *   ATTACK → saved≠rax (违规)
 *
 * 编译: gcc -shared -fPIC -O0 -o build/a/a.so test/a.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ================================================================
 *  全局模式
 * ================================================================ */

static int g_attack_mode = 0;  /* 0=SAFE, 1=ATTACK */

/* ================================================================
 *  目标函数
 * ================================================================ */

void target_a(void) { printf("  -> [A] OK\n"); }
void target_b(void) { printf("  -> [B] OK\n"); }
void target_c(void) { printf("  -> [C] OK\n"); }
void target_d(void) { printf("  -> [D] OK\n"); }
int  target_calc(int x)   { return x + 1; }
void target_args(int a, int b, int c) { printf("  -> sum = %d\n", a + b + c); }

void evil_x(void) { printf("  !! EVIL X — SHOULD BE FLAGGED !!\n"); }
void evil_y(void) { printf("  !! EVIL Y — SHOULD BE FLAGGED !!\n"); }

/* ================================================================
 *  共享的"合法指针存储区"
 * ================================================================ */

static void (*g_ptr)(void);

/* ================================================================
 *  01 — 全局函数指针间接调用 (正常场景)
 * ================================================================ */

void (*g_callback)(void) = target_a;

__attribute__((noinline))
void test01_global_fptr(void) {
    printf("[01] global function pointer\n");
    g_callback();
}

/* ================================================================
 *  02 — 局部函数指针间接调用
 * ================================================================ */

__attribute__((noinline))
void test02_local_fptr(void) {
    printf("[02] local function pointer\n");
    void (*fp)(void) = target_b;
    fp();
}

/* ================================================================
 *  03 — 函数指针表调用 (RIP_REL 读数组)
 * ================================================================ */

static void (*g_fptr_table[4])(void) = {
    target_a, target_b, target_c, target_d
};

__attribute__((noinline))
void test03_table_fptr(int idx) {
    printf("[03] table dispatch [%d]\n", idx);
    if (idx >= 0 && idx < 4)
        g_fptr_table[idx]();
}

/* ================================================================
 *  04 — 栈上函数指针 (RBP_REL)
 * ================================================================ */

__attribute__((noinline))
void test04_stack_fptr(void) {
    printf("[04] stack-based fptr\n");
    void (*fp)(void) = target_c;
    void (*volatile fp2)(void) = fp;
    fp2();
}

/* ================================================================
 *  05 — vtable 模拟 (结构体函数指针)
 * ================================================================ */

struct vtable {
    void (*do_a)(void);
    void (*do_b)(void);
    int data;
};

__attribute__((noinline))
void test05_vtable(void) {
    printf("[05] vtable-style\n");
    struct vtable vt;
    vt.do_a = target_a;
    vt.do_b = target_b;
    vt.data = 42;
    vt.do_a();
}

/* ================================================================
 *  06 — 回调函数指针传参 (寄存器参数)
 * ================================================================ */

static void call_via_fp(void (*fp)(void)) {
    fp();
}

__attribute__((noinline))
void test06_callback(void) {
    printf("[06] callback via argument\n");
    call_via_fp(target_d);
}

/* ================================================================
 *  07 — 间接跳转 + 尾调用
 * ================================================================ */

__attribute__((noinline))
void test07_indirect_jump(void) {
    printf("[07] indirect jump / tail call\n");
    void (*volatile jp)(void) = target_c;
    jp();
}

/* ================================================================
 *  08 — 间接调用带返回值
 * ================================================================ */

__attribute__((noinline))
void test08_with_retval(int n) {
    printf("[08] indirect call with retval\n");
    int (*fp)(int) = target_calc;
    int result = fp(n);
    printf("  -> result = %d\n", result);
}

/* ================================================================
 *  09 — 多参数间接调用
 * ================================================================ */

__attribute__((noinline))
void test09_multiarg(void) {
    printf("[09] multi-arg indirect call\n");
    void (*fp)(int, int, int) = target_args;
    fp(10, 20, 30);
}

/* ================================================================
 *  10 — volatile 强制内存路径 (完整的 L3→L1 数据流)
 * ================================================================ */

__attribute__((noinline))
void test10_volatile(void) {
    printf("[10] volatile forced memory path\n");
    volatile void (*fp)(void) = target_a;
    fp();
}

/* ================================================================
 *  11 — 条件选择间接调用 (jcc + 间接混合)
 * ================================================================ */

__attribute__((noinline))
void test11_conditional(int cond) {
    printf("[11] conditional indirect (cond=%d)\n", cond);
    void (*fp)(void);
    if (cond)
        fp = target_a;
    else
        fp = target_b;
    fp();
}

/* ================================================================
 *  12 — switch-case 分发
 * ================================================================ */

__attribute__((noinline))
void test12_switch(int code) {
    printf("[12] switch-style dispatch (code=%d)\n", code);
    void (*fp)(void) = NULL;
    switch (code) {
        case 0: fp = target_a; break;
        case 1: fp = target_b; break;
        case 2: fp = target_c; break;
        default:fp = target_d; break;
    }
    if (fp) fp();
}

/* ================================================================
 *  13 — LEA 计算目标地址
 * ================================================================ */

__attribute__((noinline))
void test13_lea_target(void) {
    printf("[13] LEA computed target\n");
    void (*targets[3])(void) = {target_a, target_b, target_c};
    void (*fp)(void) = targets[2];
    fp();
}

/* ================================================================
 *  14 — 嵌套返回链 (RET 验证)
 * ================================================================ */

__attribute__((noinline))
void ret_chain_deep(void)     { printf("  -> deep ret\n"); }

__attribute__((noinline))
void ret_chain_mid(void)      { printf("  -> mid ret\n"); ret_chain_deep(); }

__attribute__((noinline))
void test14_ret_chain(void)   { printf("[14] ret chain\n"); ret_chain_mid(); }

/* ================================================================
 *  15 — 双重指针间接调用 (指针的指针)
 * ================================================================ */

static void (*g_fptr_ptr)(void) = target_a;

__attribute__((noinline))
void test15_double_ptr(void) {
    printf("[15] double pointer indirect\n");
    void (**fpp)(void) = &g_fptr_ptr;
    void (*fp)(void) = *fpp;
    fp();
}

/* ================================================================
 *  16 — 函数返回指针再调用 (跨调用数据流)
 * ================================================================ */

typedef void (*fptr_t)(void);

static fptr_t get_target(int which) {
    fptr_t table[] = {target_a, target_b, target_c};
    return table[which % 3];
}

__attribute__((noinline))
void test16_returned_fptr(void) {
    printf("[16] returned fptr call\n");
    fptr_t fp = get_target(1);
    fp();
}

/* ================================================================
 *  17 — 嵌套结构体函数指针
 * ================================================================ */

struct outer {
    struct inner {
        void (*action)(void);
        int flags;
    } in;
    char name[16];
};

__attribute__((noinline))
void test17_nested_struct(void) {
    printf("[17] nested struct fptr\n");
    struct outer obj;
    obj.in.action = target_b;
    obj.in.flags  = 0xdead;
    obj.in.action();
}

/* ================================================================
 *  攻击场景 A1 — 全局指针劫持
 *  setup: g_ptr = target_a
 *  ATTACK: 篡改为 evil_x → saved(legit) ≠ rax(evil) → 违规
 * ================================================================ */

__attribute__((noinline))
static void a1_setup(void) {
    g_ptr = target_a;
}

__attribute__((noinline))
void attack_a1_global_hijack(void) {
    printf("[A1] Global Ptr Hijack\n");
    a1_setup();
    volatile void (*fp)(void) = g_ptr;   /* L3: 从数据段读 target_a */
    if (g_attack_mode == 1) {
        fp = evil_x;                     /* 篡改 */
    }
    fp();  /* L1: saved=target_a, rax=evil_x → VIOLATION */
}

/* ================================================================
 *  攻击场景 A2 — 二级指针劫持
 * ================================================================ */

__attribute__((noinline))
void attack_a2_double_ptr(void) {
    printf("[A2] Double Ptr Hijack\n");
    void (*target)(void) = target_b;
    void (* volatile *fpp)(void);
    fpp = &target;
    if (g_attack_mode == 1) {
        target = evil_y;
    }
    void (*fp)(void) = *fpp;
    fp();
}

/* ================================================================
 *  攻击场景 A3 — 条件分支劫持
 * ================================================================ */

__attribute__((noinline))
void attack_a3_branch(void) {
    printf("[A3] Conditional Branch Hijack\n");
    volatile int selector = g_attack_mode;
    void (*fp)(void);
    if (selector == 0) {
        fp = target_a;
    } else {
        fp = evil_x;
    }
    fp();
}

/* ================================================================
 *  攻击场景 A4 — 结构体函数指针替换 (vtable 破坏)
 * ================================================================ */

struct obj {
    void (*action)(void);
    int id;
};

__attribute__((noinline))
void attack_a4_struct_replace(void) {
    printf("[A4] Struct FPtr Replace\n");
    struct obj o;
    o.id = 1;
    o.action = target_a;
    if (g_attack_mode == 1) {
        o.action = evil_y;
    }
    o.action();
}

/* ================================================================
 *  攻击场景 A5 — 返回指针劫持
 * ================================================================ */

__attribute__((noinline))
static void (*a5_get_ptr(void))(void) {
    return target_b;
}

__attribute__((noinline))
void attack_a5_returned_hijack(void) {
    printf("[A5] Returned Ptr Hijack\n");
    void (*fp)(void) = a5_get_ptr();
    if (g_attack_mode == 1) {
        fp = evil_x;
    }
    fp();
}

/* ================================================================
 *  攻击场景 A6 — 堆回调替换
 * ================================================================ */

__attribute__((noinline))
void attack_a6_heap_callback(void) {
    printf("[A6] Heap Callback Replace\n");
    void (**cb)(void) = malloc(sizeof(void(*)(void)));
    if (!cb) return;
    *cb = target_c;
    if (g_attack_mode == 1) {
        *cb = evil_y;
    }
    (*cb)();
    free(cb);
}

/* ================================================================
 *  攻击场景 A7 — 函数指针表投毒
 * ================================================================ */

static void (*g_table[3])(void);

__attribute__((noinline))
static void a7_init_table(void) {
    g_table[0] = target_a;
    g_table[1] = target_b;
    g_table[2] = target_c;
}

__attribute__((noinline))
void attack_a7_table_poison(void) {
    printf("[A7] FPtr Table Poisoning\n");
    a7_init_table();
    int idx = 1;
    if (g_attack_mode == 1) {
        g_table[1] = evil_x;
    }
    g_table[idx]();
}

/* ================================================================
 *  入口函数
 * ================================================================ */

__attribute__((visibility("default")))
void test_all(void) {
    printf("\n========== test_all (SAFE) ==========\n\n");

    test01_global_fptr();
    test02_local_fptr();
    test03_table_fptr(2);
    test04_stack_fptr();
    test05_vtable();
    test06_callback();
    test07_indirect_jump();
    test08_with_retval(5);
    test09_multiarg();
    test10_volatile();
    test11_conditional(1);
    test12_switch(2);
    test13_lea_target();
    test14_ret_chain();
    test15_double_ptr();
    test16_returned_fptr();
    test17_nested_struct();

    printf("\n========== test_all DONE ==========\n\n");
}

__attribute__((visibility("default")))
void run_attack(int id) {
    g_attack_mode = 1;
    printf("\n===== Attack #%d (ATTACK) =====\n", id);
    switch (id) {
        case 1: attack_a1_global_hijack();  break;
        case 2: attack_a2_double_ptr();      break;
        case 3: attack_a3_branch();          break;
        case 4: attack_a4_struct_replace();  break;
        case 5: attack_a5_returned_hijack(); break;
        case 6: attack_a6_heap_callback();   break;
        case 7: attack_a7_table_poison();    break;
        default: printf("Invalid: %d\n", id);
    }
    printf("===== Attack #%d DONE =====\n\n", id);
}

__attribute__((visibility("default")))
void run_safe(int id) {
    g_attack_mode = 0;
    printf("\n===== Safe #%d (SAFE) =====\n", id);
    switch (id) {
        case 1: attack_a1_global_hijack();  break;
        case 2: attack_a2_double_ptr();      break;
        case 3: attack_a3_branch();          break;
        case 4: attack_a4_struct_replace();  break;
        case 5: attack_a5_returned_hijack(); break;
        case 6: attack_a6_heap_callback();   break;
        case 7: attack_a7_table_poison();    break;
        default: printf("Invalid: %d\n", id);
    }
    printf("===== Safe #%d DONE =====\n\n", id);
}
