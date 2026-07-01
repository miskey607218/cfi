/* attack.c — CFI 违规验证模块
 * ==========================================
 * 设计原理:
 *   DFI 探针在"首次从内存读取函数指针"的指令处保存目标值(saved_rax)。
 *   在间接调用指令处(L1)，比较 saved_rax 与当前 rax。
 *   攻击利用 saved≠rax 触发 is_correct=0。
 *
 *   模式: SAFE → saved==rax (正确);  ATTACK → saved≠rax (违规)
 *
 * 入口:
 *   run_attack(int id)  — ATTACK 模式 (1-7)
 *   run_safe(int id)    — SAFE  模式 (1-7)
 *   test_all()          — 遍历所有攻击
 *
 * 编译: gcc -shared -fPIC -O0 -o build/attack.so src/attack.c
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

void legit_a(void) { printf("  -> [A] OK\n"); }
void legit_b(void) { printf("  -> [B] OK\n"); }
void legit_c(void) { printf("  -> [C] OK\n"); }
int  legit_calc(int x) { return x + 1; }

/* 攻击目标 — 与 legit 函数不同的地址，但仍在模块内 */
void evil_x(void) { printf("  !! EVIL X — SHOULD BE FLAGGED !!\n"); }
void evil_y(void) { printf("  !! EVIL Y — SHOULD BE FLAGGED !!\n"); }

/* ================================================================
 *  核心攻击模式
 *  ─────────────
 *  关键: 让 DFI L2/L3 保存 legitimiate 目标值，
 *        然后在 L1 前篡改为 evil 目标值。
 *        这样 saved_rax(legit) ≠ rax(evil) → is_correct=0
 *
 *  实现方式: 使用全局函数指针 + noinline 函数边界
 *    [setup] 全局变量 = legit   → DFI 捕获 legit
 *    [attack] 读取全局变量, 篡改, 调用 → L1 发现差异
 * ================================================================ */

/* ── 共享的"合法指针存储区" ── */
static void (*g_ptr)(void);

/* ================================================================
 *  Attack 01 — 全局指针被篡改
 *  setup: g_ptr = legit_a
 *  attack (ATTACK): 读取 g_ptr 后篡改为 evil_x 再调用
 *  DFI: L3 读到 legit_a → saved=legit_a; L1: rax=evil_x → 违规
 * ================================================================ */

__attribute__((noinline))
static void a01_setup(void) {
    g_ptr = legit_a;   /* 建立"合法"指针 */
}

__attribute__((noinline))
void attack_01(void) {
    printf("[01] Global Ptr Hijack\n");
    a01_setup();
    volatile void (*fp)(void) = g_ptr;  /* 从内存读 → DFI 捕获 legit_a */
    if (g_attack_mode == 1) {
        fp = evil_x;                    /* 篡改: ATTACK 模式 */
    }
    fp();  /* L1: saved=legit_a, rax=evil_x → VIOLATION */
}

/* ================================================================
 *  Attack 02 — 双重指针劫持
 *  通过二级指针修改目标
 * ================================================================ */

__attribute__((noinline))
void attack_02(void) {
    printf("[02] Double Ptr Hijack\n");
    void (*target)(void) = legit_b;
    void (* volatile *fpp)(void);
    fpp = &target;
    if (g_attack_mode == 1) {
        target = evil_y;    /* 修改一级指针的值 */
    }
    void (*fp)(void) = *fpp;  /* DEREF: 读二级指针 */
    fp();  /* ATTACK: evil_y, SAFE: legit_b */
}

/* ================================================================
 *  Attack 03 — 条件分支选择
 *  分支条件受攻击者控制走入恶意路径
 * ================================================================ */

__attribute__((noinline))
void attack_03(void) {
    printf("[03] Conditional Branch\n");
    volatile int selector = g_attack_mode;  /* 0=safe分支, 1=attack分支 */
    void (*fp)(void);
    if (selector == 0) {
        fp = legit_a;
    } else {
        fp = evil_x;         /* 攻击者控制的分支 */
    }
    fp();
}

/* ================================================================
 *  Attack 04 — 结构体函数指针替换
 *  模拟 vtable 被破坏
 * ================================================================ */

struct obj {
    void (*action)(void);
    int id;
};

__attribute__((noinline))
void attack_04(void) {
    printf("[04] Struct FPtr Replace\n");
    struct obj o;
    o.id = 1;
    o.action = legit_a;
    if (g_attack_mode == 1) {
        o.action = evil_y;   /* 篡改结构体成员 */
    }
    o.action();  /* INDIRECT_CALL via struct member */
}

/* ================================================================
 *  Attack 05 — 返回指针再调用
 *  函数返回合法指针，攻击者替换后再调用
 * ================================================================ */

__attribute__((noinline))
static void (*a05_get_ptr(void))(void) {
    return legit_b;          /* 返回合法指针 */
}

__attribute__((noinline))
void attack_05(void) {
    printf("[05] Returned Ptr Hijack\n");
    void (*fp)(void) = a05_get_ptr();  /* rax = legit_b (返回值) */
    if (g_attack_mode == 1) {
        fp = evil_x;         /* 替换返回值 */
    }
    fp();
}

/* ================================================================
 *  Attack 06 — 堆对象回调替换
 *  malloc 后的函数指针被篡改
 * ================================================================ */

__attribute__((noinline))
void attack_06(void) {
    printf("[06] Heap Callback Replace\n");
    void (**cb)(void) = malloc(sizeof(void(*)(void)));
    if (!cb) return;
    *cb = legit_c;
    if (g_attack_mode == 1) {
        *cb = evil_y;        /* 篡改堆上指针 */
    }
    (*cb)();  /* DEREF + INDIRECT_CALL */
    free(cb);
}

/* ================================================================
 *  Attack 07 — 数组函数指针表
 *  表中某个槽位被篡改
 * ================================================================ */

static void (*g_table[3])(void);

__attribute__((noinline))
static void a07_init_table(void) {
    g_table[0] = legit_a;
    g_table[1] = legit_b;
    g_table[2] = legit_c;
}

__attribute__((noinline))
void attack_07(void) {
    printf("[07] FPtr Table Poisoning\n");
    a07_init_table();
    int idx = 1;  /* 选第二个槽 */
    if (g_attack_mode == 1) {
        g_table[1] = evil_x;  /* 投毒 */
    }
    g_table[idx]();  /* INDIRECT_CALL via table */
}

/* ================================================================
 *  Dispatcher
 * ================================================================ */

__attribute__((visibility("default")))
void run_attack(int id) {
    g_attack_mode = 1;
    printf("\n===== Attack #%d (ATTACK) =====\n", id);
    switch (id) {
        case 1: attack_01(); break;
        case 2: attack_02(); break;
        case 3: attack_03(); break;
        case 4: attack_04(); break;
        case 5: attack_05(); break;
        case 6: attack_06(); break;
        case 7: attack_07(); break;
        default: printf("Invalid: %d\n", id);
    }
    printf("===== Attack #%d DONE =====\n\n", id);
}

__attribute__((visibility("default")))
void run_safe(int id) {
    g_attack_mode = 0;
    printf("\n===== Safe #%d (SAFE) =====\n", id);
    switch (id) {
        case 1: attack_01(); break;
        case 2: attack_02(); break;
        case 3: attack_03(); break;
        case 4: attack_04(); break;
        case 5: attack_05(); break;
        case 6: attack_06(); break;
        case 7: attack_07(); break;
        default: printf("Invalid: %d\n", id);
    }
    printf("===== Safe #%d DONE =====\n\n", id);
}

__attribute__((visibility("default")))
void test_all(void) {
    for (int i = 1; i <= 7; i++) run_attack(i);
}
