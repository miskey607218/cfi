/* dispatch.c — DFI 追踪器友好的函数指针分发测试
 *
 * 设计原则（避免安全模式下误报）:
 *   1. 全局函数指针表 → RIP_REL 加载，不与其他栈变量冲突
 *   2. 函数指针加载后立即调用，无中间操作
 *   3. 每个函数只做一次间接跳转，隔离性好
 *   4. 不使用 volatile / 复杂条件赋值
 *
 * 编译: gcc -shared -fPIC -O0 -o dispatch.so dispatch.c
 */

#include <stdio.h>

/* ═══════════════════════════════════════════
 *  目标函数
 * ═══════════════════════════════════════════ */

void cmd_open(void)   { }
void cmd_close(void)  { }
void cmd_read(void)   { }
void cmd_write(void)  { }
void cmd_flush(void)  { }
void cmd_seek(void)   { }

/* ═══════════════════════════════════════════
 *  全局函数指针 — RIP_REL 寻址，追踪器可准确捕获
 * ═══════════════════════════════════════════ */

typedef void (*cmd_fn)(void);

/* 场景 A: 单个全局指针 + 直接调用 */
static cmd_fn g_cmd = NULL;

void dispatch_global(void) {
    g_cmd = cmd_open;
    g_cmd();                  // RIP_REL: mov g_cmd(%rip),%rax → call *%rax
}

/* 场景 B: 全局函数指针表 + 索引调用 */
static cmd_fn g_dispatch_table[4] = {
    cmd_open, cmd_close, cmd_read, cmd_write
};

void dispatch_table(int idx) {
    if (idx >= 0 && idx < 4)
        g_dispatch_table[idx]();  // RIP_REL: mov table(,%reg,8),%rax → call *%rax
}

/* 场景 C: 全局指针切换 — 先 A 后 B */
static cmd_fn g_primary   = NULL;
static cmd_fn g_secondary = NULL;

void dispatch_swap(void) {
    g_primary   = cmd_read;
    g_secondary = cmd_write;

    g_primary();              // 第一次间接调用
    g_secondary();            // 第二次间接调用 — 不同指针，不同加载
}

/* 场景 D: 带参数的间接调用 — 函数指针全局，参数传寄存器 */
static void (*g_action)(void) = NULL;

void dispatch_with_arg(const char *tag) {
    g_action = cmd_flush;
    g_action();               // call *%rax, 参数不影响 rax
}

/* 场景 E: 回调 — 被调用方执行间接调用 */
static cmd_fn g_callback = NULL;

static void runner(void) {
    if (g_callback)
        g_callback();         // call *g_callback(%rip)
}

void dispatch_callback(void) {
    g_callback = cmd_seek;
    runner();                 // 间接触发
}

/* 场景 F: 结构体全局实例 — DEREF 解引用 */
struct ops {
    void (*init)(void);
    void (*fini)(void);
};

static struct ops g_ops;

void dispatch_struct(void) {
    g_ops.init = cmd_open;
    g_ops.fini = cmd_close;

    g_ops.init();             // mov g_ops(%rip),%rax → call *%rax
    g_ops.fini();             // mov g_ops+8(%rip),%rax → call *%rax
}

/* ═══════════════════════════════════════════
 *  test_all — 总入口（无 printf 减少 rax 干扰）
 * ═══════════════════════════════════════════ */

__attribute__((visibility("default")))
void test_all(void) {
    dispatch_global();
    dispatch_table(2);
    dispatch_swap();
    dispatch_with_arg("ok");
    dispatch_callback();
    dispatch_struct();
}
