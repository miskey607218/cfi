/* simple.c — 最小规模间接跳转测试，快速验证 CFI/DFI 监控 */

void target_a(void) {}
void target_b(void) {}
void target_c(void) {}

typedef void (*fn_t)(void);

static fn_t g_fp = target_a;            // 全局函数指针
static fn_t g_table[2] = {target_b, target_c};  // 函数指针表

/* 全局指针间接调用 */
void test_global(void) {
    g_fp = target_a;
    g_fp();                  // call *g_fp(%rip)
}

/* 表索引间接调用 */
void test_table(void) {
    g_table[0]();            // call *g_table(,%reg,8)
}

/* 总入口 */
__attribute__((visibility("default")))
void test_all(void) {
    test_global();
    test_table();
}
