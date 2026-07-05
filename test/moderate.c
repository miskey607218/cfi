/* moderate.c — 中等规模间接跳转测试 (4 场景, ~3-5s) */
#include <stddef.h>

void fn_init(void) {}
void fn_process(void) {}
void fn_cleanup(void) {}
void fn_backup(void) {}

typedef void (*action_t)(void);

/* 全局函数指针表 */
static action_t pipeline[4] = {fn_init, fn_process, fn_cleanup, fn_backup};

/* 表索引分发 */
void dispatch_pipeline(int step) {
    if (step >= 0 && step < 4)
        pipeline[step]();          // call *pipeline(,%reg,8)
}

/* 单全局指针 */
static action_t g_handler = NULL;

void dispatch_single(void) {
    g_handler = fn_process;
    g_handler();                   // call *g_handler(%rip)
}

/* 结构体方法 */
struct worker {
    void (*start)(void);
    void (*stop)(void);
};

static struct worker g_worker;

void dispatch_struct(void) {
    g_worker.start = fn_init;
    g_worker.stop  = fn_cleanup;
    g_worker.start();              // mov g_worker(%rip),%rax → call *%rax
    g_worker.stop();
}

/* 回调 */
static action_t g_cb = NULL;

static void runner(void) {
    if (g_cb) g_cb();              // call *g_cb(%rip)
}

void dispatch_callback(void) {
    g_cb = fn_backup;
    runner();
}

/* 总入口 */
__attribute__((visibility("default")))
void test_all(void) {
    dispatch_pipeline(2);
    dispatch_single();
    dispatch_struct();
    dispatch_callback();
}
