// test.c - 完全合法的共享库，包含各种跳转指令，但全部符合 CFI
#include <stdio.h>

// 普通返回
void test_returns(void) {
    printf("[RET] test_returns called\n");
    // 这里是 C3
}

// 间接调用（FF /2）
void (*indirect_call_ptr)(void) = test_returns;

void test_indirect_call(void) {
    printf("[INDIRECT_CALL] calling via pointer\n");
    indirect_call_ptr();        // FF /2
}

// 间接跳转（FF /4）
void test_indirect_jump(int x) {
    printf("[INDIRECT_JMP] x = %d\n", x);
    void (*ptr)(int) = test_indirect_jump;
    if (x == 0) {
        ptr(1);                 // FF /4
    }
}

// 各种 FF 指令演示（全部合法）
void test_ff_instructions(void) {
    printf("[FF] indirect call & jmp demo\n");
    // FF /2
    void (*p1)(void) = test_returns;
    p1();

    // FF /4
    void (*p2)(int) = test_indirect_jump;
    p2(999);
}

__attribute__((visibility("default")))
void test_all(void) {
    test_returns();
    test_indirect_call();
    test_indirect_jump(0);
    test_ff_instructions();
}