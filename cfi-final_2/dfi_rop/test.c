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

// if-else 分支
void test_ifelse(int val) {
    if (val > 0) {
        printf("[IFELSE] val > 0: %d\n", val);
    } else if (val < 0) {
        printf("[IFELSE] val < 0: %d\n", val);
    } else {
        printf("[IFELSE] val == 0\n");
    }
}

// switch-case 分支
void test_switch(int val) {
    switch (val) {
        case 1:
            printf("[SWITCH] case 1\n");
            break;
        case 2:
            printf("[SWITCH] case 2\n");
            break;
        case 3:
            printf("[SWITCH] case 3\n");
            break;
        default:
            printf("[SWITCH] default: %d\n", val);
            break;
    }
}

__attribute__((visibility("default")))
void test_all(void) {
    test_returns();
    test_indirect_call();
    test_indirect_jump(0);
    test_ff_instructions();
    test_ifelse(10);
    test_ifelse(-5);
    test_ifelse(0);
    test_switch(1);
    test_switch(2);
    test_switch(99);
}