#include <stdio.h>
#include <string.h>

// 存在栈溢出漏洞的函数
__attribute__((visibility("default")))
void vulnerable_function(const char *input) {
    char buffer[64];
    // 危险操作：不限制拷贝长度，导致栈溢出
    strcpy(buffer, input);
    printf("Buffer content: %s\n", buffer);
}

// 安全版本（用于对比）
__attribute__((visibility("default")))
void safe_function(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("Safe buffer content: %s\n", buffer);
}