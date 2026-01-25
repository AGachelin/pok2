#include <stdio.h>
#include <stdlib.h>

#define STACK_SIZE 1024 * 64

char* create_stack() {
    char* stack = (char*)malloc(STACK_SIZE);
    if (!stack) {
        perror("Failed to allocate stack");
        exit(1);
    }
    return stack + STACK_SIZE;
}

int main() {
    char* stack_top = create_stack();
    printf("Stack created at address: %p\n", stack_top);

    free(stack_top - STACK_SIZE);
    return 0;
}