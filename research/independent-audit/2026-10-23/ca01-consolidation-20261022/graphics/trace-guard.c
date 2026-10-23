#include <stdio.h>
__attribute__((constructor)) static void ctor(void){puts("GUARD_CTOR_EXECUTED");}
int main(void){puts("GUARD_MAIN_EXECUTED");return 0;}
