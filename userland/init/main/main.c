#include <stdio.h>
#include <unistd.h>

static int s_cnt;

int main(int argc, char *argv[])
{
    for (int i = 0; i < 10; i++) {
        printf("hello world %d\n", s_cnt++);
        sleep(1);
    }

    return 0;
}