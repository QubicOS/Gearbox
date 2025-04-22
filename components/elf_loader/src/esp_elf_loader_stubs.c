#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include "rom/ets_sys.h"

/* ---------- weak stubs для неиспользуемых функций ---------- */

void __attribute__((weak)) __cxa_finalize(void *d)          { /* nothing */ }
void __attribute__((weak)) __gmon_start__(void)             { /* nothing */ }
void __attribute__((weak)) _ITM_deregisterTMCloneTable(void *t) { /* nothing */ }
void __attribute__((weak)) _ITM_registerTMCloneTable(void *t)   { /* nothing */ }

/* ---------- stack protector ---------- */

void __attribute__((weak)) __stack_chk_fail(void)
{
    ets_printf("Stack smashing detected!\n");
    abort();
}

/* ---------- минималистичный аналог glibc: __libc_start_main ---------- */

int __attribute__((weak))
__libc_start_main(int (*main)(int, char **, char **),
                  int argc, char **argv,
                  void (*init)(void), void (*fini)(void),
                  void (*rtld_fini)(void), void *stack_end)
{
    /* переходим в /mount/flash перед запуском приложения */
    chdir("/mount/flash");

    if (init)  init();
    int ret = main ? main(argc, argv, NULL) : 0;
    if (fini)  fini();
    if (rtld_fini) rtld_fini();
    return ret;
}

/* ---------- ничего больше добавлять не требуется ---------- */
