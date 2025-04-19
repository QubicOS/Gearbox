#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Инициализирует UART‑stdio по настройкам из menuconfig. */
void io_init(void);

/**
 * Читает до len байт в buf, возвращает число прочитанных байт (таймаут 100 мс).
 * Буфер не NULL‑терминируется.
 */
int io_read(char *buf, int len);

/**
 * Записывает len байт из buf, возвращает число записанных байт.
 */
int io_write(const char *buf, int len);

/**
 * Удобная обёртка: выводит нуль‑терминированную строку.
 */
static inline int io_writestring(const char *s) {
    size_t l = 0;
    while (s[l]) ++l;
    return io_write(s, (int)l);
}

#ifdef __cplusplus
}
#endif
