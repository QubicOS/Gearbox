#pragma once
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Инициализировать и смонтировать RAM‑диск.
 */
esp_err_t ramdisk_mount(void);

/**
 * Размонтировать RAM‑диск и очистить ресурсы.
 */
void ramdisk_unmount(void);

#ifdef __cplusplus
}
#endif
