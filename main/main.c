#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hw_uart_io.h"
#include "ramdisk_mount.h"
#include "flash_mount.h"

static const char *TAG = "Gearbox";

void app_main(void)
{
    // Настроить UART/CDC-ACM
    io_init();
    ESP_LOGI(TAG, "Starting Gearbox");

    // Примонтировать RAM‑диск
    if (ramdisk_mount() != ESP_OK) {
        ESP_LOGW(TAG, "RAM‑disk init failed, продолжим без него");
    }

    // Примонтировать FATFS
    mount_fatfs();

    FILE *f = fopen("/mount/flash/osinfo", "w");
    if (!f) {
        printf("Failed to create /mount/flash/osinfo: %s\n", strerror(errno));
        return;
    }

    fprintf(f, "Gearbox OS 1.0\nBuilt: %s %s\n", __DATE__, __TIME__);
    fclose(f);
    printf("Created /mount/flash/osinfo\n");
    f = fopen("/mount/flash/osinfo", "r");
if (f) {
    char buf[64];
    fgets(buf, sizeof(buf), f);
    printf("OS Info: %s\n", buf);
    fclose(f);
}


    // Основной цикл
    while (1) {
        ESP_LOGI(TAG, "Hello, Gearbox");
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
