#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hw_uart_io.h"
#include "ramdisk_mount.h"
#include "flash_mount.h"
#include "sdcard_mount.h"
#include "esp_elf.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"

static const char *TAG = "Gearbox";
static const char *ELF_FILE_PATH = "/mount/sd/init.elf";

esp_err_t load_elf_file(const char *path, uint8_t **buffer, size_t *size) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        ESP_LOGE(TAG, "Failed to open %s: %s", path, strerror(errno));
        return ESP_FAIL;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        ESP_LOGE(TAG, "Failed to get file size: %s", strerror(errno));
        close(fd);
        return ESP_FAIL;
    }

    *size = st.st_size;
    *buffer = malloc(*size);
    if (!*buffer) {
        ESP_LOGE(TAG, "Failed to allocate memory for ELF file");
        close(fd);
        return ESP_ERR_NO_MEM;
    }

    ssize_t bytes_read = read(fd, *buffer, *size);
    close(fd);

    if (bytes_read != *size) {
        ESP_LOGE(TAG, "Failed to read ELF file: read %zd of %zu bytes", bytes_read, *size);
        free(*buffer);
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void uart_echo_task(void *pvParameters)
{
    char c;
    while (1) {
        // ждем 1 байт (blocking)
        ssize_t len = read(0, &c, 1);
        if (len > 0) {
            // сразу возвращаем тот же символ
            write(1, &c, 1);
        }

        vTaskDelay(pdMS_TO_TICKS(1));
    }
}

void app_main(void) {
    // Initialize UART/CDC-ACM
    io_init();
    ESP_LOGI(TAG, "Starting Gearbox");

    uart_driver_install(CONFIG_ESP_CONSOLE_UART_NUM, 256, 0, 0, NULL, 0);  // возвращает esp_err_t
    uart_vfs_dev_use_driver(CONFIG_ESP_CONSOLE_UART_NUM);

    // Mount RAM disk
    if (ramdisk_mount() != ESP_OK) {
        ESP_LOGW(TAG, "RAM-disk init failed, continuing without it");
    }

    // Mount FATFS
    mount_fatfs();

    // Mount SD card
    mount_sdcard();

    ESP_LOGI(TAG, "Starting UART echo task");


    // Load ELF file from SD card
    uint8_t *elf_buffer = NULL;
    size_t elf_size = 0;
    if (load_elf_file(ELF_FILE_PATH, &elf_buffer, &elf_size) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to load ELF file from %s", ELF_FILE_PATH);
        return;
    }

    // Initialize ELF structure
    esp_elf_t elf;
    int ret = esp_elf_init(&elf);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to initialize ELF: %d", ret);
        free(elf_buffer);
        return;
    }

    // Relocate ELF
    ret = esp_elf_relocate(&elf, elf_buffer);
    if (ret < 0) {
        ESP_LOGE(TAG, "Failed to relocate ELF: %d", ret);
        esp_elf_deinit(&elf);
        free(elf_buffer);
        return;
    }

    // Run ELF file
    ESP_LOGI(TAG, "Starting ELF file from %s", ELF_FILE_PATH);
    esp_elf_request(&elf, 0, 0, NULL);

    // Clean up resources
    esp_elf_deinit(&elf);
    free(elf_buffer);

    ESP_LOGW(TAG, "System halted.");

    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}