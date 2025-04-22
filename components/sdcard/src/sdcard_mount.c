#include "esp_vfs_fat.h"
#include "esp_system.h"
#include "esp_log.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

static const char *TAG = "SD_CARD";

// Функция для монтирования SD-карты через SPI
void mount_sdcard()
{
    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = true,    // Форматировать, если монтирование не удалось
        .max_files = 4,                    // Максимальное количество открытых файлов
        .allocation_unit_size = 16 * 1024  // Размер блока аллокации (16 КБ)
    };

    sdmmc_card_t *card;                    // Указатель на структуру SD-карты
    const char mount_point[] = "/mount/sd";  // Точка монтирования

    // Настройки SPI для SD-карты
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = GPIO_NUM_13;  // Пин CS для SD-карты на ESP32 CAM
    slot_config.host_id = SPI2_HOST;    // Используем SPI2 для SD-карты

    // Настройки хоста SPI
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = SPI2_HOST;  // Указываем SPI2

    // Инициализация SPI шины
    spi_bus_config_t bus_cfg = {
        .mosi_io_num = GPIO_NUM_15,  // MOSI
        .miso_io_num = GPIO_NUM_2,   // MISO
        .sclk_io_num = GPIO_NUM_14,  // SCK
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };
    esp_err_t ret = spi_bus_initialize(SPI2_HOST, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Не удалось инициализировать SPI шину: %s", esp_err_to_name(ret));
        return;
    }

    // Монтирование SD-карты через SPI
    ret = esp_vfs_fat_sdspi_mount(mount_point, &host, &slot_config, &mount_config, &card);

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL) {
            ESP_LOGE(TAG, "Не удалось смонтировать файловую систему.");
        } else {
            ESP_LOGE(TAG, "Ошибка инициализации SD-карты: %s", esp_err_to_name(ret));
        }
        return;
    }
    ESP_LOGI(TAG, "SD-карта смонтирована в %s", mount_point);
}