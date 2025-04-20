#include "esp_vfs_fat.h"
#include "esp_system.h"
#include "esp_log.h"
#include "wear_levelling.h"

static const char *TAG = "FATFS";

void mount_fatfs()
{
    static wl_handle_t s_wl_handle;

    esp_vfs_fat_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 4,
        .allocation_unit_size = 4096
    };

    esp_err_t err = esp_vfs_fat_spiflash_mount_rw_wl("/mount/flash", "storage", &mount_config, &s_wl_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount FATFS (%s)", esp_err_to_name(err));
        return;
    }
    ESP_LOGI(TAG, "FATFS mounted at %s", "/mount/flash");
}
