#include <string.h>
#include "esp_log.h"
#include "sdkconfig.h"
#include "ramdisk_mount.h"
#include "ramfs.h"

static const char *TAG = "ramdisk";

esp_err_t ramdisk_mount(void)
{
    ESP_LOGI(TAG, "Mounting RAM‑disk (%d bytes)…", CONFIG_RAMDISK_SIZE);
    ramfs_fs_t *fs = ramfs_init();
    if (!fs) {
        ESP_LOGE(TAG, "ramfs_init() failed");
        return ESP_FAIL;
    }

    ramfs_vfs_conf_t cfg = {
        .base_path = CONFIG_RAMDISK_BASE_PATH,
        .fs        = fs,
        .max_files = CONFIG_RAMDISK_MAX_FILES
    };
    esp_err_t err = ramfs_vfs_register(&cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ramfs_vfs_register() failed: %s", esp_err_to_name(err));
        ramfs_deinit(fs);
        return err;
    }

    ESP_LOGI(TAG, "Mounted RAM‑disk at \"%s\", max files=%d",
             CONFIG_RAMDISK_BASE_PATH,
             CONFIG_RAMDISK_MAX_FILES);
    return ESP_OK;
}

void ramdisk_unmount(void)
{
    ramfs_vfs_unregister(CONFIG_RAMDISK_BASE_PATH);
    ESP_LOGI(TAG, "RAM‑disk unmounted");
}
