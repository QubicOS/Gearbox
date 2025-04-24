#include "vault.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <assert.h>
#include "esp_log.h"
#include "esp_osal/mutex.h"
#include "esp_err.h"
#include "esp_vfs.h"
#include "esp_vfs_fat.h"  // или нужный VFS

static const char *TAG = "Vault";
#define PERSIST_DIR  "/vault"

typedef struct vault_item {
    char               *key;
    void               *data;
    size_t              size;
    struct vault_item  *next;
} vault_item_t;

static struct {
    esp_osal_mutex_t lock;
    vault_item_t    *temp_list;
    bool             inited;
} s_vault = { 0 };

static vault_item_t* find_temp(const char *key) {
    vault_item_t *it = s_vault.temp_list;
    while (it) {
        if (strcmp(it->key, key) == 0) return it;
        it = it->next;
    }
    return NULL;
}

esp_err_t vault_init(void)
{
    assert(!s_vault.inited);
    esp_err_t err = esp_osal_mutex_create(&s_vault.lock);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "mutex create failed");
        return err;
    }
    // Создать каталог в VFS (игнорируем, если уже есть)
    mkdir(PERSIST_DIR, 0777);
    s_vault.temp_list = NULL;
    s_vault.inited = true;
    ESP_LOGI(TAG, "initialized");
    return ESP_OK;
}

void vault_deinit(void)
{
    assert(s_vault.inited);
    esp_osal_mutex_lock(&s_vault.lock, ESP_OSAL_WAIT_FOREVER);

    // Очистить все временные записи
    vault_item_t *it = s_vault.temp_list;
    while (it) {
        vault_item_t *n = it->next;
        free(it->key);
        free(it->data);
        free(it);
        it = n;
    }
    s_vault.temp_list = NULL;

    esp_osal_mutex_unlock(&s_vault.lock);
    esp_osal_mutex_delete(&s_vault.lock);
    s_vault.inited = false;
    ESP_LOGI(TAG, "deinitialized");
}

esp_err_t vault_set_temporary(const char *key, const void *data, size_t size)
{
    assert(s_vault.inited && key && data && size>0);
    esp_osal_mutex_lock(&s_vault.lock, ESP_OSAL_WAIT_FOREVER);

    // Если уже есть — перезаписать
    vault_item_t *it = find_temp(key);
    if (it) {
        free(it->data);
        it->data = malloc(size);
        if (!it->data) {
            esp_osal_mutex_unlock(&s_vault.lock);
            return ESP_ERR_NO_MEM;
        }
        memcpy(it->data, data, size);
        it->size = size;
        esp_osal_mutex_unlock(&s_vault.lock);
        return ESP_OK;
    }

    // создать новую запись
    it = calloc(1, sizeof(*it));
    if (!it) {
        esp_osal_mutex_unlock(&s_vault.lock);
        return ESP_ERR_NO_MEM;
    }
    it->key = strdup(key);
    it->data = malloc(size);
    if (!it->key || !it->data) {
        free(it->key);
        free(it);
        esp_osal_mutex_unlock(&s_vault.lock);
        return ESP_ERR_NO_MEM;
    }
    memcpy(it->data, data, size);
    it->size = size;
    it->next = s_vault.temp_list;
    s_vault.temp_list = it;

    esp_osal_mutex_unlock(&s_vault.lock);
    ESP_LOGD(TAG, "temp set '%s' (%u bytes)", key, (unsigned)size);
    return ESP_OK;
}

esp_err_t vault_get_temporary(const char *key, void *buffer, size_t buffer_size, size_t *out_size)
{
    assert(s_vault.inited && key && buffer && out_size);
    esp_osal_mutex_lock(&s_vault.lock, ESP_OSAL_WAIT_FOREVER);

    vault_item_t *it = find_temp(key);
    if (!it) {
        esp_osal_mutex_unlock(&s_vault.lock);
        return ESP_ERR_NOT_FOUND;
    }
    if (buffer_size < it->size) {
        esp_osal_mutex_unlock(&s_vault.lock);
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(buffer, it->data, it->size);
    *out_size = it->size;

    esp_osal_mutex_unlock(&s_vault.lock);
    return ESP_OK;
}

esp_err_t vault_erase_temporary(const char *key)
{
    assert(s_vault.inited && key);
    esp_osal_mutex_lock(&s_vault.lock, ESP_OSAL_WAIT_FOREVER);

    vault_item_t **pit = &s_vault.temp_list;
    while (*pit) {
        if (strcmp((*pit)->key, key) == 0) {
            vault_item_t *tofree = *pit;
            *pit = tofree->next;
            free(tofree->key);
            free(tofree->data);
            free(tofree);
            esp_osal_mutex_unlock(&s_vault.lock);
            ESP_LOGD(TAG, "temp erase '%s'", key);
            return ESP_OK;
        }
        pit = &(*pit)->next;
    }

    esp_osal_mutex_unlock(&s_vault.lock);
    return ESP_ERR_NOT_FOUND;
}

esp_err_t vault_set_persistent(const char *key, const void *data, size_t size)
{
    assert(s_vault.inited && key && data && size>0);
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", PERSIST_DIR, key);

    FILE *f = fopen(path, "wb");
    if (!f) {
        ESP_LOGE(TAG, "open '%s' failed", path);
        return ESP_FAIL;
    }
    size_t w = fwrite(data, 1, size, f);
    fclose(f);
    if (w != size) {
        ESP_LOGE(TAG, "write '%s' short (%u/%u)", path, (unsigned)w, (unsigned)size);
        return ESP_FAIL;
    }
    ESP_LOGD(TAG, "persist set '%s' (%u bytes)", key, (unsigned)size);
    return ESP_OK;
}

esp_err_t vault_get_persistent(const char *key, void *buffer, size_t buffer_size, size_t *out_size)
{
    assert(s_vault.inited && key && buffer && out_size);
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", PERSIST_DIR, key);

    FILE *f = fopen(path, "rb");
    if (!f) {
        return ESP_ERR_NOT_FOUND;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || (size_t)sz > buffer_size) {
        fclose(f);
        return ESP_ERR_INVALID_SIZE;
    }
    size_t r = fread(buffer, 1, sz, f);
    fclose(f);
    if (r != (size_t)sz) {
        return ESP_FAIL;
    }
    *out_size = r;
    return ESP_OK;
}

esp_err_t vault_erase_persistent(const char *key)
{
    assert(s_vault.inited && key);
    char path[128];
    snprintf(path, sizeof(path), "%s/%s", PERSIST_DIR, key);
    int res = unlink(path);
    if (res != 0) {
        return ESP_ERR_NOT_FOUND;
    }
    ESP_LOGD(TAG, "persist erase '%s'", key);
    return ESP_OK;
}
