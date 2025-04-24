#pragma once

#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * Права доступа к ключу 
 */
typedef enum {
    VAULT_PERM_READ  = 1 << 0,
    VAULT_PERM_WRITE = 1 << 1,
} vault_perm_t;

/**
 * Метрика Vault
 */
typedef struct {
    size_t temp_count;
    size_t persist_count;
    size_t temp_bytes;
    size_t persist_bytes;
} vault_metrics_t;

/**
 * Callback для асинхронных операций
 */
typedef void (*vault_async_cb_t)(esp_err_t err, const char *key, void *ctx);

/**
 * @brief Инициализировать Vault.  
 *   - Создаёт mutex  
 *   - Монтирует VFS, создаёт /vault/ и /vault/wal/  
 *   - Загружает мастер-ключ из NVS или генерирует новый  
 */
esp_err_t vault_init(void);

/** Деинициализация (очистка RAM-хранилища и останов задач) */
void vault_deinit(void);

/** 🌐 ACL: выдать права на ключ для модуля (id строки) */
esp_err_t vault_set_acl(const char *key, const char *module_id, vault_perm_t perms);

/** Проверить право */
bool      vault_check_acl(const char *key, const char *module_id, vault_perm_t perm);

/** 🔑 Установить/получить мастер-ключ AES-GCM (32 байта) */
esp_err_t vault_set_master_key(const uint8_t key[32]);
esp_err_t vault_get_master_key(uint8_t out_key[32]);

/**  
 * 1️⃣ Временное хранилище (шифруется в RAM)  
 */
esp_err_t vault_set_temporary(const char *key, const void *data, size_t size, uint32_t ttl_ms);
esp_err_t vault_get_temporary(const char *key, void *buf, size_t buf_size, size_t *out_size);
esp_err_t vault_erase_temporary(const char *key);

/**  
 * 2️⃣ Постоянное хранилище (VFS + WAL + шифрование)  
 */
esp_err_t vault_set_persistent(const char *key, const void *data, size_t size);
esp_err_t vault_get_persistent(const char *key, void *buf, size_t buf_size, size_t *out_size);
esp_err_t vault_erase_persistent(const char *key);

/**  
 * 3️⃣ TTL-функции  
 */
esp_err_t vault_get_temporary_ttl(const char *key, int64_t *remaining_ms);

/**  
 * 4️⃣ Версионирование  
 */
esp_err_t vault_get_version(const char *key, uint32_t *version);
esp_err_t vault_rollback(const char *key, uint32_t target_version);

/**  
 * 5️⃣ Перечисление ключей  
 */
esp_err_t vault_list_temp_keys(char ***keys, size_t *count);
esp_err_t vault_list_persistent_keys(char ***keys, size_t *count);

/**  
 * 6️⃣ Безопасное удаление  
 *    – временные автоматически очищаются
 *    – для постоянных флаг secure = true
 */
esp_err_t vault_erase_persistent_secure(const char *key);

/**  
 * 7️⃣ Резервное копирование / восстановление  
 */
esp_err_t vault_backup(const char *tar_path);
esp_err_t vault_restore(const char *tar_path);

/**  
 * 8️⃣ Метрики  
 */
esp_err_t vault_get_metrics(vault_metrics_t *metrics);

/**  
 * 9️⃣ Интеграция c NVS (для small blobs)  
 *    – threshold задаётся в sdkconfig: VAULT_NVS_THRESHOLD  
 */

/**  
 * 🔟 Асинхронные операции  
 */
esp_err_t vault_set_temporary_async(const char *key, const void *data, size_t size,
                                    uint32_t ttl_ms, vault_async_cb_t cb, void *ctx);
esp_err_t vault_get_persistent_async(const char *key, void *buf, size_t buf_size,
                                     vault_async_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
