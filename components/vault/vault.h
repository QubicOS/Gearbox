#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Инициализировать Vault.
 *        Создаёт mutex, готовит структуру данных,
 *        создаёт каталог для постоянного хранилища.
 *
 * @return ESP_OK или код ошибки.
 */
esp_err_t vault_init(void);

/**
 * @brief Деинициализировать Vault.
 *        Удаляет mutex и очищает все временные записи.
 */
void      vault_deinit(void);

/**
 * @brief Сохранить данные во временное (RAM) хранилище.
 *
 * @param key   Уникальный ключ (строка).
 * @param data  Указатель на данные.
 * @param size  Размер данных в байтах.
 *
 * @return ESP_OK или ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG.
 */
esp_err_t vault_set_temporary(const char *key, const void *data, size_t size);

/**
 * @brief Получить данные из временного хранилища.
 *
 * @param key           Ключ.
 * @param buffer        Буфер для чтения.
 * @param buffer_size   Размер буфера.
 * @param out_size      [out] реальный размер данных.
 *
 * @return ESP_OK или ESP_ERR_NOT_FOUND, ESP_ERR_INVALID_ARG.
 */
esp_err_t vault_get_temporary(const char *key, void *buffer, size_t buffer_size, size_t *out_size);

/**
 * @brief Удалить запись из временного хранилища.
 */
esp_err_t vault_erase_temporary(const char *key);

/**
 * @brief Сохранить данные в постоянное хранилище (VFS).
 *
 * @param key   Используется как имя файла в каталоге "/vault/".
 * @param data  Указатель на данные.
 * @param size  Размер данных.
 */
esp_err_t vault_set_persistent(const char *key, const void *data, size_t size);

/**
 * @brief Прочитать данные из постоянного хранилища.
 *
 * @param key           Ключ (имя файла).
 * @param buffer        Буфер для чтения.
 * @param buffer_size   Размер буфера.
 * @param out_size      [out] реальный размер.
 */
esp_err_t vault_get_persistent(const char *key, void *buffer, size_t buffer_size, size_t *out_size);

/**
 * @brief Удалить файл из постоянного хранилища.
 */
esp_err_t vault_erase_persistent(const char *key);

#ifdef __cplusplus
}
#endif
