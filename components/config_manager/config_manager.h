#pragma once
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/**  Максимальная длина имени секции/ключа  */
#define CFG_NAME_MAX 32

/**  Источник конфигурации  */
typedef enum {
    CFG_SRC_DEFAULT = 0,
    CFG_SRC_FILE,
    CFG_SRC_NVS,
    CFG_SRC_RUNTIME,
} cfg_source_t;

/**  Тип значения  */
typedef enum {
    CFG_T_U32,
    CFG_T_I32,
    CFG_T_BOOL,
    CFG_T_STR,
    CFG_T_BIN,
} cfg_type_t;

/**  Дескриптор одного параметра  */
typedef struct {
    const char *section;                  /* "network" */
    const char *key;                      /* "ssid"    */
    cfg_type_t  type;                     /* CFG_T_STR…*/
    void       *ptr;                      /* указатель на переменную */
    size_t      len;                      /* макс. размер (для STR/BIN) */
    const void *def_val;                  /* значение по умолчанию     */
} cfg_entry_t;

/**  Callback при изменении параметра */
typedef void (*cfg_on_change_cb_t)(const cfg_entry_t *entry,
                                   cfg_source_t src, void *ctx);

/**  API  */
esp_err_t cfg_init(const cfg_entry_t *table, size_t count,
                   const char *file_path, const char *nvs_namespace);

esp_err_t cfg_load(void);                /* перечитать из VFS + NVS   */
esp_err_t cfg_commit(void);              /* сохранить ↔ файл + NVS    */

esp_err_t cfg_set_str (const char *sec, const char *key,
                       const char *val, cfg_source_t src);
esp_err_t cfg_set_u32 (const char *sec, const char *key,
                       uint32_t val,     cfg_source_t src);
esp_err_t cfg_set_bool(const char *sec, const char *key,
                       bool     val,     cfg_source_t src);

esp_err_t cfg_get      (const char *sec, const char *key,
                        void *out, size_t *len);

esp_err_t cfg_register_on_change(cfg_on_change_cb_t cb, void *ctx);

/* JSON-dump всей конфигурации (формат совместим с idf.py monitor) */
esp_err_t cfg_dump_json(char *out_buf, size_t buf_sz);

/* CLI-шные вспомогалки (чтение/запись по строке) */
esp_err_t cfg_cli_handle(const char *cmd_line, char *resp, size_t resp_sz);

#ifdef __cplusplus
}
#endif
