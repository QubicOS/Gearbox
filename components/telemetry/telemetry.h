#pragma once
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Вид метрики */
typedef enum { TM_COUNTER, TM_GAUGE, TM_HISTO } tm_type_t;

/* Идентификатор метрики */
typedef struct tm_metric *tm_handle_t;

/* Режим транспортного экспорта */
typedef enum { TM_EXP_PUSH, TM_EXP_PULL } tm_export_mode_t;

/* --- API регистрации --------------------------------------------------------- */
tm_handle_t tm_register_counter(const char *name, const char *help,
                                const char *labels /* "core=0,if=wifi" */);
tm_handle_t tm_register_gauge  (const char *name, const char *help,
                                const char *labels);
tm_handle_t tm_register_histo  (const char *name, const char *help,
                                const double *buckets, size_t bucket_cnt,
                                const char *labels);

/* --- обновление -------------------------------------------------------------- */
void tm_inc(tm_handle_t h, double v);          /* counter +hist */
void tm_set(tm_handle_t h, double v);          /* gauge        */

/* --- экспорт ----------------------------------------------------------------- */
esp_err_t tm_init_export_mqtt(const char *uri, const char *topic_root,
                              uint32_t push_interval_ms);
esp_err_t tm_init_export_http(uint16_t port);  /* /metrics */

esp_err_t tm_start(void);   /* запускает таймеры/таски */
esp_err_t tm_stop(void);

/* Получить Prometheus-формат в строку */
esp_err_t tm_get_prom_text(char *buf, size_t *len);

/* Встроенные системные метрики (heap/uptime) */
void tm_enable_sys_metrics(bool on);

#ifdef __cplusplus
}
#endif
