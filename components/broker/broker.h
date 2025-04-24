#pragma once

#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/** 
 * Функция-обработчик события. 
 * @param event_data  Указатель на данные события (не изменяется брокером). 
 * @param ctx         Пользовательский контекст, заданный при подписке.
 */
typedef void (*broker_sub_cb_t)(void *event_data, void *ctx);

/**
 * @brief Инициализировать брокер.
 *        Вызывать до любых publish/subscribe.
 *
 * @return ESP_OK или код ошибки.
 */
esp_err_t broker_init(void);

/**
 * @brief Деинициализировать брокер, освободить все ресурсы.
 *        После этого нельзя вызывать publish/subscribe без повторного init.
 */
void      broker_deinit(void);

/**
 * @brief Подписаться на топик.
 *
 * @param topic   Строковый идентификатор топика (null-terminated).
 * @param cb      Callback, который вызовется при публикации в этот топик.
 * @param ctx     Произвольный указатель для callback.
 *
 * @return ESP_OK или код ошибки (ESP_ERR_NO_MEM, ESP_ERR_INVALID_ARG и т.п.).
 */
esp_err_t broker_subscribe(const char *topic, broker_sub_cb_t cb, void *ctx);

/**
 * @brief Отписаться от топика.
 *
 * @param topic   Название топика.
 * @param cb      Тот же callback, что передавался в subscribe.
 * @param ctx     Тот же ctx, что передавался в subscribe.
 *
 * @return ESP_OK или ESP_ERR_NOT_FOUND, если такой подписки не было.
 */
esp_err_t broker_unsubscribe(const char *topic, broker_sub_cb_t cb, void *ctx);

/**
 * @brief Опубликовать событие в топик.
 *
 * @param topic       Название топика.
 * @param event_data  Указатель на данные события (копирования не происходит).
 *
 * @return ESP_OK или ESP_ERR_NOT_FOUND, если нет ни одной подписки на topic.
 */
esp_err_t broker_publish(const char *topic, void *event_data);

/**
 * @brief Отписаться от всех топиков для заданного ctx.
 *
 * @param ctx  Контекст, переданный в subscribe.
 *
 * @return ESP_OK.
 */
esp_err_t broker_unsubscribe_all(void *ctx);

#ifdef __cplusplus
}
#endif
