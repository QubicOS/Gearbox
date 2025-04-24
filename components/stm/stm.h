#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t stm_state_id_t;
typedef uint32_t stm_event_id_t;

typedef struct stm_ctx stm_t;

typedef void (*stm_on_enter_t)(stm_t *sm, void *user);
typedef void (*stm_on_exit_t) (stm_t *sm, void *user);
typedef bool (*stm_guard_t)   (stm_t *sm, void *user);

/* Одно правило перехода */
typedef struct {
    stm_state_id_t from;
    stm_event_id_t event;
    stm_guard_t    guard;     /* NULL – без условия  */
    stm_state_id_t to;
} stm_rule_t;

/* Описание состояния */
typedef struct {
    stm_state_id_t id;
    stm_on_enter_t on_enter;
    stm_on_exit_t  on_exit;
    uint32_t       timeout_ms;     /* 0 – нет тайм-аута */
    stm_event_id_t timeout_event;
} stm_state_t;

/* Публичное API */
stm_t     *stm_create(const stm_state_t *states, size_t scount,
                      const stm_rule_t  *rules,  size_t rcount,
                      stm_state_id_t initial, const char *name);

void       stm_destroy(stm_t *sm);

/* Запустить/остановить таймеры */
esp_err_t  stm_start(stm_t *sm);
void       stm_stop (stm_t *sm);

/* Послать внешнее событие */
esp_err_t  stm_post_event(stm_t *sm, stm_event_id_t ev, void *user);

/* Получить текущий id */
stm_state_id_t stm_current(stm_t *sm);

#ifdef __cplusplus
}
#endif
