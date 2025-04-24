/**********************************************************************
 * STM – простая, потокобезопасная State-Machine-библиотека
 *********************************************************************/
#include "stm.h"
#include "esp_osal/mutex.h"
#include "esp_timer.h"
#include "esp_log.h"
#include <string.h>
#include <stdlib.h>
#define TAG "STM"

struct stm_ctx {
    char name[32];
    const stm_state_t *states; size_t sc;
    const stm_rule_t  *rules;  size_t rc;
    stm_state_id_t cur;
    esp_osal_mutex_t mtx;
    esp_timer_handle_t tmr;
};

static const stm_state_t *find_state(stm_t *sm,stm_state_id_t id)
{
    for(size_t i=0;i<sm->sc;i++) if(sm->states[i].id==id) return &sm->states[i];
    return NULL;
}

/* --- таймаут → постим виртуальное событие ------------------------- */
static void timeout_cb(void*arg)
{
    stm_t*sm=arg;
    esp_osal_mutex_lock(&sm->mtx,ESP_OSAL_WAIT_FOREVER);
    const stm_state_t*st=find_state(sm,sm->cur);
    stm_event_id_t ev=st->timeout_event;
    esp_osal_mutex_unlock(&sm->mtx);
    stm_post_event(sm,ev,NULL);
}

/* --- ядро стейт-машины -------------------------------------------- */
static esp_err_t transition(stm_t*sm,const stm_rule_t*r,void*user)
{
    const stm_state_t *old=find_state(sm,sm->cur);
    const stm_state_t *nw =find_state(sm,r->to);
    if(!nw) return ESP_ERR_INVALID_STATE;

    if(old&&old->on_exit) old->on_exit(sm,user);
    sm->cur = r->to;
    if(nw->on_enter) nw->on_enter(sm,user);

    /* настроить таймаут */
    if(sm->tmr) esp_timer_stop(sm->tmr);
    if(nw->timeout_ms){
        esp_timer_start_once(sm->tmr,(uint64_t)nw->timeout_ms*1000);
    }
    return ESP_OK;
}

/* --- public API --------------------------------------------------- */
stm_t *stm_create(const stm_state_t *st,size_t sc,
                  const stm_rule_t *rl,size_t rc,
                  stm_state_id_t init,const char*name)
{
    stm_t*sm=calloc(1,sizeof(*sm));
    strncpy(sm->name,name,sizeof(sm->name)-1);
    sm->states=st; sm->sc=sc; sm->rules=rl; sm->rc=rc; sm->cur=init;
    esp_osal_mutex_create(&sm->mtx);
    const esp_timer_create_args_t ta={.callback=timeout_cb,.arg=sm,.name="stmT"};
    esp_timer_create(&ta,&sm->tmr);
    if(find_state(sm,init)->on_enter) find_state(sm,init)->on_enter(sm,NULL);
    return sm;
}

void stm_destroy(stm_t*sm){ if(!sm) return; esp_timer_delete(sm->tmr);
    esp_osal_mutex_delete(&sm->mtx); free(sm);}

esp_err_t stm_start(stm_t*sm)
{
    esp_osal_mutex_lock(&sm->mtx,ESP_OSAL_WAIT_FOREVER);
    const stm_state_t*st=find_state(sm,sm->cur);
    if(st->timeout_ms) esp_timer_start_once(sm->tmr,(uint64_t)st->timeout_ms*1000);
    esp_osal_mutex_unlock(&sm->mtx); return ESP_OK;
}
void stm_stop(stm_t*sm){ esp_timer_stop(sm->tmr); }

stm_state_id_t stm_current(stm_t*sm){ return sm->cur; }

esp_err_t stm_post_event(stm_t*sm,stm_event_id_t ev,void*user)
{
    esp_osal_mutex_lock(&sm->mtx,ESP_OSAL_WAIT_FOREVER);
    for(size_t i=0;i<sm->rc;i++){
        const stm_rule_t*r=&sm->rules[i];
        if(r->from==sm->cur && r->event==ev &&
           (!r->guard || r->guard(sm,user))){
            esp_err_t e=transition(sm,r,user);
            esp_osal_mutex_unlock(&sm->mtx);
            return e;
        }
    }
    esp_osal_mutex_unlock(&sm->mtx);
    return ESP_ERR_NOT_FOUND;
}
