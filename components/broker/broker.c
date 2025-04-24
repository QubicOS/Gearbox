#include "broker.h"
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "esp_log.h"
#include "esp_osal/mutex.h"

static const char *TAG = "Broker";

/* Описание подписчика */
typedef struct subscriber {
    broker_sub_cb_t       cb;
    void                 *ctx;
    struct subscriber    *next;
} subscriber_t;

/* Топик со списком подписчиков */
typedef struct topic {
    char          *name;   /* strdup */
    subscriber_t  *subs;
    struct topic  *next;
} topic_t;

/* Глобальное состояние брокера */
static struct {
    esp_osal_mutex_t lock;
    topic_t         *topics;
    bool             inited;
} s_broker = { 0 };

esp_err_t broker_init(void)
{
    assert(!s_broker.inited);
    esp_err_t err = esp_osal_mutex_create(&s_broker.lock);
    assert(err == ESP_OK);
    s_broker.topics = NULL;
    s_broker.inited = true;
    ESP_LOGI(TAG, "initialized");
    return ESP_OK;
}

void broker_deinit(void)
{
    assert(s_broker.inited);
    esp_osal_mutex_lock(&s_broker.lock, ESP_OSAL_WAIT_FOREVER);

    /* Удаляем все топики и подписчиков */
    topic_t *t = s_broker.topics;
    while (t) {
        subscriber_t *sub = t->subs;
        while (sub) {
            subscriber_t *nsub = sub->next;
            free(sub);
            sub = nsub;
        }
        topic_t *nt = t->next;
        free(t->name);
        free(t);
        t = nt;
    }
    s_broker.topics = NULL;

    esp_osal_mutex_unlock(&s_broker.lock);
    esp_osal_mutex_delete(&s_broker.lock);
    s_broker.inited = false;
    ESP_LOGI(TAG, "deinitialized");
}

static topic_t *find_topic(const char *topic)
{
    assert(topic);
    topic_t *t = s_broker.topics;
    while (t) {
        if (strcmp(t->name, topic) == 0) {
            return t;
        }
        t = t->next;
    }
    return NULL;
}

esp_err_t broker_subscribe(const char *topic, broker_sub_cb_t cb, void *ctx)
{
    assert(s_broker.inited && topic && cb);

    esp_osal_mutex_lock(&s_broker.lock, ESP_OSAL_WAIT_FOREVER);

    topic_t *t = find_topic(topic);
    if (!t) {
        t = calloc(1, sizeof(*t));
        if (!t) {
            esp_osal_mutex_unlock(&s_broker.lock);
            return ESP_ERR_NO_MEM;
        }
        t->name = strdup(topic);
        assert(t->name);
        t->next = s_broker.topics;
        s_broker.topics = t;
        ESP_LOGD(TAG, "new topic '%s'", topic);
    }

    /* Проверим, что такой подписчик ещё не добавлен */
    subscriber_t *s = t->subs;
    while (s) {
        if (s->cb == cb && s->ctx == ctx) {
            esp_osal_mutex_unlock(&s_broker.lock);
            return ESP_OK;  /* идем молча */
        }
        s = s->next;
    }

    s = calloc(1, sizeof(*s));
    if (!s) {
        esp_osal_mutex_unlock(&s_broker.lock);
        return ESP_ERR_NO_MEM;
    }
    s->cb  = cb;
    s->ctx = ctx;
    s->next = t->subs;
    t->subs = s;

    ESP_LOGD(TAG, "subscribed to '%s'", topic);
    esp_osal_mutex_unlock(&s_broker.lock);
    return ESP_OK;
}

esp_err_t broker_unsubscribe(const char *topic, broker_sub_cb_t cb, void *ctx)
{
    assert(s_broker.inited && topic && cb);

    esp_osal_mutex_lock(&s_broker.lock, ESP_OSAL_WAIT_FOREVER);

    topic_t *t = find_topic(topic);
    if (!t) {
        esp_osal_mutex_unlock(&s_broker.lock);
        return ESP_ERR_NOT_FOUND;
    }

    subscriber_t **ps = &t->subs;
    while (*ps) {
        subscriber_t *cur = *ps;
        if (cur->cb == cb && cur->ctx == ctx) {
            *ps = cur->next;
            free(cur);
            ESP_LOGD(TAG, "unsubscribed from '%s'", topic);
            break;
        }
        ps = &cur->next;
    }

    /* Если подписчиков не осталось — удалим сам топик */
    if (!t->subs) {
        /* ищем t в списке */
        topic_t **pt = &s_broker.topics;
        while (*pt) {
            if (*pt == t) {
                *pt = t->next;
                free(t->name);
                free(t);
                break;
            }
            pt = &(*pt)->next;
        }
    }

    esp_osal_mutex_unlock(&s_broker.lock);
    return ESP_OK;
}

esp_err_t broker_publish(const char *topic, void *event_data)
{
    assert(s_broker.inited && topic);

    esp_osal_mutex_lock(&s_broker.lock, ESP_OSAL_WAIT_FOREVER);
    topic_t *t = find_topic(topic);
    if (!t || !t->subs) {
        esp_osal_mutex_unlock(&s_broker.lock);
        return ESP_ERR_NOT_FOUND;
    }

    /* Скопируем указатели подписчиков под защитой */
    size_t count = 0;
    for (subscriber_t *s = t->subs; s; s = s->next) count++;
    subscriber_t **list = malloc(count * sizeof(*list));
    assert(list);
    size_t idx = 0;
    for (subscriber_t *s = t->subs; s; s = s->next) {
        list[idx++] = s;
    }
    esp_osal_mutex_unlock(&s_broker.lock);

    /* Вне мьютекса вызываем callbacks */
    for (size_t i = 0; i < idx; i++) {
        list[i]->cb(event_data, list[i]->ctx);
    }
    free(list);

    return ESP_OK;
}

esp_err_t broker_unsubscribe_all(void *ctx)
{
    assert(s_broker.inited && ctx);

    esp_osal_mutex_lock(&s_broker.lock, ESP_OSAL_WAIT_FOREVER);
    topic_t *t = s_broker.topics;
    while (t) {
        subscriber_t **ps = &t->subs;
        while (*ps) {
            if ((*ps)->ctx == ctx) {
                subscriber_t *tofree = *ps;
                *ps = tofree->next;
                free(tofree);
            } else {
                ps = &(*ps)->next;
            }
        }
        topic_t *next = t->next;
        /* удаляем пустой топик */
        if (!t->subs) {
            /* найдём и удалим из списка */
            topic_t **pt = &s_broker.topics;
            while (*pt && *pt != t) pt = &(*pt)->next;
            if (*pt == t) {
                *pt = t->next;
                free(t->name);
                free(t);
            }
        }
        t = next;
    }
    esp_osal_mutex_unlock(&s_broker.lock);
    return ESP_OK;
}
