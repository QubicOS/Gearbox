/**********************************************************************
 * Telemetry – агрегатор метрик с MQTT/HTTP экспортом (Prometheus)
 *********************************************************************/
#include "telemetry.h"
#include "esp_osal/mutex.h"
#include "esp_timer.h"
#include "esp_log.h"
#include "mqtt_client.h"
#include "esp_http_server.h"
#include <string.h>
#include <stdlib.h>
#define TAG "TM"
#define MAX_METRICS 128

typedef struct tm_metric {
    char      name[48];
    char      help[96];
    char      labels[96];
    tm_type_t type;
    double    value;
    double   *buckets;
    size_t    bucket_cnt;
    uint64_t *hist_counts;
    struct tm_metric *next;
} tm_metric_t;

static struct {
    tm_metric_t *list;
    esp_osal_mutex_t mtx;
    /* MQTT */
    esp_mqtt_client_handle_t mqtt;
    char topic_root[64];
    uint32_t push_ms;
    /* HTTP */
    httpd_handle_t http;
    bool sys;
} T;

/* --- helpers ------------------------------------------------------------------ */
static tm_metric_t *alloc_base(const char *name,const char*help,
                               const char*labs,tm_type_t t)
{
    tm_metric_t *m=calloc(1,sizeof(*m));
    strncpy(m->name,name,sizeof(m->name)-1);
    strncpy(m->help,help,sizeof(m->help)-1);
    strncpy(m->labels,labs?labs:"",sizeof(m->labels)-1);
    m->type=t; return m;
}
static void add_metric(tm_metric_t *m)
{
    esp_osal_mutex_lock(&T.mtx,ESP_OSAL_WAIT_FOREVER);
    m->next=T.list; T.list=m;
    esp_osal_mutex_unlock(&T.mtx);
}
/* --- API регистрации --------------------------------------------------------- */
#define REG_COMMON(NAME,TYPE)                                    \
    tm_handle_t NAME(const char*n,const char*h,const char*l){    \
        tm_metric_t*m=alloc_base(n,h,l,TYPE); add_metric(m);     \
        return m;                                                \
    }
REG_COMMON(tm_register_counter,TM_COUNTER)
REG_COMMON(tm_register_gauge  ,TM_GAUGE)

tm_handle_t tm_register_histo(const char*n,const char*h,
                              const double*b,size_t bc,const char*l)
{
    tm_metric_t*m=alloc_base(n,h,l,TM_HISTO);
    m->buckets=malloc(bc*sizeof(double));
    m->hist_counts=calloc(bc+1,sizeof(uint64_t));
    memcpy(m->buckets,b,bc*sizeof(double));
    m->bucket_cnt=bc; add_metric(m); return m;
}

/* --- update ------------------------------------------------------------------ */
static void hist_add(tm_metric_t*h,double v)
{
    for(size_t i=0;i<h->bucket_cnt;i++)
        if(v<=h->buckets[i]){h->hist_counts[i]++; return;}
    h->hist_counts[h->bucket_cnt]++; /* +Inf */
}
void tm_inc(tm_handle_t h,double v)
{
    tm_metric_t*m=h;
    esp_osal_mutex_lock(&T.mtx,ESP_OSAL_WAIT_FOREVER);
    if(m->type==TM_COUNTER) m->value+=v;
    else if(m->type==TM_HISTO){ m->value+=v; hist_add(m,v); }
    esp_osal_mutex_unlock(&T.mtx);
}
void tm_set(tm_handle_t h,double v)
{
    tm_metric_t*m=h;
    if(m->type!=TM_GAUGE) return;
    esp_osal_mutex_lock(&T.mtx,ESP_OSAL_WAIT_FOREVER);
    m->value=v; esp_osal_mutex_unlock(&T.mtx);
}

/* --- prom formatting --------------------------------------------------------- */
static void print_metric(char **dst,size_t *cap,const char*fmt,...)
{
    va_list ap; va_start(ap,fmt);
    int n=vsnprintf(*dst,*cap,fmt,ap); va_end(ap);
    *dst+=n; *cap-=n;
}
esp_err_t tm_get_prom_text(char *buf,size_t *len)
{
    char *p=buf; size_t cap=*len;
    esp_osal_mutex_lock(&T.mtx,ESP_OSAL_WAIT_FOREVER);
    for(tm_metric_t*m=T.list;m;m=m->next){
        print_metric(&p,&cap,"# HELP %s %s\n# TYPE %s %s\n",
                m->name,m->help,m->name,
                m->type==TM_COUNTER?"counter":m->type==TM_GAUGE?"gauge":"histogram");
        if(m->type==TM_HISTO){
            uint64_t acc=0;
            for(size_t i=0;i<m->bucket_cnt;i++){
                acc+=m->hist_counts[i];
                print_metric(&p,&cap,"%s_bucket{%s,le=\"%.3f\"} %"PRIu64"\n",
                             m->name,m->labels,m->buckets[i],acc);
            }
            acc+=m->hist_counts[m->bucket_cnt];
            print_metric(&p,&cap,"%s_bucket{%s,le=\"+Inf\"} %"PRIu64"\n",
                         m->name,m->labels,acc);
            print_metric(&p,&cap,"%s_sum{%s} %.3f\n",m->name,m->labels,m->value);
            print_metric(&p,&cap,"%s_count{%s} %"PRIu64"\n",m->name,m->labels,acc);
        }else{
            print_metric(&p,&cap,"%s{%s} %.3f\n",m->name,m->labels,m->value);
        }
    }
    esp_osal_mutex_unlock(&T.mtx);
    *len=p-buf; return ESP_OK;
}

/* --- MQTT push --------------------------------------------------------------- */
static void push_mqtt(void*arg)
{
    char buf[1024]; size_t n=sizeof(buf);
    tm_get_prom_text(buf,&n);
    esp_mqtt_client_publish(T.mqtt,T.topic_root,buf,n,1,0);
}
static void mqtt_timer_cb(void*arg){ push_mqtt(NULL); }

esp_err_t tm_init_export_mqtt(const char*uri,const char*root,uint32_t int_ms)
{
    strcpy(T.topic_root,root);
    esp_mqtt_client_config_t c={.broker.address.uri=uri};
    T.mqtt=esp_mqtt_client_init(&c);
    esp_mqtt_client_start(T.mqtt);
    T.push_ms=int_ms;
    return ESP_OK;
}

/* --- HTTP /metrics ----------------------------------------------------------- */
static esp_err_t handle_metrics(httpd_req_t *r)
{
    char buf[2048]; size_t n=sizeof(buf);
    tm_get_prom_text(buf,&n);
    httpd_resp_set_type(r,"text/plain; version=0.0.4");
    return httpd_resp_send(r,buf,n);
}
esp_err_t tm_init_export_http(uint16_t port)
{
    httpd_config_t c=HTTPD_DEFAULT_CONFIG();
    c.server_port=port;
    httpd_start(&T.http,&c);
    httpd_uri_t u={.uri="/metrics",.method=HTTP_GET,.handler=handle_metrics};
    httpd_register_uri_handler(T.http,&u);
    return ESP_OK;
}

/* --- system metrics ---------------------------------------------------------- */
static tm_handle_t h_heap,h_uptime;
static void sys_cb(void*arg)
{
    tm_set(h_heap, (double)esp_get_free_heap_size());
    tm_set(h_uptime, (double)(esp_timer_get_time()/1e6));
}
void tm_enable_sys_metrics(bool on)
{
    if(on&&!T.sys){
        h_heap=tm_register_gauge("sys_heap_bytes","Free heap",""); 
        h_uptime=tm_register_gauge("sys_uptime_sec","Uptime",""); 
        const esp_timer_create_args_t t={.callback=sys_cb,.name="sysTM"};
        esp_timer_handle_t h; esp_timer_create(&t,&h);
        esp_timer_start_periodic(h,5000000); /* 5 с */
        T.sys=true;
    }
}

/* --- start/stop -------------------------------------------------------------- */
esp_err_t tm_start(void)
{
    ESP_ERROR_CHECK(esp_osal_mutex_create(&T.mtx));
    if(T.mqtt&&T.push_ms){
        const esp_timer_create_args_t t={.callback=mqtt_timer_cb,.name="tmMQTT"};
        esp_timer_handle_t h; esp_timer_create(&t,&h);
        esp_timer_start_periodic(h,T.push_ms*1000ULL);
    }
    return ESP_OK;
}
esp_err_t tm_stop(void){ /* TODO */ return ESP_OK; }
