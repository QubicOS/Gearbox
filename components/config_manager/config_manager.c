/**********************************************************************
 *  CONFIG MANAGER  –  thread-safe, JSON/NVS/VFS, hot-reloadable
 *********************************************************************/
#include "config_manager.h"
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_osal/mutex.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_vfs.h"
#include "esp_timer.h"
#include "cJSON.h"
#define TAG "CFG"

#define MAX_LISTENERS 8
typedef struct { cfg_on_change_cb_t cb; void *ctx; } listener_t;

/* --- статические переменные ------------------------------------------------------- */
static const cfg_entry_t *s_tbl; static size_t s_cnt;
static listener_t s_ls[MAX_LISTENERS];
static size_t s_lc;
static char s_path[64];
static char s_nvs_ns[16];
static esp_osal_mutex_t s_mtx;

/* --- helpers ---------------------------------------------------------------------- */
static const cfg_entry_t *find(const char *sec,const char*key)
{
    for(size_t i=0;i<s_cnt;i++)
        if(!strcmp(s_tbl[i].section,sec)&&!strcmp(s_tbl[i].key,key))
            return &s_tbl[i];
    return NULL;
}
static void notify(const cfg_entry_t *e,cfg_source_t s)
{
    for(size_t i=0;i<s_lc;i++) if(s_ls[i].cb) s_ls[i].cb(e,s,s_ls[i].ctx);
}

/* --- JSON helpers (cJSON) --------------------------------------------------------- */
static cJSON* table_to_json(void)
{
    cJSON *root=cJSON_CreateObject();
    for(size_t i=0;i<s_cnt;i++){
        cJSON *sec=cJSON_GetObjectItem(root,s_tbl[i].section);
        if(!sec){ sec=cJSON_CreateObject(); cJSON_AddItemToObject(root,s_tbl[i].section,sec);}
        switch(s_tbl[i].type){
        case CFG_T_U32:  cJSON_AddNumberToObject(sec,s_tbl[i].key,*(uint32_t*)s_tbl[i].ptr); break;
        case CFG_T_I32:  cJSON_AddNumberToObject(sec,s_tbl[i].key,*(int32_t *)s_tbl[i].ptr); break;
        case CFG_T_BOOL: cJSON_AddBoolToObject  (sec,s_tbl[i].key,*(bool    *)s_tbl[i].ptr); break;
        case CFG_T_STR:  cJSON_AddStringToObject(sec,s_tbl[i].key,(char*)s_tbl[i].ptr);      break;
        case CFG_T_BIN: { char *b64 = NULL; /* base64-encode if needed */ break; }
        }
    }
    return root;
}
static void json_to_table(const cJSON *root,cfg_source_t src)
{
    cJSON *sec=NULL;
    cJSON_ArrayForEach(sec,root){
        cJSON *kv=NULL;
        cJSON_ArrayForEach(kv,sec){
            const cfg_entry_t *e=find(sec->string,kv->string);
            if(!e) continue;
            switch(e->type){
            case CFG_T_U32:  if(cJSON_IsNumber(kv)){*(uint32_t*)e->ptr=(uint32_t)kv->valuedouble; notify(e,src);} break;
            case CFG_T_I32:  if(cJSON_IsNumber(kv)){*(int32_t *)e->ptr=(int32_t )kv->valuedouble; notify(e,src);} break;
            case CFG_T_BOOL: if(cJSON_IsBool  (kv)){*(bool    *)e->ptr=cJSON_IsTrue(kv);          notify(e,src);} break;
            case CFG_T_STR:  if(cJSON_IsString(kv)&&strlen(kv->valuestring)<e->len){
                                strcpy((char*)e->ptr,kv->valuestring); notify(e,src);} break;
            case CFG_T_BIN:  /* decode base64 if нужно */ break;
            }
        }
    }
}

/* --- public API ------------------------------------------------------------------- */
esp_err_t cfg_init(const cfg_entry_t *tbl,size_t cnt,
                   const char *file_path,const char *nvs_ns)
{
    s_tbl=tbl; s_cnt=cnt;
    strncpy(s_path,file_path,sizeof(s_path)-1);
    strncpy(s_nvs_ns,nvs_ns,sizeof(s_nvs_ns)-1);
    ESP_ERROR_CHECK(esp_osal_mutex_create(&s_mtx));

    /* defaults */
    for(size_t i=0;i<cnt;i++){
        if(e_tbl[i].def_val){
            switch(tbl[i].type){
            case CFG_T_U32:*(uint32_t*)tbl[i].ptr=*(uint32_t*)tbl[i].def_val;break;
            case CFG_T_I32:*(int32_t *)tbl[i].ptr=*(int32_t *)tbl[i].def_val;break;
            case CFG_T_BOOL:*(bool*)tbl[i].ptr=*(bool*)tbl[i].def_val;break;
            case CFG_T_STR: strncpy((char*)tbl[i].ptr, tbl[i].def_val, tbl[i].len);break;
            case CFG_T_BIN: memcpy(tbl[i].ptr,tbl[i].def_val,tbl[i].len);break;
            }
        }
    }
    return cfg_load(); /* сразу подтянуть данные */
}

esp_err_t cfg_load(void)
{
    esp_osal_mutex_lock(&s_mtx,ESP_OSAL_WAIT_FOREVER);

    /* 1) файл */
    FILE *f=fopen(s_path,"r");
    if(f){
        long sz; fseek(f,0,SEEK_END); sz=ftell(f); fseek(f,0,SEEK_SET);
        char *buf=malloc(sz+1); fread(buf,1,sz,f); buf[sz]=0; fclose(f);
        cJSON *json=cJSON_Parse(buf); free(buf);
        if(json){ json_to_table(json,CFG_SRC_FILE); cJSON_Delete(json); }
    }

    /* 2) NVS */
    nvs_handle h;
    if(nvs_open(s_nvs_ns,NVS_READONLY,&h)==ESP_OK){
        for(size_t i=0;i<s_cnt;i++){
            char full[CFG_NAME_MAX*2]; sprintf(full,"%s.%s",s_tbl[i].section,s_tbl[i].key);
            switch(s_tbl[i].type){
            case CFG_T_U32:{
                uint32_t v; if(nvs_get_u32(h,full,&v)==ESP_OK)
                    {*(uint32_t*)s_tbl[i].ptr=v; notify(&s_tbl[i],CFG_SRC_NVS);}
            }break;
            case CFG_T_BOOL:{
                uint8_t v; if(nvs_get_u8(h,full,&v)==ESP_OK)
                    {*(bool*)s_tbl[i].ptr=v; notify(&s_tbl[i],CFG_SRC_NVS);}
            }break;
            case CFG_T_STR:{
                size_t len=s_tbl[i].len;
                if(nvs_get_str(h,full,(char*)s_tbl[i].ptr,&len)==ESP_OK)
                    notify(&s_tbl[i],CFG_SRC_NVS);
            }break;
            default: break;
            }
        }
        nvs_close(h);
    }
    esp_osal_mutex_unlock(&s_mtx);
    return ESP_OK;
}

esp_err_t cfg_commit(void)
{
    esp_osal_mutex_lock(&s_mtx,ESP_OSAL_WAIT_FOREVER);

    /* 1) JSON-файл */
    cJSON *root=table_to_json();
    char *txt=cJSON_PrintUnformatted(root);
    FILE *f=fopen(s_path,"w");
    if(!f){ cJSON_free(txt); cJSON_Delete(root); esp_osal_mutex_unlock(&s_mtx); return ESP_FAIL; }
    fwrite(txt,1,strlen(txt),f); fclose(f);
    cJSON_free(txt); cJSON_Delete(root);

    /* 2) NVS (только «маленькие») */
    nvs_handle h; ESP_ERROR_CHECK(nvs_open(s_nvs_ns,NVS_READWRITE,&h));
    for(size_t i=0;i<s_cnt;i++){
        char full[CFG_NAME_MAX*2]; sprintf(full,"%s.%s",s_tbl[i].section,s_tbl[i].key);
        switch(s_tbl[i].type){
        case CFG_T_U32: ESP_ERROR_CHECK(nvs_set_u32(h,full,*(uint32_t*)s_tbl[i].ptr)); break;
        case CFG_T_BOOL:ESP_ERROR_CHECK(nvs_set_u8 (h,full,*(bool    *)s_tbl[i].ptr)); break;
        case CFG_T_STR: ESP_ERROR_CHECK(nvs_set_str(h,full,(char*)s_tbl[i].ptr));       break;
        default: break;
        }
    }
    nvs_commit(h); nvs_close(h);

    esp_osal_mutex_unlock(&s_mtx);
    return ESP_OK;
}

/* ---- set/get helpers (thread-safe) ---------------------------------------------- */
#define SET_BODY(TYPE,CAST)                                                 \
    esp_err_t cfg_set_##TYPE(const char*sec,const char*key,CAST v,cfg_source_t s){\
        esp_osal_mutex_lock(&s_mtx,ESP_OSAL_WAIT_FOREVER);                  \
        const cfg_entry_t*e=find(sec,key); if(!e){esp_osal_mutex_unlock(&s_mtx);return ESP_ERR_NOT_FOUND;}\
        *(CAST*)e->ptr=v;  notify(e,s); esp_osal_mutex_unlock(&s_mtx); return ESP_OK; }

SET_BODY(u32,uint32_t) SET_BODY(bool,bool)

esp_err_t cfg_set_str(const char*sec,const char*key,const char*val,cfg_source_t s)
{
    esp_osal_mutex_lock(&s_mtx,ESP_OSAL_WAIT_FOREVER);
    const cfg_entry_t*e=find(sec,key);
    if(!e){esp_osal_mutex_unlock(&s_mtx);return ESP_ERR_NOT_FOUND;}
    strncpy((char*)e->ptr,val,e->len-1); notify(e,s);
    esp_osal_mutex_unlock(&s_mtx); return ESP_OK;
}

esp_err_t cfg_get(const char*sec,const char*key,void*out,size_t*len)
{
    esp_osal_mutex_lock(&s_mtx,ESP_OSAL_WAIT_FOREVER);
    const cfg_entry_t*e=find(sec,key);
    if(!e){esp_osal_mutex_unlock(&s_mtx);return ESP_ERR_NOT_FOUND;}
    switch(e->type){
    case CFG_T_U32: if(*len<sizeof(uint32_t)){esp_osal_mutex_unlock(&s_mtx);return ESP_ERR_INVALID_SIZE;}
                    memcpy(out,e->ptr,sizeof(uint32_t));*len=sizeof(uint32_t);break;
    case CFG_T_BOOL:if(*len<sizeof(bool))    {esp_osal_mutex_unlock(&s_mtx);return ESP_ERR_INVALID_SIZE;}
                    memcpy(out,e->ptr,sizeof(bool));*len=sizeof(bool);break;
    case CFG_T_STR: strncpy(out,e->ptr,*len);*len=strlen(out);break;
    default: esp_osal_mutex_unlock(&s_mtx); return ESP_ERR_NOT_SUPPORTED;
    }
    esp_osal_mutex_unlock(&s_mtx); return ESP_OK;
}

esp_err_t cfg_register_on_change(cfg_on_change_cb_t cb,void*ctx)
{
    if(!cb||s_lc>=MAX_LISTENERS) return ESP_ERR_INVALID_STATE;
    s_ls[s_lc++] = (listener_t){cb,ctx}; return ESP_OK;
}

/* JSON dump & CLI helpers опущены — см. исходник vault-style */

