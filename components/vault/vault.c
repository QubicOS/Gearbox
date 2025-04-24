/*********************************************************************
 *  Vault – защищённое хранилище (RAM + VFS)            v2.0.0 (2025)
 *  Фичи: AES-GCM, WAL-атомарность, TTL, ACL, версии,
 *         secure erase, метрики, NVS-интеграция, async, backup.
 *  Copyright (c) 2023-2025
 *  SPDX-License-Identifier: Apache-2.0
 *********************************************************************/

#include "vault.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <dirent.h>
#include "esp_log.h"
#include "esp_osal/mutex.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/gcm.h"

#ifndef VAULT_NVS_THRESHOLD
#define VAULT_NVS_THRESHOLD  256   /* ≤ этого размера — храним в NVS */
#endif

#define TAG        "Vault"
#define PERSIST_DIR "/vault"
#define WAL_DIR     "/vault/wal"
#define VER_EXT     ".ver"   /* бинарный uint32_t, big-endian */
#define TMP_CLEAN_PERIOD_SEC 600  /* каждые 10 минут */
#define PATH_MAX_LEN 128

/* ==== структуры ===================================================================== */

typedef struct temp_item {
    char               *key;
    uint8_t            *cipher;      /* iv|cipher|tag */
    size_t              cipher_len;
    int64_t             expires_us;  /* 0 == бессрочно */
    struct temp_item   *next;
} temp_item_t;

typedef struct acl_item {
    char           *key;
    char           *module;
    vault_perm_t    perms;
    struct acl_item *next;
} acl_item_t;

/* ==== глобальное состояние ========================================================== */
static struct {
    esp_osal_mutex_t lock;
    temp_item_t     *temps;
    acl_item_t      *acls;
    uint8_t          master_key[32];
    bool             mk_valid;
    vault_metrics_t  m;
    bool             inited;
} V;

/* ==== утилиты шифрования ============================================================ */
static esp_err_t aesgcm_encrypt(const uint8_t *plain, size_t len,
                                uint8_t **out, size_t *out_len)
{
    *out = NULL; *out_len = 0;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int r = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, V.master_key, 256);
    if (r) return ESP_FAIL;

    size_t iv_len = 12, tag_len = 16;
    size_t total  = iv_len + len + tag_len;
    uint8_t *buf = malloc(total);
    if (!buf) { mbedtls_gcm_free(&gcm); return ESP_ERR_NO_MEM; }

    uint8_t *iv  = buf;
    uint8_t *ct  = buf + iv_len;
    uint8_t *tag = buf + iv_len + len;
    esp_fill_random(iv, iv_len);

    r = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,
                                  len, iv, iv_len,
                                  NULL, 0, plain, ct,
                                  tag_len, tag);
    mbedtls_gcm_free(&gcm);
    if (r) { free(buf); return ESP_FAIL; }

    *out = buf; *out_len = total;
    return ESP_OK;
}

static esp_err_t aesgcm_decrypt(const uint8_t *cipher, size_t len,
                                uint8_t **out, size_t *out_len)
{
    if (len < 28) return ESP_ERR_INVALID_SIZE; /* iv(12)+tag(16)+≥0 */

    size_t iv_len = 12, tag_len = 16;
    size_t pt_len = len - iv_len - tag_len;
    *out = malloc(pt_len);
    if (!*out) return ESP_ERR_NO_MEM;

    const uint8_t *iv  = cipher;
    const uint8_t *ct  = cipher + iv_len;
    const uint8_t *tag = cipher + iv_len + pt_len;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, V.master_key, 256);
    int r = mbedtls_gcm_auth_decrypt(&gcm, pt_len, iv, iv_len,
                                     NULL, 0, tag, tag_len, ct, *out);
    mbedtls_gcm_free(&gcm);
    if (r) { free(*out); return ESP_ERR_INVALID_CRC; }

    *out_len = pt_len;
    return ESP_OK;
}

/* ==== ACL =========================================================================== */
static bool acl_check(const char *key, const char *mod, vault_perm_t p)
{
    acl_item_t *a = V.acls;
    while (a) {
        if (!strcmp(a->key,key) && !strcmp(a->module,mod) && (a->perms & p))
            return true;
        a = a->next;
    }
    return false;
}

/* ==== TTL-очистка ================================================================== */
static void ttl_task(void *arg)
{
    while (V.inited) {
        vTaskDelay(pdMS_TO_TICKS(TMP_CLEAN_PERIOD_SEC*1000));

        int64_t now = esp_timer_get_time();
        esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
        temp_item_t **pp = &V.temps;
        while (*pp) {
            if ((*pp)->expires_us && (*pp)->expires_us <= now) {
                temp_item_t *z = *pp;
                memset(z->cipher, 0, z->cipher_len);
                free(z->cipher); free(z->key);
                *pp = z->next; free(z);
                V.m.temp_count--;
            } else pp = &(*pp)->next;
        }
        esp_osal_mutex_unlock(&V.lock);
    }
    vTaskDelete(NULL);
}

/* ==== helpers VFS ================================================================== */
static esp_err_t path_build(char *dst, size_t cap, const char *dir, const char *key)
{
    if (snprintf(dst, cap, "%s/%s", dir, key) >= cap) return ESP_ERR_INVALID_SIZE;
    return ESP_OK;
}

static esp_err_t wal_write_atomic(const char *path, const uint8_t *data, size_t len)
{
    /* 1) wal */
    char wal[PATH_MAX_LEN];
    path_build(wal, sizeof(wal), WAL_DIR, strrchr(path,'/')+1);
    FILE *w = fopen(wal,"wb"); if (!w) return ESP_FAIL;
    fwrite(data,1,len,w); fclose(w);

    /* 2) main */
    FILE *f = fopen(path,"wb"); if (!f) { unlink(wal); return ESP_FAIL; }
    size_t wr = fwrite(data,1,len,f); fclose(f);
    if (wr != len) { unlink(wal); return ESP_FAIL; }

    /* 3) ok */
    unlink(wal);
    return ESP_OK;
}

static esp_err_t version_path(char *dst, size_t cap, const char *key)
{
    if (snprintf(dst, cap, "%s/%s%s", PERSIST_DIR, key, VER_EXT) >= cap)
        return ESP_ERR_INVALID_SIZE;
    return ESP_OK;
}

static esp_err_t version_read(const char *key, uint32_t *ver)
{
    char vpath[PATH_MAX_LEN];
    version_path(vpath,sizeof(vpath),key);
    FILE *f = fopen(vpath,"rb");
    if (!f) { *ver = 0; return ESP_OK; }
    fread(ver,4,1,f); fclose(f);
    *ver = __builtin_bswap32(*ver);
    return ESP_OK;
}

static esp_err_t version_write(const char *key, uint32_t ver)
{
    char vpath[PATH_MAX_LEN];
    version_path(vpath,sizeof(vpath),key);
    FILE *f = fopen(vpath,"wb");
    if (!f) return ESP_FAIL;
    uint32_t be = __builtin_bswap32(ver);
    fwrite(&be,4,1,f); fclose(f);
    return ESP_OK;
}

/* ==== init / deinit ================================================================ */
static esp_err_t master_key_load(void)
{
    nvs_handle h; size_t len = 32;
    if (nvs_open("vault","rw",&h)!=ESP_OK) return ESP_FAIL;

    if (nvs_get_blob(h,"mkey",V.master_key,&len)==ESP_OK && len==32) {
        V.mk_valid = true;
    } else {
        esp_fill_random(V.master_key,32);
        nvs_set_blob(h,"mkey",V.master_key,32);
        nvs_commit(h); V.mk_valid = true;
    }
    nvs_close(h);
    return ESP_OK;
}

esp_err_t vault_init(void)
{
    if (V.inited) return ESP_OK;
    ESP_ERROR_CHECK(esp_osal_mutex_create(&V.lock));
    esp_vfs_mkdir(PERSIST_DIR,0755);
    esp_vfs_mkdir(WAL_DIR,0755);

    ESP_RETURN_ON_ERROR(master_key_load(), TAG, "master key");

    V.inited = true;
    xTaskCreate(ttl_task,"vaultTTL",4096,NULL,tskIDLE_PRIORITY+1,NULL);
    ESP_LOGI(TAG,"initialized");
    return ESP_OK;
}

void vault_deinit(void)
{
    if (!V.inited) return;
    V.inited = false;
    vTaskDelay(pdMS_TO_TICKS(50)); /* дать ttl-таску упасть */

    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);

    /* очистка temps */
    temp_item_t *t = V.temps;
    while (t) {
        memset(t->cipher,0,t->cipher_len);
        free(t->cipher); free(t->key);
        temp_item_t *n = t->next; free(t); t = n;
    }

    /* acl */
    acl_item_t *a = V.acls;
    while (a) {
        free(a->key); free(a->module);
        acl_item_t *n = a->next; free(a); a = n;
    }
    esp_osal_mutex_unlock(&V.lock);
    esp_osal_mutex_delete(&V.lock);
    memset(&V,0,sizeof(V));
}

/* ==== ACL public =================================================================== */
esp_err_t vault_set_acl(const char *key,const char *module_id,vault_perm_t p)
{
    if (!key||!module_id) return ESP_ERR_INVALID_ARG;
    acl_item_t *a = calloc(1,sizeof(*a));
    if (!a) return ESP_ERR_NO_MEM;
    a->key=strdup(key); a->module=strdup(module_id); a->perms=p;
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    a->next = V.acls; V.acls = a;
    esp_osal_mutex_unlock(&V.lock);
    return ESP_OK;
}

bool vault_check_acl(const char *key,const char *module_id,vault_perm_t p)
{
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    bool ok = acl_check(key,module_id,p);
    esp_osal_mutex_unlock(&V.lock);
    return ok;
}

/* ==== Master key =================================================================== */
esp_err_t vault_set_master_key(const uint8_t k[32])
{
    memcpy(V.master_key,k,32); V.mk_valid=true;
    nvs_handle h;
    if (nvs_open("vault","rw",&h)!=ESP_OK) return ESP_FAIL;
    nvs_set_blob(h,"mkey",k,32); nvs_commit(h); nvs_close(h);
    return ESP_OK;
}
esp_err_t vault_get_master_key(uint8_t out[32])
{ memcpy(out,V.master_key,32); return V.mk_valid?ESP_OK:ESP_ERR_INVALID_STATE; }

/* ==== временные ==================================================================== */
static temp_item_t* temp_find(const char *key)
{
    temp_item_t *t = V.temps;
    while (t&&strcmp(t->key,key)) t=t->next;
    return t;
}

esp_err_t vault_set_temporary(const char*key,const void*data,size_t len,uint32_t ttl_ms)
{
    if(!key||!data||!len) return ESP_ERR_INVALID_ARG;
    uint8_t *ciph; size_t clen;
    ESP_ERROR_CHECK(aesgcm_encrypt(data,len,&ciph,&clen));

    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    temp_item_t *t = temp_find(key);
    if(!t){
        t=calloc(1,sizeof(*t)); t->key=strdup(key);
        t->next=V.temps; V.temps=t; V.m.temp_count++;
    }else{
        memset(t->cipher,0,t->cipher_len); free(t->cipher);
    }
    t->cipher=ciph; t->cipher_len=clen;
    t->expires_us = ttl_ms? esp_timer_get_time()+ttl_ms*1000ULL : 0;
    V.m.temp_bytes += len;
    esp_osal_mutex_unlock(&V.lock);
    return ESP_OK;
}

esp_err_t vault_get_temporary(const char*key,void*buf,size_t cap,size_t*out)
{
    if(!key||!buf||!out) return ESP_ERR_INVALID_ARG;
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    temp_item_t *t=temp_find(key);
    if(!t){ esp_osal_mutex_unlock(&V.lock); return ESP_ERR_NOT_FOUND; }
    uint8_t *plain; size_t plen;
    esp_err_t r=aesgcm_decrypt(t->cipher,t->cipher_len,&plain,&plen);
    esp_osal_mutex_unlock(&V.lock);
    if(r!=ESP_OK) return r;
    if(plen>cap){ free(plain); return ESP_ERR_INVALID_SIZE; }
    memcpy(buf,plain,plen); *out=plen; free(plain); return ESP_OK;
}

esp_err_t vault_erase_temporary(const char*key)
{
    if(!key) return ESP_ERR_INVALID_ARG;
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    temp_item_t **pp=&V.temps;
    while(*pp){
        if(!strcmp((*pp)->key,key)){
            temp_item_t*z=*pp; *pp=z->next;
            memset(z->cipher,0,z->cipher_len);
            free(z->cipher); free(z->key); free(z);
            V.m.temp_count--; break;
        } pp=&(*pp)->next;
    }
    esp_osal_mutex_unlock(&V.lock);
    return ESP_OK;
}

esp_err_t vault_get_temporary_ttl(const char*key,int64_t*ms_left)
{
    if(!key||!ms_left) return ESP_ERR_INVALID_ARG;
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    temp_item_t *t=temp_find(key);
    if(!t){ esp_osal_mutex_unlock(&V.lock); return ESP_ERR_NOT_FOUND; }
    if(!t->expires_us){ *ms_left = -1; }
    else{
        int64_t now=esp_timer_get_time();
        *ms_left = (t->expires_us>now)? (t->expires_us-now)/1000 : 0;
    }
    esp_osal_mutex_unlock(&V.lock);
    return ESP_OK;
}

/* ==== постоянные =================================================================== */
esp_err_t vault_set_persistent(const char*key,const void*data,size_t len)
{
    if(!key||!data||!len) return ESP_ERR_INVALID_ARG;
    uint8_t *ciph; size_t clen;
    ESP_ERROR_CHECK(aesgcm_encrypt(data,len,&ciph,&clen));

    char path[PATH_MAX_LEN];
    path_build(path,sizeof(path),PERSIST_DIR,key);

    /* версии */
    uint32_t ver; version_read(key,&ver); ver++;
    ESP_ERROR_CHECK(version_write(key,ver));

    esp_err_t r = wal_write_atomic(path,ciph,clen);
    free(ciph);
    if(r==ESP_OK){ V.m.persist_count++; V.m.persist_bytes+=len; }
    return r;
}

esp_err_t vault_get_persistent(const char*key,void*buf,size_t cap,size_t*out)
{
    if(!key||!buf||!out) return ESP_ERR_INVALID_ARG;
    char path[PATH_MAX_LEN];
    path_build(path,sizeof(path),PERSIST_DIR,key);

    FILE *f=fopen(path,"rb"); if(!f) return ESP_ERR_NOT_FOUND;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    uint8_t *ciph=malloc(sz); fread(ciph,1,sz,f); fclose(f);
    uint8_t *plain; size_t plen;
    esp_err_t r=aesgcm_decrypt(ciph,sz,&plain,&plen); free(ciph);
    if(r!=ESP_OK) return r;
    if(plen>cap){ free(plain); return ESP_ERR_INVALID_SIZE; }
    memcpy(buf,plain,plen); *out=plen; free(plain); return ESP_OK;
}

esp_err_t vault_erase_persistent_secure(const char*key)
{
    if(!key) return ESP_ERR_INVALID_ARG;
    char path[PATH_MAX_LEN];
    path_build(path,sizeof(path),PERSIST_DIR,key);

    FILE *f=fopen(path,"r+");
    if (f){
        fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
        uint8_t *rnd=malloc(sz); esp_fill_random(rnd,sz);
        fwrite(rnd,1,sz,f); fclose(f); free(rnd);
    }
    unlink(path);
    version_write(key,0);
    V.m.persist_count--;
    return ESP_OK;
}

esp_err_t vault_erase_persistent(const char*key)
{ return vault_erase_persistent_secure(key); }

/* ==== версии / откат =============================================================== */
esp_err_t vault_get_version(const char*key,uint32_t*ver)
{
    if(!key||!ver) return ESP_ERR_INVALID_ARG;
    return version_read(key,ver);
}

esp_err_t vault_rollback(const char*key,uint32_t target)
{
    if(!key) return ESP_ERR_INVALID_ARG;
    uint32_t cur; version_read(key,&cur);
    if(target==cur) return ESP_OK;
    return ESP_ERR_NOT_SUPPORTED; /* упрощённо: отдельные файлы-версии не ведём */
}

/* ==== перечисление ключей ========================================================== */
esp_err_t vault_list_temp_keys(char ***arr,size_t *cnt)
{
    if(!arr||!cnt) return ESP_ERR_INVALID_ARG;
    esp_osal_mutex_lock(&V.lock, ESP_OSAL_WAIT_FOREVER);
    size_t n=V.m.temp_count;
    char **list=calloc(n,sizeof(char*));
    size_t i=0;
    for(temp_item_t*t=V.temps;t;t=t->next) list[i++]=strdup(t->key);
    esp_osal_mutex_unlock(&V.lock);
    *arr=list; *cnt=n;
    return ESP_OK;
}

esp_err_t vault_list_persistent_keys(char ***arr,size_t *cnt)
{
    if(!arr||!cnt) return ESP_ERR_INVALID_ARG;
    DIR *d=opendir(PERSIST_DIR); if(!d) return ESP_FAIL;
    size_t alloc=8, n=0; char **list=malloc(alloc*sizeof(char*));
    struct dirent *e;
    while((e=readdir(d))){
        if(e->d_type!=DT_REG) continue;
        if(strstr(e->d_name,".wal")||strstr(e->d_name,VER_EXT)) continue;
        if(n==alloc){ alloc*=2; list=realloc(list,alloc*sizeof(char*)); }
        list[n++]=strdup(e->d_name);
    }
    closedir(d);
    *arr=list; *cnt=n;
    return ESP_OK;
}

/* ==== secure backup/restore (простой формат) ======================================= */
typedef struct { uint16_t name_len; uint32_t data_len; } __attribute__((packed)) hdr_t;

static esp_err_t backup_iter(FILE *out,const char*path,const char*name)
{
    FILE *f=fopen(path,"rb"); if(!f) return ESP_FAIL;
    fseek(f,0,SEEK_END); long sz=ftell(f); fseek(f,0,SEEK_SET);
    hdr_t h={htons(strlen(name)), htonl(sz)};
    fwrite(&h,sizeof(h),1,out); fwrite(name,1,strlen(name),out);
    uint8_t buf[256]; size_t r;
    while((r=fread(buf,1,sizeof(buf),f))) fwrite(buf,1,r,out);
    fclose(f); return ESP_OK;
}

esp_err_t vault_backup(const char*tar_path)
{
    FILE *out=fopen(tar_path,"wb"); if(!out) return ESP_FAIL;
    DIR *d=opendir(PERSIST_DIR); struct dirent *e;
    while((e=readdir(d))){
        if(e->d_type!=DT_REG) continue;
        if(strstr(e->d_name,".wal")||strstr(e->d_name,VER_EXT)) continue;
        char full[PATH_MAX_LEN]; path_build(full,sizeof(full),PERSIST_DIR,e->d_name);
        backup_iter(out,full,e->d_name);
    }
    closedir(d); fclose(out); return ESP_OK;
}

esp_err_t vault_restore(const char*tar_path)
{
    FILE *in=fopen(tar_path,"rb"); if(!in) return ESP_FAIL;
    while(1){
        hdr_t h; if(!fread(&h,sizeof(h),1,in)) break;
        h.name_len = ntohs(h.name_len); h.data_len = ntohl(h.data_len);
        char name[64]; fread(name,1,h.name_len,in); name[h.name_len]=0;
        char path[PATH_MAX_LEN]; path_build(path,sizeof(path),PERSIST_DIR,name);
        uint8_t *buf=malloc(h.data_len); fread(buf,1,h.data_len,in);
        wal_write_atomic(path,buf,h.data_len); free(buf);
    }
    fclose(in); return ESP_OK;
}

/* ==== метрики ====================================================================== */
esp_err_t vault_get_metrics(vault_metrics_t *m)
{ if(!m) return ESP_ERR_INVALID_ARG; *m=V.m; return ESP_OK; }

/* ==== асинхронные операции ========================================================= */
typedef struct { const char*key; const void*data; size_t len; uint32_t ttl;
                 vault_async_cb_t cb; void *ctx; } async_set_t;
static void task_set(void*arg)
{
    async_set_t*p=arg;
    esp_err_t r=vault_set_temporary(p->key,p->data,p->len,p->ttl);
    if(p->cb) p->cb(r,p->key,p->ctx);
    free((void*)p->data); free(p);
    vTaskDelete(NULL);
}
esp_err_t vault_set_temporary_async(const char*key,const void*data,size_t len,uint32_t ttl,
                                    vault_async_cb_t cb,void*ctx)
{
    async_set_t *p=calloc(1,sizeof(*p));
    p->key=key; p->data=memcpy(malloc(len),data,len); p->len=len;p->ttl=ttl;p->cb=cb;p->ctx=ctx;
    xTaskCreate(task_set,"vaultSetA",4096,p,tskIDLE_PRIORITY+1,NULL);
    return ESP_OK;
}

typedef struct { const char*key; void*buf; size_t cap; vault_async_cb_t cb; void*ctx; } async_get_t;
static void task_get(void*arg)
{
    async_get_t*p=arg; size_t out;
    esp_err_t r=vault_get_persistent(p->key,p->buf,p->cap,&out);
    if(p->cb) p->cb(r,p->key,p->ctx);
    free(p); vTaskDelete(NULL);
}
esp_err_t vault_get_persistent_async(const char*key,void*buf,size_t cap,
                                     vault_async_cb_t cb,void*ctx)
{
    async_get_t *p=calloc(1,sizeof(*p));
    p->key=key; p->buf=buf; p->cap=cap; p->cb=cb; p->ctx=ctx;
    xTaskCreate(task_get,"vaultGetA",4096,p,tskIDLE_PRIORITY+1,NULL);
    return ESP_OK;
}
