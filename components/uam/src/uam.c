#include "uam_internal.h"
#include <cJSON.h>

static const char *TAG = "esp_uam";

static int ensure_master_key(uam_context_t *ctx)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(UAM_NAMESPACE, NVS_READWRITE, &h);
    if (e != ESP_OK) return -1;
    size_t len = UAM_AES_KEY_LEN;
    if (nvs_get_blob(h, UAM_MASTER_KEY_NVS, ctx->master_key, &len) != ESP_OK) {
        esp_fill_random(ctx->master_key, UAM_AES_KEY_LEN);
        nvs_set_blob(h, UAM_MASTER_KEY_NVS, ctx->master_key, UAM_AES_KEY_LEN);
        nvs_commit(h);
    }
    nvs_close(h);
    return 0;
}

uam_context_t *uam_init(void)
{
    static uam_context_t s_ctx;
    if (ensure_master_key(&s_ctx) != 0) return NULL;
    strncpy(s_ctx.storage_path, CONFIG_UAM_SD_BACKEND_PATH,
            sizeof(s_ctx.storage_path));
    return &s_ctx;
}

int uam_set_storage_path(uam_context_t *ctx, const char *path)
{
    if (!ctx || !path) return -1;
    strncpy(ctx->storage_path, path, sizeof(ctx->storage_path));
    return 0;
}

/* === Низкоуровневые операции с JSON === */
static int user_to_record(cJSON *user, uint8_t *salt, uint8_t *hash,
                          char *group, uint32_t *priv)
{
    const char *ssalt = cJSON_GetObjectItem(user, "salt")->valuestring;
    const char *shash = cJSON_GetObjectItem(user, "hash")->valuestring;
    const char *sgrp  = cJSON_GetObjectItem(user, "group")->valuestring;
    *priv             = cJSON_GetObjectItem(user, "priv")->valuedouble;

    size_t slen = esp_base64_decode(salt, 32, &slen, (const unsigned char *)ssalt,
                                    strlen(ssalt));
    size_t hlen = esp_base64_decode(hash, 32, &hlen, (const unsigned char *)shash,
                                    strlen(shash));
    strncpy(group, sgrp, UAM_MAX_GROUP_LEN);
    return (slen && hlen) ? 0 : -1;
}

static void record_to_json(cJSON *obj, const uint8_t *salt, const uint8_t *hash,
                           const char *group, uint32_t priv)
{
    char sb64[48], hb64[48]; size_t blen;
    esp_base64_encode((unsigned char *)sb64, sizeof(sb64), &blen, salt, 16);
    sb64[blen] = '\0';
    esp_base64_encode((unsigned char *)hb64, sizeof(hb64), &blen, hash, 32);
    hb64[blen] = '\0';
    cJSON_AddStringToObject(obj, "salt", sb64);
    cJSON_AddStringToObject(obj, "hash", hb64);
    cJSON_AddStringToObject(obj, "group", group);
    cJSON_AddNumberToObject(obj, "priv", priv);
}

/* === Хеширование пароля === */
static void pwd_hash(const uint8_t *salt, const char *pwd, uint8_t *out)
{
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_pkcs5_pbkdf2_hmac(info, (const unsigned char *)pwd, strlen(pwd),
                              salt, 16, 10000, 32, out);
}

/* === API реализации === */
int uam_add_user(uam_context_t *ctx, const char *login, const char *pwd,
                 const char *group, uint32_t priv)
{
    cJSON *root; if (uam_load_json(ctx, &root) != 0) return -1;
    if (cJSON_GetObjectItem(root, login)) { cJSON_Delete(root); return -1; }

    uint8_t salt[16]; esp_fill_random(salt, 16);
    uint8_t hash[32]; pwd_hash(salt, pwd, hash);

    cJSON *u = cJSON_CreateObject();
    record_to_json(u, salt, hash, group ? group : "default", priv);
    cJSON_AddItemToObject(root, login, u);

    int r = uam_save_json(ctx, root);
    cJSON_Delete(root);
    return r;
}

int uam_remove_user(uam_context_t *ctx, const char *login)
{
    cJSON *root; if (uam_load_json(ctx, &root) != 0) return -1;
    cJSON_DeleteItemFromObject(root, login);
    int r = uam_save_json(ctx, root);
    cJSON_Delete(root);
    return r;
}

static int change_field(uam_context_t *ctx, const char *login,
                        void (*mut)(cJSON *u))
{
    cJSON *root; if (uam_load_json(ctx, &root) != 0) return -1;
    cJSON *u = cJSON_GetObjectItem(root, login); if (!u) { cJSON_Delete(root); return -1; }
    mut(u);
    int r = uam_save_json(ctx, root);
    cJSON_Delete(root);
    return r;
}

int uam_set_password(uam_context_t *ctx, const char *login, const char *pwd)
{
    return change_field(ctx, login, ^(cJSON *u){
        uint8_t salt[16]; esp_fill_random(salt, 16);
        uint8_t hash[32]; pwd_hash(salt, pwd, hash);
        cJSON_DeleteItemFromObject(u, "salt");
        cJSON_DeleteItemFromObject(u, "hash");
        record_to_json(u, salt, hash, cJSON_GetObjectItem(u, "group")->valuestring,
                       cJSON_GetObjectItem(u, "priv")->valuedouble);
    });
}

int uam_set_group(uam_context_t *ctx, const char *login, const char *group)
{
    return change_field(ctx, login, ^(cJSON *u){
        cJSON_ReplaceItemInObject(u, "group", cJSON_CreateString(group));
    });
}

int uam_set_privileges(uam_context_t *ctx, const char *login, uint32_t priv)
{
    return change_field(ctx, login, ^(cJSON *u){
        cJSON_ReplaceItemInObject(u, "priv", cJSON_CreateNumber(priv));
    });
}

int uam_root_change_password(uam_context_t *ctx, const char *pwd)
{
    return uam_set_password(ctx, "root", pwd);
}

int uam_authenticate(uam_context_t *ctx, const char *login, const char *pwd,
                     char *token, size_t len)
{
    cJSON *root; if (uam_load_json(ctx, &root) != 0) return -1;
    cJSON *u = cJSON_GetObjectItem(root, login); if (!u) { cJSON_Delete(root); return -1; }
    uint8_t rsalt[16], rhash[32]; char g[UAM_MAX_GROUP_LEN]; uint32_t priv;
    user_to_record(u, rsalt, rhash, g, &priv);
    uint8_t calc[32]; pwd_hash(rsalt, pwd, calc);
    if (memcmp(calc, rhash, 32) != 0) { cJSON_Delete(root); return -1; }
    cJSON_Delete(root);
    return uam_generate_token(ctx, login, token, len);
}

int uam_token_validate(uam_context_t *ctx, const char *tok, uam_user_desc_t *out)
{
    char login[UAM_MAX_LOGIN_LEN]; if (uam_verify_token(ctx, tok, login) != 0) return -1;
    cJSON *root; if (uam_load_json(ctx, &root) != 0) return -1;
    cJSON *u = cJSON_GetObjectItem(root, login); if (!u) { cJSON_Delete(root); return -1; }
    strncpy(out->login, login, UAM_MAX_LOGIN_LEN);
    strncpy(out->group, cJSON_GetObjectItem(u, "group")->valuestring, UAM_MAX_GROUP_LEN);
    out->privileges = cJSON_GetObjectItem(u, "priv")->valuedouble;
    cJSON_Delete(root);
    return 0;
}