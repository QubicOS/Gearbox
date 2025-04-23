#include "uam_internal.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cJSON.h>
#include <esp_err.h>

static const char *TAG = "uam_store";

/* === Вспомогательные функции чтения / записи файла === */
static int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *tmp = malloc(sz);
    fread(tmp, 1, sz, f); fclose(f);
    *buf = tmp; *len = sz; return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len)
{
    char dir[128]; strncpy(dir, path, sizeof(dir));
    char *slash = strrchr(dir, '/'); if (slash) { *slash = '\0'; mkdir(dir, 0700); }
    FILE *f = fopen(path, "wb"); if (!f) return -1;
    fwrite(buf, 1, len, f); fclose(f); return 0;
}

/* === Шифрование / расшифрование JSON === */
static int encrypt_json(uam_context_t *ctx, const uint8_t *json, size_t jlen,
                        uint8_t **out, size_t *olen)
{
    size_t total = UAM_AES_IV_LEN + jlen + UAM_AES_TAG_LEN;
    uint8_t *buf = malloc(total);
    uint8_t *iv = buf; uint8_t *cipher = buf + UAM_AES_IV_LEN;
    uint8_t *tag = cipher + jlen;
    esp_fill_random(iv, UAM_AES_IV_LEN);

    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, ctx->master_key,
                       UAM_AES_KEY_LEN * 8);
    mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, jlen,
                              iv, UAM_AES_IV_LEN,
                              NULL, 0, json, cipher,
                              UAM_AES_TAG_LEN, tag);
    mbedtls_gcm_free(&gcm);
    *out = buf; *olen = total; return 0;
}

static int decrypt_json(uam_context_t *ctx, const uint8_t *buf, size_t len,
                        uint8_t **json, size_t *jlen)
{
    if (len < UAM_AES_IV_LEN + UAM_AES_TAG_LEN) return -1;
    const uint8_t *iv = buf; const uint8_t *cipher = buf + UAM_AES_IV_LEN;
    const uint8_t *tag = buf + len - UAM_AES_TAG_LEN;
    size_t clen = len - UAM_AES_IV_LEN - UAM_AES_TAG_LEN;

    uint8_t *plain = malloc(clen);
    mbedtls_gcm_context gcm; mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, ctx->master_key,
                       UAM_AES_KEY_LEN * 8);
    int rc = mbedtls_gcm_auth_decrypt(&gcm, clen, iv, UAM_AES_IV_LEN,
                                      NULL, 0, tag, UAM_AES_TAG_LEN,
                                      cipher, plain);
    mbedtls_gcm_free(&gcm);
    if (rc != 0) { free(plain); return -1; }
    *json = plain; *jlen = clen; return 0;
}

/* === Публичные функции === */
int uam_load_json(uam_context_t *ctx, cJSON **root)
{
    uint8_t *enc; size_t elen;
    if (read_file(ctx->storage_path, &enc, &elen) != 0) {
        *root = cJSON_CreateObject(); return 0; /* первый запуск */
    }
    uint8_t *plain; size_t plen;
    if (decrypt_json(ctx, enc, elen, &plain, &plen) != 0) { free(enc); return -1; }
    free(enc);
    char *str = malloc(plen + 1); memcpy(str, plain, plen); str[plen] = '\0';
    free(plain);
    *root = cJSON_Parse(str); free(str);
    return *root ? 0 : -1;
}

int uam_save_json(uam_context_t *ctx, cJSON *root)
{
    char *json = cJSON_PrintUnformatted(root); size_t jlen = strlen(json);
    uint8_t *enc; size_t elen;
    if (encrypt_json(ctx, (const uint8_t *)json, jlen, &enc, &elen) != 0) {
        free(json); return -1; }
    int r = write_file(ctx->storage_path, enc, elen);
    free(json); free(enc); return r;
}