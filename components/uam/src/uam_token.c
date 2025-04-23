#include "uam_internal.h"
#include <esp_base64.h>
#include <mbedtls/md.h>
#include <string.h>

/* === base64url helpers === */
static int b64url_enc(const uint8_t *in, size_t inlen, char *out, size_t outlen)
{
    size_t n; esp_base64_encode((unsigned char *)out, outlen, &n, in, inlen);
    for (size_t i = 0; i < n; ++i) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    out[n] = '\0'; return 0;
}

static int b64url_dec(const char *in, uint8_t *out, size_t *outlen)
{
    size_t len = strlen(in); char *tmp = alloca(len + 1);
    for (size_t i = 0; i < len; ++i) tmp[i] = (in[i] == '-') ? '+' : (in[i] == '_') ? '/' : in[i];
    tmp[len] = '\0';
    return esp_base64_decode(out, *outlen, outlen, (unsigned char *)tmp, len);
}

/* === token = base64url(payload|hmac) === */
int uam_generate_token(uam_context_t *ctx, const char *login,
                       char *tok, size_t toklen)
{
    uint8_t payload[64];
    uint32_t ts = esp_log_timestamp(); uint32_t nonce; esp_fill_random(&nonce, 4);
    size_t l = strlen(login) + 1;
    memcpy(payload, login, l);
    memcpy(payload + l, &ts, 4);
    memcpy(payload + l + 4, &nonce, 4);
    size_t plen = l + 8;

    uint8_t hmac[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    ctx->master_key, UAM_AES_KEY_LEN,
                    payload, plen, hmac);
    uint8_t buf[96]; memcpy(buf, payload, plen); memcpy(buf + plen, hmac, 32);
    return b64url_enc(buf, plen + 32, tok, toklen);
}

int uam_verify_token(uam_context_t *ctx, const char *tok, char *login)
{
    uint8_t buf[96]; size_t blen = sizeof(buf);
    if (b64url_dec(tok, buf, &blen) != 0 || blen < 40) return -1;
    uint8_t *payload = buf; uint8_t *sig = buf + blen - 32;
    size_t plen = blen - 32;

    uint8_t calc[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256),
                    ctx->master_key, UAM_AES_KEY_LEN,
                    payload, plen, calc);
    if (memcmp(calc, sig, 32) != 0) return -1;
    strncpy(login, (char *)payload, UAM_MAX_LOGIN_LEN);
    return 0;
}