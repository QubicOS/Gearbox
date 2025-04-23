#pragma once

#include "uam.h"
#include <mbedtls/md.h>
#include <mbedtls/gcm.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_system.h>
#include <esp_log.h>
#include <string.h>

#define UAM_NAMESPACE             "uam_keys"
#define UAM_MASTER_KEY_NVS        "key_users_master"
#define UAM_AES_KEY_LEN           32     /* 256‑bit */
#define UAM_AES_IV_LEN            16
#define UAM_AES_TAG_LEN           16

struct uam_context {
    uint8_t master_key[UAM_AES_KEY_LEN];  /* используется для AES‑GCM */
    char    storage_path[128];            /* /mount/sd/.uam/users.dat */
};

/* === helpers === */
int  uam_load_json(uam_context_t *, cJSON **root);
int  uam_save_json(uam_context_t *, cJSON *root);