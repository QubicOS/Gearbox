#ifndef _UAM_H_
#define _UAM_H_

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define UAM_MAX_LOGIN_LEN   32
#define UAM_MAX_GROUP_LEN   16
#define UAM_TOKEN_MAX_LEN   128

/* Привилегии */
#define UAM_PRIV_READ   (1U<<0)
#define UAM_PRIV_WRITE  (1U<<1)
#define UAM_PRIV_EXEC   (1U<<2)
#define UAM_PRIV_ADMIN  (1U<<31)

/* Описание пользователя */
typedef struct {
    char     login[UAM_MAX_LOGIN_LEN];
    char     group[UAM_MAX_GROUP_LEN];
    uint32_t privileges;
} uam_user_desc_t;

/* Контекст UAM */
typedef struct uam_context uam_context_t;

/* === Инициализация === */
uam_context_t *uam_init(void);                    /* монтирование backend */
int  uam_set_storage_path(uam_context_t *, const char *path);
int  uam_migrate_nvs_to_file(uam_context_t *);    /* 1.x → 2.x */

/* === Управление пользователями (root) === */
int  uam_add_user(uam_context_t *, const char *login, const char *password,
                  const char *group, uint32_t priv);
int  uam_remove_user(uam_context_t *, const char *login);
int  uam_set_password(uam_context_t *, const char *login, const char *newpwd);
int  uam_set_group(uam_context_t *, const char *login, const char *group);
int  uam_set_privileges(uam_context_t *, const char *login, uint32_t priv);
int  uam_root_change_password(uam_context_t *, const char *newpwd);

/* === Аутентификация / токены === */
int  uam_authenticate(uam_context_t *, const char *login, const char *password,
                      char *out_token, size_t out_len);
int  uam_token_validate(uam_context_t *, const char *token,
                        uam_user_desc_t *out_user);

#ifdef __cplusplus
}
#endif

#endif /* _UAM_H_ */