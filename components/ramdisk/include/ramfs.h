#pragma once
#include <stdbool.h>
#include <sys/stat.h>
#include <dirent.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ramfs_file {
    char     name[32];
    uint8_t *data;
    size_t   size;
    size_t   capacity;
    bool     used;
} ramfs_file_t;

typedef struct ramfs_fs {
    ramfs_file_t *files;
    size_t        total_used;
} ramfs_fs_t;

ramfs_fs_t *ramfs_init(void);
void        ramfs_deinit(ramfs_fs_t *fs);

typedef struct {
    const char *base_path;
    ramfs_fs_t *fs;
    size_t      max_files;
} ramfs_vfs_conf_t;

esp_err_t ramfs_vfs_register(const ramfs_vfs_conf_t *cfg);
void      ramfs_vfs_unregister(const char *base_path);

/* файловые операции */
int     ramfs_open(void *ctx, const char *path, int flags, int mode);
ssize_t ramfs_read(void *ctx, int fd, void *dst, size_t size);
ssize_t ramfs_write(void *ctx, int fd, const void *src, size_t size);
off_t   ramfs_lseek(void *ctx, int fd, off_t offset, int whence);
int     ramfs_close(void *ctx, int fd);
int     ramfs_fstat(void *ctx, int fd, struct stat *st);
/* stat по пути */
int     ramfs_stat(void *ctx, const char *path, struct stat *st);

/* операции по директориям */
int            ramfs_unlink(void *ctx, const char *path);
int            ramfs_rename(void *ctx, const char *src, const char *dst);
DIR           *ramfs_opendir(void *ctx, const char *path);
struct dirent *ramfs_readdir(void *ctx, DIR *d);
int            ramfs_closedir(void *ctx, DIR *d);
long           ramfs_telldir(void *ctx, DIR *d);
void           ramfs_seekdir(void *ctx, DIR *d, long offset);

#ifdef __cplusplus
}
#endif
