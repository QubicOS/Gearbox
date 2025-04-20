#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include "sdkconfig.h"
#include "ramfs.h"
#include "esp_vfs.h"

#if CONFIG_VFS_SUPPORT_DIR
DIR *ramfs_opendir(void *ctx, const char *path)
{
    (void)path;
    ramfs_fs_t *fs = ctx;
    typedef struct { ramfs_fs_t *fs; size_t idx; } ramfs_dir_t;
    ramfs_dir_t *d = calloc(1, sizeof(ramfs_dir_t));
    if (!d) { errno = ENOMEM; return NULL; }
    d->fs  = fs;
    d->idx = 0;
    return (DIR *)d;
}

struct dirent *ramfs_readdir(void *ctx, DIR *dirp)
{
    (void)ctx;
    static struct dirent ent;
    typedef struct { ramfs_fs_t *fs; size_t idx; } ramfs_dir_t;
    ramfs_dir_t *d = (ramfs_dir_t *)dirp;
    while (d->idx < CONFIG_RAMDISK_MAX_FILES) {
        ramfs_file_t *f = &d->fs->files[d->idx++];
        if (!f->used) continue;
        memset(&ent, 0, sizeof(ent));
        ent.d_type = DT_REG;
        snprintf(ent.d_name, sizeof(ent.d_name), "%s", f->name);
        return &ent;
    }
    return NULL;
}

int ramfs_closedir(void *ctx, DIR *dirp)
{
    (void)ctx;
    free(dirp);
    return 0;
}

long ramfs_telldir(void *ctx, DIR *dirp)
{
    (void)ctx;
    typedef struct { ramfs_fs_t *fs; size_t idx; } ramfs_dir_t;
    return ((ramfs_dir_t *)dirp)->idx;
}

void ramfs_seekdir(void *ctx, DIR *dirp, long offset)
{
    (void)ctx;
    typedef struct { ramfs_fs_t *fs; size_t idx; } ramfs_dir_t;
    ((ramfs_dir_t *)dirp)->idx =
        (offset < 0 || (size_t)offset > CONFIG_RAMDISK_MAX_FILES)
        ? 0 : (size_t)offset;
}
#endif  // CONFIG_VFS_SUPPORT_DIR

static const esp_vfs_dir_ops_t ramfs_dir_ops = {
    .stat_p      = ramfs_stat,
    .link_p      = NULL,
    .unlink_p    = ramfs_unlink,
    .rename_p    = ramfs_rename,
    .opendir_p   = ramfs_opendir,
    .readdir_p   = ramfs_readdir,
    .closedir_p  = ramfs_closedir,
    .telldir_p   = ramfs_telldir,
    .seekdir_p   = ramfs_seekdir,
    .mkdir_p     = NULL,
    .rmdir_p     = NULL,
    .truncate_p  = NULL,
    .ftruncate_p = NULL,
    .utime_p     = NULL
};

static const esp_vfs_fs_ops_t ramfs_ops = {
    .open_p   = ramfs_open,
    .read_p   = ramfs_read,
    .write_p  = ramfs_write,
    .lseek_p  = ramfs_lseek,
    .close_p  = ramfs_close,
    .fstat_p  = ramfs_fstat,
#if CONFIG_VFS_SUPPORT_DIR
    .dir      = &ramfs_dir_ops,
#endif
};

esp_err_t ramfs_vfs_register(const ramfs_vfs_conf_t *cfg)
{
    return esp_vfs_register_fs(
        cfg->base_path,
        &ramfs_ops,
        ESP_VFS_FLAG_DEFAULT | ESP_VFS_FLAG_CONTEXT_PTR,
        cfg->fs
    );
}

void ramfs_vfs_unregister(const char *base_path)
{
    esp_vfs_unregister(base_path);
}
