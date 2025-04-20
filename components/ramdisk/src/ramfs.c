#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include "sdkconfig.h"
#include "ramfs.h"

static ramfs_fs_t *s_ramfs_fs = NULL;
static ramfs_file_t *s_files = NULL;
static size_t       s_fd_table_sz = 0;
typedef struct {
    ramfs_fs_t   *fs;
    ramfs_file_t *file;
    size_t        offset;
    bool          in_use;
    int           flags;
} ramfs_fd_t;
static ramfs_fd_t *s_fd_table = NULL;

ramfs_fs_t *ramfs_init(void)
{
    s_ramfs_fs = calloc(1, sizeof(ramfs_fs_t));
    if (!s_ramfs_fs) return NULL;
    s_files = calloc(CONFIG_RAMDISK_MAX_FILES, sizeof(ramfs_file_t));
    if (!s_files) { free(s_ramfs_fs); return NULL; }
    s_ramfs_fs->files = s_files;
    s_fd_table_sz = CONFIG_RAMDISK_MAX_FILES * 2;
    s_fd_table    = calloc(s_fd_table_sz, sizeof(ramfs_fd_t));
    if (!s_fd_table) { free(s_files); free(s_ramfs_fs); return NULL; }
    return s_ramfs_fs;
}

void ramfs_deinit(ramfs_fs_t *fs)
{
    if (!fs) return;
    for (size_t i = 0; i < CONFIG_RAMDISK_MAX_FILES; i++) {
        free(fs->files[i].data);
    }
    free(fs->files);
    free(fs);
    free(s_fd_table);
    s_fd_table = NULL;
    s_ramfs_fs = NULL;
}

static ramfs_file_t *find_file(ramfs_fs_t *fs, const char *name)
{
    for (size_t i = 0; i < CONFIG_RAMDISK_MAX_FILES; i++) {
        if (fs->files[i].used && strcmp(fs->files[i].name, name) == 0) {
            return &fs->files[i];
        }
    }
    return NULL;
}

static ramfs_file_t *create_file(ramfs_fs_t *fs, const char *name)
{
    for (size_t i = 0; i < CONFIG_RAMDISK_MAX_FILES; i++) {
        if (!fs->files[i].used) {
            memset(&fs->files[i], 0, sizeof(ramfs_file_t));
            snprintf(fs->files[i].name, sizeof(fs->files[i].name), "%s", name);
            fs->files[i].used = true;
            return &fs->files[i];
        }
    }
    errno = ENOSPC;
    return NULL;
}

static int alloc_fd(void)
{
    for (size_t i = 0; i < s_fd_table_sz; i++) {
        if (!s_fd_table[i].in_use) {
            s_fd_table[i].in_use = true;
            return (int)i;
        }
    }
    errno = EMFILE;
    return -1;
}

int ramfs_open(void *ctx, const char *path, int flags, int mode)
{
    (void)mode;
    ramfs_fs_t *fs = ctx;
    const char *name = (*path == '/') ? path + 1 : path;
    ramfs_file_t *f = find_file(fs, name);
    if (!f) {
        if (!(flags & O_CREAT)) { errno = ENOENT; return -1; }
        f = create_file(fs, name);
        if (!f) return -1;
    }
    int fd = alloc_fd();
    if (fd < 0) return -1;
    s_fd_table[fd].fs     = fs;
    s_fd_table[fd].file   = f;
    s_fd_table[fd].offset = (flags & O_APPEND) ? f->size : 0;
    s_fd_table[fd].flags  = flags;
    return fd;
}

ssize_t ramfs_read(void *ctx, int fd, void *dst, size_t len)
{
    (void)ctx;
    if ((size_t)fd >= s_fd_table_sz || !s_fd_table[fd].in_use) { errno = EBADF; return -1; }
    ramfs_file_t *f = s_fd_table[fd].file;
    size_t off = s_fd_table[fd].offset;
    if (off >= f->size) return 0;
    size_t to_copy = (len > f->size - off) ? (f->size - off) : len;
    memcpy(dst, f->data + off, to_copy);
    s_fd_table[fd].offset += to_copy;
    return to_copy;
}

ssize_t ramfs_write(void *ctx, int fd, const void *src, size_t len)
{
    (void)ctx;
    if ((size_t)fd >= s_fd_table_sz || !s_fd_table[fd].in_use) { errno = EBADF; return -1; }
    ramfs_fs_t   *fs = s_fd_table[fd].fs;
    ramfs_file_t *f  = s_fd_table[fd].file;
    if (fs->total_used + len > CONFIG_RAMDISK_SIZE) { errno = ENOSPC; return -1; }
    size_t needed = s_fd_table[fd].offset + len;
    if (needed > f->capacity) {
        size_t new_cap = ((needed + CONFIG_RAMDISK_SECTOR_SIZE - 1)
                         / CONFIG_RAMDISK_SECTOR_SIZE)
                         * CONFIG_RAMDISK_SECTOR_SIZE;
        uint8_t *buf = realloc(f->data, new_cap);
        if (!buf) { errno = ENOSPC; return -1; }
        f->data     = buf;
        f->capacity = new_cap;
    }
    memcpy(f->data + s_fd_table[fd].offset, src, len);
    s_fd_table[fd].offset += len;
    if (s_fd_table[fd].offset > f->size) {
        fs->total_used += (s_fd_table[fd].offset - f->size);
        f->size = s_fd_table[fd].offset;
    }
    return len;
}

off_t ramfs_lseek(void *ctx, int fd, off_t offset, int whence)
{
    (void)ctx;
    if ((size_t)fd >= s_fd_table_sz || !s_fd_table[fd].in_use) { errno = EBADF; return -1; }
    ramfs_file_t *f = s_fd_table[fd].file;
    size_t new_off;
    switch (whence) {
        case SEEK_SET: new_off = offset; break;
        case SEEK_CUR: new_off = s_fd_table[fd].offset + offset; break;
        case SEEK_END: new_off = f->size + offset; break;
        default: errno = EINVAL; return -1;
    }
    if (new_off > f->size) { errno = EINVAL; return -1; }
    s_fd_table[fd].offset = new_off;
    return new_off;
}

int ramfs_close(void *ctx, int fd)
{
    (void)ctx;
    if ((size_t)fd >= s_fd_table_sz || !s_fd_table[fd].in_use) { errno = EBADF; return -1; }
    s_fd_table[fd].in_use = false;
    return 0;
}

int ramfs_fstat(void *ctx, int fd, struct stat *st)
{
    (void)ctx;
    if ((size_t)fd >= s_fd_table_sz || !s_fd_table[fd].in_use) { errno = EBADF; return -1; }
    ramfs_file_t *f = s_fd_table[fd].file;
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0666;
    st->st_size = f->size;
    return 0;
}

int ramfs_stat(void *ctx, const char *path, struct stat *st)
{
    ramfs_fs_t *fs = ctx;
    const char *name = (*path == '/') ? path + 1 : path;
    ramfs_file_t *f = find_file(fs, name);
    if (!f) { errno = ENOENT; return -1; }
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG | 0666;
    st->st_size = f->size;
    return 0;
}

int ramfs_unlink(void *ctx, const char *path)
{
    ramfs_fs_t *fs = ctx;
    const char *name = (*path == '/') ? path + 1 : path;
    ramfs_file_t *f = find_file(fs, name);
    if (!f) { errno = ENOENT; return -1; }
    fs->total_used -= f->size;
    free(f->data);
    memset(f, 0, sizeof(*f));
    return 0;
}

int ramfs_rename(void *ctx, const char *src, const char *dst)
{
    ramfs_fs_t *fs = ctx;
    const char *s = (*src == '/') ? src + 1 : src;
    const char *d = (*dst == '/') ? dst + 1 : dst;
    ramfs_file_t *f = find_file(fs, s);
    if (!f) { errno = ENOENT; return -1; }
    if (find_file(fs, d)) { errno = EEXIST; return -1; }
    snprintf(f->name, sizeof(f->name), "%s", d);
    return 0;
}
