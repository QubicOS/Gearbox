#include <stdio.h>

void create_osinfo_file(void)
{
    const char *filepath = CONFIG_RAMDISK_BASE_PATH "/osinfo";
    FILE *f = fopen(filepath, "w");
    if (f) {
        fprintf(f, "ESP32 RAMFS Demo OS\n");
        fclose(f);
    } else {
        printf("Failed to create file: %s\n", filepath);
    }
}
