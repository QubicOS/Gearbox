idf_component_register(
    SRCS
        "src/sdcard_mount.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES
        fatfs vfs sdmmc
)
