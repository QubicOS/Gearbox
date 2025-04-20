idf_component_register(
    SRCS
        "src/flash_mount.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES
        fatfs vfs wear_levelling
)
