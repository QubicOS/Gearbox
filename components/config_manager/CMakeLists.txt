idf_component_register(
    SRCS "config_manager.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES cjson nvs_flash esp_vfs esp_osal esp_timer
)
