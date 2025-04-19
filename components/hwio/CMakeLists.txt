idf_component_register(
    SRCS
        "src/uart.c"
    INCLUDE_DIRS
        "include"
    PRIV_REQUIRES
        esp_driver_uart
)
