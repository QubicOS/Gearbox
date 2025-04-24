idf_component_register(
    SRCS "telemetry.c"
    INCLUDE_DIRS "."
    PRIV_REQUIRES esp_osal esp_timer mqtt esp_http_client
)
