/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <reent.h>
#include <pthread.h>
#include <setjmp.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "rom/ets_sys.h"

#include "private/elf_symbol.h"

extern int __ltdf2(double a, double b);
extern unsigned int __fixunsdfsi(double a);
extern int __gtdf2(double a, double b);
extern double __floatunsidf(unsigned int i);
extern double __divdf3(double a, double b);

extern uam_context_t *uam_init(void);
extern int  uam_set_storage_path(uam_context_t *, const char *);
extern int  uam_migrate_nvs_to_file(uam_context_t *);
extern int  uam_add_user(uam_context_t *, const char *, const char *, const char *, uint32_t);
extern int  uam_remove_user(uam_context_t *, const char *);
extern int  uam_set_password(uam_context_t *, const char *, const char *);
extern int  uam_set_group(uam_context_t *, const char *, const char *);
extern int  uam_set_privileges(uam_context_t *, const char *, uint32_t);
extern int  uam_root_change_password(uam_context_t *, const char *);
extern int  uam_authenticate(uam_context_t *, const char *, const char *, char *, size_t);
extern int  uam_token_validate(uam_context_t *, const char *, uam_user_desc_t *);

/* === libc symbol table (unchanged, shortened for brevity) === */
extern const struct esp_elfsym g_esp_libc_elfsyms[];

/* === public ESP‑IDF symbols table (unchanged) === */
extern const struct esp_elfsym g_esp_espidf_elfsyms[];


/** @brief Libc public functions symbols look-up table */

static const struct esp_elfsym g_esp_libc_elfsyms[] = {

    /* string.h */

    ESP_ELFSYM_EXPORT(strerror),
    ESP_ELFSYM_EXPORT(memset),
    ESP_ELFSYM_EXPORT(memcpy),
    ESP_ELFSYM_EXPORT(strlen),
    ESP_ELFSYM_EXPORT(strtod),
    ESP_ELFSYM_EXPORT(strrchr),
    ESP_ELFSYM_EXPORT(strchr),
    ESP_ELFSYM_EXPORT(strcmp),
    ESP_ELFSYM_EXPORT(strtol),
    ESP_ELFSYM_EXPORT(strcspn),
    ESP_ELFSYM_EXPORT(strncat),
    ESP_ELFSYM_EXPORT(strtok),           /*  NEW */

    /* stdio.h */

    ESP_ELFSYM_EXPORT(puts),
    ESP_ELFSYM_EXPORT(putchar),
    ESP_ELFSYM_EXPORT(fputc),
    ESP_ELFSYM_EXPORT(fputs),
    ESP_ELFSYM_EXPORT(printf),
    ESP_ELFSYM_EXPORT(vfprintf),
    ESP_ELFSYM_EXPORT(fprintf),
    ESP_ELFSYM_EXPORT(fwrite),
    ESP_ELFSYM_EXPORT(fgets),            /*  NEW */
    ESP_ELFSYM_EXPORT(perror),           /*  NEW */

    /* unistd.h */

    ESP_ELFSYM_EXPORT(usleep),
    ESP_ELFSYM_EXPORT(sleep),
    ESP_ELFSYM_EXPORT(exit),
    ESP_ELFSYM_EXPORT(close),
    ESP_ELFSYM_EXPORT(chdir),            /*  NEW */
    ESP_ELFSYM_EXPORT(getcwd),           /*  NEW */

    /* dirent.h */
    ESP_ELFSYM_EXPORT(opendir),          /*  NEW */
    ESP_ELFSYM_EXPORT(readdir),          /*  NEW */
    ESP_ELFSYM_EXPORT(closedir),         /*  NEW */

    /* stdlib.h */

    ESP_ELFSYM_EXPORT(malloc),
    ESP_ELFSYM_EXPORT(calloc),
    ESP_ELFSYM_EXPORT(realloc),
    ESP_ELFSYM_EXPORT(free),

    /* time.h */

    ESP_ELFSYM_EXPORT(clock_gettime),
    ESP_ELFSYM_EXPORT(strftime),

    /* pthread.h */

    ESP_ELFSYM_EXPORT(pthread_create),
    ESP_ELFSYM_EXPORT(pthread_attr_init),
    ESP_ELFSYM_EXPORT(pthread_attr_setstacksize),
    ESP_ELFSYM_EXPORT(pthread_detach),
    ESP_ELFSYM_EXPORT(pthread_join),
    ESP_ELFSYM_EXPORT(pthread_exit),

    /* newlib */

    ESP_ELFSYM_EXPORT(__errno),
    ESP_ELFSYM_EXPORT(__getreent),
#ifdef __HAVE_LOCALE_INFO__
    ESP_ELFSYM_EXPORT(__locale_ctype_ptr),
#else
    ESP_ELFSYM_EXPORT(_ctype_),
#endif

    /* math */

    ESP_ELFSYM_EXPORT(__ltdf2),
    ESP_ELFSYM_EXPORT(__fixunsdfsi),
    ESP_ELFSYM_EXPORT(__gtdf2),
    ESP_ELFSYM_EXPORT(__floatunsidf),
    ESP_ELFSYM_EXPORT(__divdf3),

    /* getopt.h */

    ESP_ELFSYM_EXPORT(getopt_long),
    ESP_ELFSYM_EXPORT(optind),
    ESP_ELFSYM_EXPORT(opterr),
    ESP_ELFSYM_EXPORT(optarg),
    ESP_ELFSYM_EXPORT(optopt),

    /* setjmp.h */

    ESP_ELFSYM_EXPORT(longjmp),
    ESP_ELFSYM_EXPORT(setjmp),

    ESP_ELFSYM_END
};

/** @brief ESP-IDF public functions symbols look-up table */

static const struct esp_elfsym g_esp_espidf_elfsyms[] = {

    /* sys/socket.h */

    ESP_ELFSYM_EXPORT(lwip_bind),
    ESP_ELFSYM_EXPORT(lwip_setsockopt),
    ESP_ELFSYM_EXPORT(lwip_socket),
    ESP_ELFSYM_EXPORT(lwip_listen),
    ESP_ELFSYM_EXPORT(lwip_accept),
    ESP_ELFSYM_EXPORT(lwip_recv),
    ESP_ELFSYM_EXPORT(lwip_recvfrom),
    ESP_ELFSYM_EXPORT(lwip_send),
    ESP_ELFSYM_EXPORT(lwip_sendto),
    ESP_ELFSYM_EXPORT(lwip_connect),

    /* arpa/inet.h */

    ESP_ELFSYM_EXPORT(ipaddr_addr),
    ESP_ELFSYM_EXPORT(lwip_htons),
    ESP_ELFSYM_EXPORT(lwip_htonl),
    ESP_ELFSYM_EXPORT(ip4addr_ntoa),

    /* ROM functions */

    ESP_ELFSYM_EXPORT(ets_printf),

    ESP_ELFSYM_END
};

static const struct esp_elfsym g_esp_prop_elfsyms[] = {
    /* Wi‑Fi */
    ESP_ELFSYM_EXPORT(esp_wifi_init),
    ESP_ELFSYM_EXPORT(esp_wifi_set_mode),
    ESP_ELFSYM_EXPORT(esp_wifi_start),
    ESP_ELFSYM_EXPORT(esp_wifi_stop),

    /* Event */
    ESP_ELFSYM_EXPORT(esp_event_loop_create_default),
    ESP_ELFSYM_EXPORT(esp_event_handler_register),

    /* HTTP client */
    ESP_ELFSYM_EXPORT(esp_http_client_init),
    ESP_ELFSYM_EXPORT(esp_http_client_perform),
    ESP_ELFSYM_EXPORT(esp_http_client_cleanup),

    /* MQTT */
    ESP_ELFSYM_EXPORT(esp_mqtt_client_init),
    ESP_ELFSYM_EXPORT(esp_mqtt_client_publish),
    ESP_ELFSYM_EXPORT(esp_mqtt_client_subscribe),

    ESP_ELFSYM_END
};

static const struct esp_elfsym g_esp_idf_ext_elfsyms[] = {
    /* System */
    ESP_ELFSYM_EXPORT(esp_restart),
    ESP_ELFSYM_EXPORT(esp_get_free_heap_size),
    ESP_ELFSYM_EXPORT(esp_chip_info),

    /* Timer */
    ESP_ELFSYM_EXPORT(esp_timer_get_time),
    ESP_ELFSYM_EXPORT(esp_timer_create),
    ESP_ELFSYM_EXPORT(esp_timer_start_once),
    ESP_ELFSYM_EXPORT(esp_timer_delete),

    /* GPIO */
    ESP_ELFSYM_EXPORT(gpio_set_direction),
    ESP_ELFSYM_EXPORT(gpio_set_level),
    ESP_ELFSYM_EXPORT(gpio_get_level),
    ESP_ELFSYM_EXPORT(gpio_config),

    /* UART */
    ESP_ELFSYM_EXPORT(uart_driver_install),
    ESP_ELFSYM_EXPORT(uart_param_config),
    ESP_ELFSYM_EXPORT(uart_set_pin),
    ESP_ELFSYM_EXPORT(uart_write_bytes),
    ESP_ELFSYM_EXPORT(uart_read_bytes),

    /* SPI */
    ESP_ELFSYM_EXPORT(spi_bus_initialize),
    ESP_ELFSYM_EXPORT(spi_bus_add_device),
    ESP_ELFSYM_EXPORT(spi_device_transmit),

    /* I2C */
    ESP_ELFSYM_EXPORT(i2c_param_config),
    ESP_ELFSYM_EXPORT(i2c_driver_install),
    ESP_ELFSYM_EXPORT(i2c_master_write_read_device),

    /* ADC */
    ESP_ELFSYM_EXPORT(adc1_config_width),
    ESP_ELFSYM_EXPORT(adc1_config_channel_atten),
    ESP_ELFSYM_EXPORT(adc1_get_raw),

    /* LEDC (PWM) */
    ESP_ELFSYM_EXPORT(ledc_timer_config),
    ESP_ELFSYM_EXPORT(ledc_channel_config),
    ESP_ELFSYM_EXPORT(ledc_set_duty),
    ESP_ELFSYM_EXPORT(ledc_update_duty),

    /* I2S */
    ESP_ELFSYM_EXPORT(i2s_driver_install),
    ESP_ELFSYM_EXPORT(i2s_set_clk),
    ESP_ELFSYM_EXPORT(i2s_write),
    ESP_ELFSYM_EXPORT(i2s_read),

    /* NVS */
    ESP_ELFSYM_EXPORT(nvs_flash_init),
    ESP_ELFSYM_EXPORT(nvs_flash_erase),
    ESP_ELFSYM_EXPORT(nvs_open),
    ESP_ELFSYM_EXPORT(nvs_get_str),
    ESP_ELFSYM_EXPORT(nvs_set_str),
    ESP_ELFSYM_EXPORT(nvs_commit),

    /* Networking */
    ESP_ELFSYM_EXPORT(esp_netif_init),
    ESP_ELFSYM_EXPORT(esp_netif_create_default_wifi_sta),
    ESP_ELFSYM_EXPORT(esp_event_loop_create_default),
    ESP_ELFSYM_EXPORT(esp_event_handler_register),

    /* HTTP client */
    ESP_ELFSYM_EXPORT(esp_http_client_init),
    ESP_ELFSYM_EXPORT(esp_http_client_perform),
    ESP_ELFSYM_EXPORT(esp_http_client_cleanup),

    /* MQTT */
    ESP_ELFSYM_EXPORT(esp_mqtt_client_init),
    ESP_ELFSYM_EXPORT(esp_mqtt_client_publish),
    ESP_ELFSYM_EXPORT(esp_mqtt_client_subscribe),

    ESP_ELFSYM_END
};

/* === ELF‑loader API symbols === */
static const struct esp_elfsym g_esp_elfloader_elfsyms[] = {
    ESP_ELFSYM_EXPORT(esp_elf_init),
    ESP_ELFSYM_EXPORT(esp_elf_relocate),
    ESP_ELFSYM_EXPORT(esp_elf_request),
    ESP_ELFSYM_EXPORT(esp_elf_deinit),
    ESP_ELFSYM_EXPORT(esp_elf_map_sym),
    ESP_ELFSYM_EXPORT(esp_elf_print_ehdr),
    ESP_ELFSYM_EXPORT(esp_elf_print_phdr),
    ESP_ELFSYM_EXPORT(esp_elf_print_shdr),
    ESP_ELFSYM_EXPORT(esp_elf_print_sec),
    ESP_ELFSYM_END
};


/* === esp_uam API symbols === */
static const struct esp_elfsym g_esp_uam_elfsyms[] = {
    ESP_ELFSYM_EXPORT(uam_init),
    ESP_ELFSYM_EXPORT(uam_set_storage_path),
    ESP_ELFSYM_EXPORT(uam_migrate_nvs_to_file),
    ESP_ELFSYM_EXPORT(uam_add_user),
    ESP_ELFSYM_EXPORT(uam_remove_user),
    ESP_ELFSYM_EXPORT(uam_set_password),
    ESP_ELFSYM_EXPORT(uam_set_group),
    ESP_ELFSYM_EXPORT(uam_set_privileges),
    ESP_ELFSYM_EXPORT(uam_root_change_password),
    ESP_ELFSYM_EXPORT(uam_authenticate),
    ESP_ELFSYM_EXPORT(uam_token_validate),
    ESP_ELFSYM_END
};

/**
 * @brief Find symbol address by name.
 *
 * @param sym_name - Symbol name
 *
 * @return Symbol address if success or 0 if failed.
 */
uintptr_t elf_find_sym(const char *sym_name)
{
    const struct esp_elfsym *syms;

    /* libc */
    syms = g_esp_libc_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }

    /* public ESP‑IDF */
    syms = g_esp_espidf_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }

    /* proprietary ESP‑IDF */
    syms = g_esp_prop_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }

    /* extended ESP‑IDF */
    syms = g_esp_idf_ext_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }

    /* esp_uam */
    syms = g_esp_uam_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }

#ifdef CONFIG_ELF_LOADER_CUSTOMER_SYMBOLS
    extern const struct esp_elfsym g_customer_elfsyms[];
    syms = g_customer_elfsyms;
    while (syms->name) {
        if (!strcmp(syms->name, sym_name)) return (uintptr_t)syms->sym;
        syms++;
    }
#endif

    return 0; /* not found */
}