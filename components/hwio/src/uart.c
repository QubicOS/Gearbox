#include <stdio.h>      
#include <string.h>

#include "driver/uart.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
   

void io_init(void)
{
    // Настройки из sdkconfig
    uart_port_t port = (uart_port_t)CONFIG_io_UART_PORT;
    int baud   = CONFIG_io_UART_BAUD_RATE;
    int buf_sz = CONFIG_io_UART_BUF_SIZE;

    // Конфиг UART
    uart_config_t cfg = {
        .baud_rate = baud,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE
    };

    // Устанавливаем драйвер и параметры
    uart_driver_install(port, buf_sz * 2, buf_sz * 2, 0, NULL, 0);
    uart_param_config(port, &cfg);
    uart_set_pin(port,
                 UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE,
                 UART_PIN_NO_CHANGE);
}

int io_read(char *buf, int len)
{
    // Чтение с таймаутом 100 мс
    return uart_read_bytes((uart_port_t)CONFIG_io_UART_PORT,
                           (uint8_t*)buf, len,
                           pdMS_TO_TICKS(100));
}

int io_write(const char *buf, int len)
{
    // Запись и возврат числа байт
    return uart_write_bytes((uart_port_t)CONFIG_io_UART_PORT,
                            buf, len);
}
