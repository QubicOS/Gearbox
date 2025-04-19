#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hw_uart_io.h"

void app_main(void)
{
    // Инициализация стандартного вывода (UART или USB CDC-ACM)
    io_init();

    // Вывод тестового сообщения
    const char *test_msg = "Starting Gearbox\n";
    io_write(test_msg, strlen(test_msg));

    // Бесконечный цикл с выводом сообщения каждую секунду
    while (1) {
        const char *loop_msg = "Hello, Gearbox\n";
        io_write(loop_msg, strlen(loop_msg));
        vTaskDelay(pdMS_TO_TICKS(1000)); // Задержка 1 секунда
    }
}
