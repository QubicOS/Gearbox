/*
 * SPDX-FileCopyrightText: 2023 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>

#define MAX_ARGS 10

// Структура для представления команды
typedef struct {
    const char *name;           // Имя команды
    int (*func)(int argc, char *argv[]); // Указатель на функцию обработки
} command_t;

// Прототипы функций команд
int cmd_echo(int argc, char *argv[]);
int cmd_pwd(int argc, char *argv[]);
int cmd_ls(int argc, char *argv[]);
int cmd_cd(int argc, char *argv[]);
int cmd_exit(int argc, char *argv[]);
int cmd_help(int argc, char *argv[]);

// Массив поддерживаемых команд
command_t commands[] = {
    {"echo", cmd_echo},
    {"pwd", cmd_pwd},
    {"ls", cmd_ls},
    {"cd", cmd_cd},
    {"exit", cmd_exit},
    {"help", cmd_help},
    {NULL, NULL} // Метка конца списка
};

// Функция для парсинга ввода пользователя
int parse_input(char *input, char *argv[]) {
    int argc = 0;
    char *token = strtok(input, " \n");
    while (token != NULL && argc < MAX_ARGS) {
        argv[argc++] = token;
        token = strtok(NULL, " \n");
    }
    return argc;
}

// Реализация команды echo
int cmd_echo(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        printf("%s ", argv[i]);
    }
    printf("\n");
    return 0;
}

// Реализация команды pwd
int cmd_pwd(int argc, char *argv[]) {
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("%s\n", cwd);
    } else {
        perror("getcwd");
    }
    return 0;
}

// Реализация команды ls
int cmd_ls(int argc, char *argv[]) {
    DIR *dir;
    struct dirent *entry;
    char *path = (argc > 1) ? argv[1] : "."; // По умолчанию текущий каталог

    if ((dir = opendir(path)) == NULL) {
        perror("opendir");
        return 1;
    }

    while ((entry = readdir(dir)) != NULL) {
        printf("%s\n", entry->d_name);
    }

    closedir(dir);
    return 0;
}

// Реализация команды cd
int cmd_cd(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "cd: missing argument\n");
        return 1;
    }

    if (chdir(argv[1]) != 0) {
        perror("chdir");
        return 1;
    }

    return 0;
}

// Реализация команды exit
int cmd_exit(int argc, char *argv[]) {
    exit(0);
}

// Реализация команды help
int cmd_help(int argc, char *argv[]) {
    printf("Available commands:\n");
    for (command_t *cmd = commands; cmd->name != NULL; cmd++) {
        printf("  %s\n", cmd->name);
    }
    return 0;
}

// Основная функция
int main() {
    char input[1024];         // Буфер для ввода пользователя
    char *argv[MAX_ARGS + 1]; // Массив аргументов
    int argc;                 // Количество аргументов

    printf(
        "Welcome to plush — the plushest little shell in the system.\n"
        "\n"
        "    Gearbox OS for ESP32 // minimal, modular, embedded.\n"
        "    Type `help` to get cozy.\n"
        "    Type `exit` to drift away.\n"
        "\n"
        "Run light. Stay plush.\n\n"
    );


    while (1) {
        printf("plush $: "); // Вывод приглашения
        if (fgets(input, sizeof(input), stdin) == NULL) {
            printf("fgets() failed\n");
            break; // Выход при ошибке ввода или EOF
        }

        argc = parse_input(input, argv);
        if (argc == 0) {
            continue; // Пропуск пустого ввода
        }

        int found = 0;
        // Поиск команды в массиве
        for (command_t *cmd = commands; cmd->name != NULL; cmd++) {
            if (strcmp(argv[0], cmd->name) == 0) {
                cmd->func(argc, argv); // Выполнение команды
                found = 1;
                break;
            }
        }

        if (!found) {
            printf("Command not found: %s\n", argv[0]);
        }
    }

    return 0;
}