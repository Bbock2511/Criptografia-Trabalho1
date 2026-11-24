/* etapa1.c - Vigenere com chave de 1 ou mais caracteres */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LEN 4096
#define ALPHABET_SIZE 26

static void build_tabula_recta(char table[ALPHABET_SIZE][ALPHABET_SIZE]) {
    for (int r = 0; r < ALPHABET_SIZE; r++) {
        for (int c = 0; c < ALPHABET_SIZE; c++) {
            table[r][c] = (char)('A' + ((r + c) % ALPHABET_SIZE));
        }
    }
}

static void normalize_alpha_upper(const char *src, char *dst, size_t max_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < max_len; i++) {
        unsigned char uc = (unsigned char)src[i];
        if (isalpha(uc)) {
            dst[j++] = (char)toupper(uc);
        }
    }
    dst[j] = '\0';
}

/* Suporta chave de qualquer tamanho >= 1 (ex.: chave de 1 caractere) */
static void vigenere_cipher(const char table[ALPHABET_SIZE][ALPHABET_SIZE],
                            const char *input,
                            const char *key,
                            char *output,
                            int decrypt) {
    size_t len = strlen(input);
    size_t klen = strlen(key);

    for (size_t i = 0; i < len; i++) {
        int row = key[i % klen] - 'A';
        if (!decrypt) {
            int col = input[i] - 'A';
            output[i] = table[row][col];
        } else {
            char target = input[i];
            int found_col = 0;
            for (int col = 0; col < ALPHABET_SIZE; col++) {
                if (table[row][col] == target) {
                    found_col = col;
                    break;
                }
            }
            output[i] = (char)('A' + found_col);
        }
    }
    output[len] = '\0';
}

static void read_line(char *buf, size_t size) {
    if (fgets(buf, (int)size, stdin) != NULL) {
        buf[strcspn(buf, "\r\n")] = '\0';
    } else {
        buf[0] = '\0';
    }
}

int main(void) {
    char table[ALPHABET_SIZE][ALPHABET_SIZE];
    build_tabula_recta(table);

    int mode = 0;
    printf("1 - Cifrar\n2 - Decifrar\nOpcao: ");
    if (scanf("%d", &mode) != 1 || (mode != 1 && mode != 2)) {
        fprintf(stderr, "Opcao invalida.\n");
        return 1;
    }
    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    char raw_msg[MAX_LEN], msg[MAX_LEN];
    char raw_key[MAX_LEN], key[MAX_LEN];
    char out[MAX_LEN];

    printf("Mensagem: ");
    read_line(raw_msg, sizeof(raw_msg));
    normalize_alpha_upper(raw_msg, msg, sizeof(msg));

    printf("Chave (1 ou mais letras): ");
    read_line(raw_key, sizeof(raw_key));
    normalize_alpha_upper(raw_key, key, sizeof(key));

    if (strlen(msg) == 0 || strlen(key) == 0) {
        fprintf(stderr, "Mensagem ou chave vazia.\n");
        return 1;
    }

    vigenere_cipher(table, msg, key, out, mode == 2);
    printf("Resultado: %s\n", out);
    return 0;
}