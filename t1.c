#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LEN 1024
#define ALPHABET_SIZE 26

static void build_tabula_recta(char table[ALPHABET_SIZE][ALPHABET_SIZE]) {
    for (int row = 0; row < ALPHABET_SIZE; row++) {
        for (int col = 0; col < ALPHABET_SIZE; col++) {
            table[row][col] = (char)('A' + ((row + col) % ALPHABET_SIZE));
        }
    }
}

static int char_to_index(char c) {
    unsigned char uc = (unsigned char)c;
    if (isalpha(uc)) {
        return toupper(uc) - 'A';
    }
    return -1;
}

/* Filtra apenas caracteres alfabeticos simples (A-Z / a-z) e converte para maiusculas */
static void normalize_alpha_upper(const char *src, char *dst, size_t max_len) {
    size_t j = 0;
    for (size_t i = 0; src[i] != '\0' && j + 1 < max_len; i++) {
        int idx = char_to_index(src[i]);
        if (idx >= 0) {
            dst[j++] = (char)('A' + idx);
        }
    }
    dst[j] = '\0';
}

static void generate_random_key(char *key, size_t len) {
    for (size_t i = 0; i < len; i++) {
        key[i] = (char)('A' + (rand() % ALPHABET_SIZE));
    }
    key[len] = '\0';
}

/* Cifragem usando a Tabula Recta: linha = chave, coluna = plaintext */
static void encrypt_vigenere(const char table[ALPHABET_SIZE][ALPHABET_SIZE],
                             const char *plaintext,
                             const char *key,
                             char *ciphertext) {
    size_t len = strlen(plaintext);
    for (size_t i = 0; i < len; i++) {
        int row = char_to_index(key[i]);
        int col = char_to_index(plaintext[i]);
        ciphertext[i] = table[row][col];
    }
    ciphertext[len] = '\0';
}

/* Decifragem usando a Tabula Recta: busca ciphertext na linha da chave -> retorna coluna */
static void decrypt_vigenere(const char table[ALPHABET_SIZE][ALPHABET_SIZE],
                             const char *ciphertext,
                             const char *key,
                             char *plaintext) {
    size_t len = strlen(ciphertext);
    for (size_t i = 0; i < len; i++) {
        int row = char_to_index(key[i]);
        char target = (char)toupper((unsigned char)ciphertext[i]);
        int found_col = 0;

        for (int col = 0; col < ALPHABET_SIZE; col++) {
            if (table[row][col] == target) {
                found_col = col;
                break;
            }
        }
        plaintext[i] = (char)('A' + found_col);
    }
    plaintext[len] = '\0';
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
    srand((unsigned int)time(NULL));

    int mode = 0;
    printf("Escolha a operacao:\n");
    printf("1 - Cifrar mensagem\n");
    printf("2 - Decifrar mensagem\n");
    printf("Opcao: ");
    if (scanf("%d", &mode) != 1) {
        fprintf(stderr, "Entrada invalida.\n");
        return 1;
    }

    int ch;
    while ((ch = getchar()) != '\n' && ch != EOF) {}

    char raw_input[MAX_LEN];
    char clean_msg[MAX_LEN];
    char raw_key[MAX_LEN];
    char clean_key[MAX_LEN];
    char output[MAX_LEN];

    if (mode == 1) {
        printf("Digite a mensagem (plaintext, letras sem acento): ");
        read_line(raw_input, sizeof(raw_input));
        normalize_alpha_upper(raw_input, clean_msg, sizeof(clean_msg));

        size_t msg_len = strlen(clean_msg);
        if (msg_len == 0) {
            fprintf(stderr, "Nenhuma letra valida informada.\n");
            return 1;
        }

        int key_opt = 0;
        printf("Deseja (1) informar uma chave ou (2) gerar chave aleatoria? ");
        if (scanf("%d", &key_opt) != 1) {
            fprintf(stderr, "Entrada invalida.\n");
            return 1;
        }
        while ((ch = getchar()) != '\n' && ch != EOF) {}

        if (key_opt == 1) {
            printf("Digite a chave (minimo %zu letras): ", msg_len);
            read_line(raw_key, sizeof(raw_key));
            normalize_alpha_upper(raw_key, clean_key, sizeof(clean_key));

            if (strlen(clean_key) < msg_len) {
                fprintf(stderr, "Chave menor que a mensagem (%zu < %zu).\n",
                        strlen(clean_key), msg_len);
                return 1;
            }
            clean_key[msg_len] = '\0';
        } else if (key_opt == 2) {
            generate_random_key(clean_key, msg_len);
        } else {
            fprintf(stderr, "Opcao de chave invalida.\n");
            return 1;
        }

        encrypt_vigenere(table, clean_msg, clean_key, output);

        printf("\n--- Resultado da Cifragem ---\n");
        printf("Plaintext : %s\n", clean_msg);
        printf("Chave     : %s\n", clean_key);
        printf("Ciphertext: %s\n", output);
    } else if (mode == 2) {
        printf("Digite o ciphertext (letras sem acento): ");
        read_line(raw_input, sizeof(raw_input));
        normalize_alpha_upper(raw_input, clean_msg, sizeof(clean_msg));

        size_t msg_len = strlen(clean_msg);
        if (msg_len == 0) {
            fprintf(stderr, "Ciphertext invalido.\n");
            return 1;
        }

        printf("Digite a chave (%zu letras): ", msg_len);
        read_line(raw_key, sizeof(raw_key));
        normalize_alpha_upper(raw_key, clean_key, sizeof(clean_key));

        if (strlen(clean_key) < msg_len) {
            fprintf(stderr, "Chave menor que o ciphertext (%zu < %zu).\n",
                    strlen(clean_key), msg_len);
            return 1;
        }
        clean_key[msg_len] = '\0';

        decrypt_vigenere(table, clean_msg, clean_key, output);

        printf("\n--- Resultado da Decifragem ---\n");
        printf("Ciphertext: %s\n", clean_msg);
        printf("Chave     : %s\n", clean_key);
        printf("Plaintext : %s\n", output);
    } else {
        fprintf(stderr, "Opcao invalida.\n");
        return 1;
    }

    return 0;
}