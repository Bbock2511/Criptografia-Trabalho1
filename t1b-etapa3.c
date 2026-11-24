/* etapa3.c - Quebra de Vigenere com chave de tamanho desconhecido (Kasiski + IC) */
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26
#define MAX_TEXT 65536
#define MIN_KEYSIZE 2
#define MAX_KEYSIZE 40

/* Frequencias relativas do portugues (A-Z) */
static const double PT_FREQ[ALPHABET_SIZE] = {
    0.1463, 0.0104, 0.0388, 0.0499, 0.1257, 0.0102, 0.0130, 0.0128, 0.0618,
    0.0040, 0.0002, 0.0278, 0.0474, 0.0505, 0.1073, 0.0252, 0.0120, 0.0653,
    0.0781, 0.0434, 0.0463, 0.0167, 0.0001, 0.0021, 0.0001, 0.0047
};

typedef struct {
    int keysize;
    int kasiski_hits;
    double avg_ic;
} KeySizeScore;

/* Le arquivo e extrai apenas letras A-Z em maiusculo */
static size_t load_clean_ciphertext(const char *filename, char *out, size_t max_len) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Erro ao abrir arquivo");
        return 0;
    }
    size_t len = 0;
    int ch;
    while ((ch = fgetc(fp)) != EOF && len + 1 < max_len) {
        if (isalpha((unsigned char)ch)) {
            out[len++] = (char)toupper((unsigned char)ch);
        }
    }
    out[len] = '\0';
    fclose(fp);
    return len;
}

/* Calcula o Indice de Coincidencia de uma sequencia */
static double index_of_coincidence(const char *seq, size_t n) {
    if (n < 2) return 0.0;
    int counts[ALPHABET_SIZE] = {0};
    for (size_t i = 0; i < n; i++) {
        counts[seq[i] - 'A']++;
    }
    double num = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        num += (double)counts[i] * (double)(counts[i] - 1);
    }
    return num / ((double)n * (double)(n - 1));
}

/* Calcula o IC medio das colunas transpostas para um dado keysize */
static double average_column_ic(const char *cipher, size_t len, int keysize) {
    char *col_buf = (char *)malloc((len / (size_t)keysize) + 2);
    if (!col_buf) return 0.0;

    double sum_ic = 0.0;
    for (int col = 0; col < keysize; col++) {
        size_t clen = 0;
        for (size_t i = (size_t)col; i < len; i += (size_t)keysize) {
            col_buf[clen++] = cipher[i];
        }
        sum_ic += index_of_coincidence(col_buf, clen);
    }
    free(col_buf);
    return sum_ic / (double)keysize;
}

/* Computa distancias entre substrings repetidas e fatora (Exame de Kasiski) */
static void compute_kasiski_factors(const char *cipher, size_t len, int factor_counts[MAX_KEYSIZE + 1]) {
    memset(factor_counts, 0, sizeof(int) * (MAX_KEYSIZE + 1));

    /* Testa substrings repetidas de tamanho 3 ate 8 */
    for (size_t sub_len = 3; sub_len <= 8; sub_len++) {
        if (len <= sub_len) break;
        for (size_t i = 0; i <= len - sub_len; i++) {
            for (size_t j = i + 1; j <= len - sub_len; j++) {
                if (memcmp(&cipher[i], &cipher[j], sub_len) == 0) {
                    size_t dist = j - i;
                    /* Fatora a distancia procurando divisores entre MIN_KEYSIZE e MAX_KEYSIZE */
                    for (int f = MIN_KEYSIZE; f <= MAX_KEYSIZE; f++) {
                        if (dist % (size_t)f == 0) {
                            factor_counts[f]++;
                        }
                    }
                }
            }
        }
    }
}

static int cmp_keysize(const void *a, const void *b) {
    const KeySizeScore *ka = (const KeySizeScore *)a;
    const KeySizeScore *kb = (const KeySizeScore *)b;
    /* Ordena pela contagem de fatores de Kasiski (e desempata por IC proximo do portugues) */
    if (kb->kasiski_hits != ka->kasiski_hits) {
        return kb->kasiski_hits - ka->kasiski_hits;
    }
    if (kb->avg_ic > ka->avg_ic) return 1;
    if (kb->avg_ic < ka->avg_ic) return -1;
    return 0;
}

/* Ataca um bloco transposto como cifra de 1 caractere usando MIC com o portugues */
static char solve_single_column(const char *col_text, size_t clen) {
    char best_key = 'A';
    double best_mic = -1.0;

    for (int k = 0; k < ALPHABET_SIZE; k++) {
        int counts[ALPHABET_SIZE] = {0};
        for (size_t i = 0; i < clen; i++) {
            int p = (col_text[i] - 'A' - k + ALPHABET_SIZE) % ALPHABET_SIZE;
            counts[p]++;
        }
        double mic = 0.0;
        for (int i = 0; i < ALPHABET_SIZE; i++) {
            mic += PT_FREQ[i] * ((double)counts[i] / (double)clen);
        }
        if (mic > best_mic) {
            best_mic = mic;
            best_key = (char)('A' + k);
        }
    }
    return best_key;
}

static void decrypt_vigenere(const char *cipher, size_t len, const char *key, char *plain) {
    size_t klen = strlen(key);
    for (size_t i = 0; i < len; i++) {
        int c = cipher[i] - 'A';
        int k = key[i % klen] - 'A';
        plain[i] = (char)('A' + ((c - k + ALPHABET_SIZE) % ALPHABET_SIZE));
    }
    plain[len] = '\0';
}

int main(int argc, char **argv) {
    const char *filename = (argc >= 2) ? argv[1] : "Vigenere ciphertext.txt";

    static char cipher[MAX_TEXT];
    static char plain[MAX_TEXT];
    size_t len = load_clean_ciphertext(filename, cipher, sizeof(cipher));
    if (len == 0) {
        fprintf(stderr, "Uso: %s <arquivo_ciphertext.txt>\n", argv[0]);
        return 1;
    }

    printf("Arquivo carregado: %s (%zu caracteres alfabeticos)\n\n", filename, len);

    /* 1. Exame de Kasiski + IC medio por tamanho de chave */
    int factor_counts[MAX_KEYSIZE + 1];
    compute_kasiski_factors(cipher, len, factor_counts);

    KeySizeScore candidates[MAX_KEYSIZE - MIN_KEYSIZE + 1];
    int total_cands = 0;
    for (int ks = MIN_KEYSIZE; ks <= MAX_KEYSIZE; ks++) {
        candidates[total_cands].keysize = ks;
        candidates[total_cands].kasiski_hits = factor_counts[ks];
        candidates[total_cands].avg_ic = average_column_ic(cipher, len, ks);
        total_cands++;
    }

    qsort(candidates, (size_t)total_cands, sizeof(KeySizeScore), cmp_keysize);

    printf("=== TOP 5 TAMANHOS DE CHAVE ESTIMADOS (KASISKI + IC) ===\n");
    for (int i = 0; i < 5 && i < total_cands; i++) {
        printf("#%d | KEYSIZE = %2d | Fatores Kasiski = %4d | IC medio = %.5f\n",
               i + 1, candidates[i].keysize, candidates[i].kasiski_hits, candidates[i].avg_ic);
    }

    /* Escolhe entre os top candidatos aquele com IC mais proximo de ~0.0745 (portugues)
       para evitar multiplos (ex.: KEYSIZE=10 quando a chave real e 5) */
    int best_keysize = candidates[0].keysize;
    for (int i = 0; i < 5 && i < total_cands; i++) {
        if (candidates[i].avg_ic > 0.062) {
            best_keysize = candidates[i].keysize;
            break;
        }
    }

    printf("\nKEYSIZE selecionado: %d\n", best_keysize);

    /* 2. Transposicao e ataque individual em cada bloco */
    char key[MAX_KEYSIZE + 1];
    char *col_buf = (char *)malloc((len / (size_t)best_keysize) + 2);
    if (!col_buf) return 1;

    for (int col = 0; col < best_keysize; col++) {
        size_t clen = 0;
        for (size_t i = (size_t)col; i < len; i += (size_t)best_keysize) {
            col_buf[clen++] = cipher[i];
        }
        key[col] = solve_single_column(col_buf, clen);
    }
    key[best_keysize] = '\0';
    free(col_buf);

    /* 3. Decifragem com a chave reconstruida */
    decrypt_vigenere(cipher, len, key, plain);

    printf("Chave encontrada : %s\n", key);
    printf("\n=== TEXTO DECIFRADO ===\n%s\n", plain);

    return 0;
}