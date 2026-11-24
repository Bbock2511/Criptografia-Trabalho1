/* etapa2.c - Forca bruta de chave de 1 caractere com Top 5 em 2 metodos */
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26

/* Frequencias relativas das letras na lingua portuguesa (A-Z) */
static const double PT_FREQ[ALPHABET_SIZE] = {
    0.1463, 0.0104, 0.0388, 0.0499, 0.1257, 0.0102, 0.0130, 0.0128, 0.0618,
    0.0040, 0.0002, 0.0278, 0.0474, 0.0505, 0.1073, 0.0252, 0.0120, 0.0653,
    0.0781, 0.0434, 0.0463, 0.0167, 0.0001, 0.0021, 0.0001, 0.0047
};

typedef struct {
    char key;
    double mic_score;   /* Metodo 1: Indice de Coincidencia Mutuo (maior = melhor) */
    double chi2_val;    /* Metodo 2: Estatistica Qui-Quadrado (menor = melhor) */
    double chi2_score;  /* Metodo 2 normalizado: 1 / (1 + chi2/N) (maior = melhor) */
    char plaintext[1024];
} Candidate;

static void decrypt_single_char(const char *cipher, char key, char *plain) {
    int shift = key - 'A';
    size_t len = strlen(cipher);
    for (size_t i = 0; i < len; i++) {
        int c = cipher[i] - 'A';
        plain[i] = (char)('A' + ((c - shift + ALPHABET_SIZE) % ALPHABET_SIZE));
    }
    plain[len] = '\0';
}

/* Metodo 1: Indice de Coincidencia Mutuo (MIC) com o portugues */
static double compute_mutual_ic(const char *text) {
    int counts[ALPHABET_SIZE] = {0};
    size_t n = strlen(text);
    for (size_t i = 0; i < n; i++) {
        counts[text[i] - 'A']++;
    }
    double mic = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        mic += PT_FREQ[i] * ((double)counts[i] / (double)n);
    }
    return mic;
}

/* Metodo 2: Indice de aderencia via Qui-Quadrado (Chi-Squared) */
static double compute_chi_squared(const char *text) {
    int counts[ALPHABET_SIZE] = {0};
    size_t n = strlen(text);
    for (size_t i = 0; i < n; i++) {
        counts[text[i] - 'A']++;
    }
    double chi2 = 0.0;
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        double expected = (double)n * PT_FREQ[i];
        double diff = (double)counts[i] - expected;
        chi2 += (diff * diff) / expected;
    }
    return chi2;
}

static int cmp_by_mic_desc(const void *a, const void *b) {
    const Candidate *ca = (const Candidate *)a;
    const Candidate *cb = (const Candidate *)b;
    if (cb->mic_score > ca->mic_score) return 1;
    if (cb->mic_score < ca->mic_score) return -1;
    return 0;
}

static int cmp_by_chi2_asc(const void *a, const void *b) {
    const Candidate *ca = (const Candidate *)a;
    const Candidate *cb = (const Candidate *)b;
    if (ca->chi2_val > cb->chi2_val) return 1;
    if (ca->chi2_val < cb->chi2_val) return -1;
    return 0;
}

int main(void) {
    const char *ciphertext = "MXOXYBKPSLZBZLKPBDRFRABZFCOXOXJBKPXDBJ";
    Candidate list[ALPHABET_SIZE];
    size_t n = strlen(ciphertext);

    for (int k = 0; k < ALPHABET_SIZE; k++) {
        list[k].key = (char)('A' + k);
        decrypt_single_char(ciphertext, list[k].key, list[k].plaintext);
        list[k].mic_score = compute_mutual_ic(list[k].plaintext);
        list[k].chi2_val = compute_chi_squared(list[k].plaintext);
        list[k].chi2_score = 1.0 / (1.0 + (list[k].chi2_val / (double)n));
    }

    printf("=== TOP 5 - METODO 1: INDICE DE COINCIDENCIA MUTUO (MIC) ===\n");
    qsort(list, ALPHABET_SIZE, sizeof(Candidate), cmp_by_mic_desc);
    for (int i = 0; i < 5; i++) {
        printf("#%d | Chave: %c | MIC: %.5f | Texto: %s\n",
               i + 1, list[i].key, list[i].mic_score, list[i].plaintext);
    }

    printf("\n=== TOP 5 - METODO 2: INDICE DE ADERENCIA QUI-QUADRADO ===\n");
    qsort(list, ALPHABET_SIZE, sizeof(Candidate), cmp_by_chi2_asc);
    for (int i = 0; i < 5; i++) {
        printf("#%d | Chave: %c | Chi2: %7.2f (Score: %.5f) | Texto: %s\n",
               i + 1, list[i].key, list[i].chi2_val, list[i].chi2_score, list[i].plaintext);
    }

    return 0;
}