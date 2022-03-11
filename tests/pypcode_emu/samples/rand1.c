// Options:   --max-funcs 1 --concise
#include "csmith.h"

static long __undefined;

static volatile int32_t g_3[4][1][4]  = {{{0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L}},
                                        {{0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L}},
                                        {{0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L}},
                                        {{0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L, 0x60B4FFB8L}}};
static volatile int32_t *volatile g_2 = &g_3[0][0][2];
static uint8_t g_11                   = 0xCAL;
static int32_t g_13[2]                = {1L, 1L};

static int16_t func_1(void);

static int16_t func_1(void) {
    int32_t *l_8  = (void *)0;
    int32_t l_9   = 9L;
    uint8_t *l_10 = &g_11;
    int32_t *l_12 = &g_13[1];
    g_2           = g_2;
    (*l_12) ^= ((safe_rshift_func_uint64_t_u_u(
                    g_3[2][0][0], (safe_mod_func_int16_t_s_s((l_8 == (void *)0), 0xD9B9L)))) ||
                ((*l_10) = l_9));
    return g_3[3][0][1];
}

int main(int argc, char *argv[]) {
    int i, j, k;
    int print_hash_value = 0;
    if (argc == 2 && strcmp(argv[1], "1") == 0)
        print_hash_value = 1;
    platform_main_begin();
    crc32_gentab();
    func_1();
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 1; j++) {
            for (k = 0; k < 4; k++) {
                transparent_crc(g_3[i][j][k], "g_3[i][j][k]", print_hash_value);
                if (print_hash_value)
                    printf("index = [%d][%d][%d]\n", i, j, k);
            }
        }
    }
    transparent_crc(g_11, "g_11", print_hash_value);
    for (i = 0; i < 2; i++) {
        transparent_crc(g_13[i], "g_13[i]", print_hash_value);
        if (print_hash_value)
            printf("index = [%d]\n", i);
    }
    platform_main_end(crc32_context ^ 0xFFFFFFFFUL, print_hash_value);
    return 0;
}
