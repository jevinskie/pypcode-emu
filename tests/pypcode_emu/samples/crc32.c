// Options:   --max-funcs 1 --concise
#include "csmith.h"


extern uint32_t crc32_tab[256];
extern uint32_t crc32_context;

int main (int argc, char* argv[])
{
    int print_hash_value = 0;
    if (argc == 2 && strcmp(argv[1], "1") == 0) print_hash_value = 1;
    platform_main_begin();
    crc32_gentab();
#if 1
    transparent_crc(243, "v243", print_hash_value);
    platform_main_end(crc32_context ^ 0xFFFFFFFFUL, print_hash_value);
#else
    platform_main_end(crc32_tab[1], print_hash_value);
#endif
    return 0;
}
