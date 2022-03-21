int liveness_test(volatile int *array, int n) {
    int a = array[0];
    ++array[0];
    array[0] += n;
    int b = array[0];

    array[4] = array[0];
    array[4] = array[8];
    array[4] = array[12];

    return a + b + array[4];
}

int main(int argc, const char **argv) {
    (void)argv;
    volatile int array[16];
    for (int i = 0; i < sizeof(array) / sizeof(array[0]); ++i) {
        array[i] = 0;
    }
    return liveness_test(array, argc);
}
