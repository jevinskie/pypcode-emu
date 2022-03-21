int fact(int n) {
    int res = 1;
    while (n)
        res *= n--;
    return res;
}

int main(int argc, const char **argv) {
    (void)argv;
    return fact(argc);
}
