extern "C" void throw_int() {
    throw 7;
}

extern "C" int cross_rust(void (*callback)()) {
    try {
        callback();
    } catch (int value) {
        return value;
    }

    return -1;
}
