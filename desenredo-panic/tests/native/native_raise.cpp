extern "C" void catch_foreign(void (*callback)()) {
    try {
        callback();
    } catch (...) {
    }
}
