#include <typeinfo>

extern "C" std::type_info* int_type_info() {
    return const_cast<std::type_info*>(&typeid(int));
}

extern "C" int catch_from_rust(void (*callback)()) {
    try {
        callback();
    } catch (int value) {
        return value;
    } catch (...) {
        return -1;
    }

    return -2;
}
