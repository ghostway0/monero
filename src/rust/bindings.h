#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct FFIScalar {
    uint64_t arr[4];
};

extern "C" {

void librustmonero_mul(const FFIScalar *s1, const FFIScalar *s2, FFIScalar *result);

} // extern "C"
