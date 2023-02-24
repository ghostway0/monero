#include "rust/bindings.h"

int main() {
  FFIScalar s1{};
  FFIScalar s2{};
  FFIScalar result{};
  librustmonero_mul(&s1, &s2, &result);

  // librustmonero_display(&s1);
  // librustmonero_display(&s2);
  // librustmonero_display(&result);

  return 0;
}
