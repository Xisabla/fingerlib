# fingerlib

HTTP Fingerprint generation and distance computation library in C++

## Requirements

- [`POCO C++`](https://pocoproject.org/) >= **1.11**
- [`libboost`](https://www.boost.org/) >= **1.71**
- [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html) & [`clang-tidy`](https://clang.llvm.org/extra/clang-tidy/) for code formatting
- [`cpputest`](https://cpputest.github.io/) as test framework >= **3.8**

## Getting started

### Building the library

```bash
make
```

The library should be located in `out/` as `out/fingerlib.so`

### Using the library

```cpp
#include "include/finger/fingerprint.hpp"

int main() {
    // Computes and print the fingerprint
    std::cout << fingerprint({ ... }) << std::endl;
}
```
