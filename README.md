# fingerlib

[![Linux build](https://github.com/Xisabla/fingerlib/actions/workflows/build-and-test.yaml/badge.svg)](https://github.com/Xisabla/fingerlib/actions/workflows/build-and-test.yaml)

HTTP Fingerprint generation and distance computation library in C++

## Requirements

- [`faup`](https://github.com/stricaud/faup)
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

## Dataset

### Run server

We use [OWASP webgoat](https://owasp.org/www-project-webgoat/) as test server to feed our dataset.

The custom docker image also runs `tshark` in background to capture requests

First build the docker image:

```bash
cd server
docker build . -t fingerlib-server
```

Then run it:

```bash
docker run -p 8080:8080 -v "$(pwd)/out:/out" fingerlib-server
```

OWASP Goat server will be running on http://127.0.0.1:8080/WebGoat/, pcap files will be available under `out` directory.

If you need more specifics captures, feel fire to run `docker exec` to enter the running container, write your output files to `/out` to get them the mounted volume.
