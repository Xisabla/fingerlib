#include <finger/fingerprint.hpp>
#include <finger/utils.hpp>
#include <iostream>

int main() {
    hello();

    try {
        throw BadReportmodeVariable();
    } catch(BadReportmodeVariable &e) {
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
