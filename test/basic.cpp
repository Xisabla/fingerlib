/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.0
 * @date 2022-03-03
 */
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
