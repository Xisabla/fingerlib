/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.0
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>

// clang-format off
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
// clang-format on

TEST_GROUP(Basic) {};

TEST(Basic, EmptyFingerprint) {
    HTTPRequest req("http://hello.world", "GET");

    auto fp = uri_fingerprint(req.uri);

    STRCMP_EQUAL(fp.c_str(), "");
}

int main(int argc, char** argv) { CommandLineTestRunner::RunAllTests(argc, argv); }