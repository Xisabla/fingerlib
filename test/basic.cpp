/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.1
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>

// clang-format off
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
// clang-format on

TEST_GROUP(Basic) {};

TEST(Basic, URIFingerprint) {
    HTTPRequest req(
    "/www.appinf.com:88/sample/anothersubdir/just_a_test/a?example-query=a&other=value#frag",
    "GET");

    auto fp = uri_fingerprint(req.uri);

    STRCMP_EQUAL("1.9|5|1.0||1.4|2|0.5", fp.c_str());
}

TEST(Basic, URIFingerprintExt) {
    HTTPRequest req("/mutillidae/index.php?page=redirectandlog.php&forwardurl=http://www.evil.com",
                    "GET");

    auto fp = uri_fingerprint(req.uri);

    STRCMP_EQUAL("1.9|2|1.0|php|1.7|2|1.3", fp.c_str());
}

int main(int argc, char** argv) { CommandLineTestRunner::RunAllTests(argc, argv); }