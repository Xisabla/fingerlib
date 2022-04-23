/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.1
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>
#include <test/dataset.hpp>

// clang-format off
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
// clang-format on

TEST_GROUP(Basic) {};

TEST(Basic, URIFingerprintExt) {
    auto set = dataset_use("test/data/dataset_basic.json", { "sets", "with_extension" });

    for (auto& entry: set) {
        if (!dataset_contains(entry, { "uri", "fingerprint" })) {
            continue;
        }

        std::string expect = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();

        auto fp = uri_fingerprint(uri);

        STRCMP_EQUAL(expect.c_str(), fp.c_str());
    }
}

TEST(Basic, URIFingerprint) {
    auto set = dataset_use("test/data/dataset_basic.json", { "sets", "without_extension" });

    for (auto& entry: set) {
        if (!dataset_contains(entry, { "uri", "fingerprint" })) {
            continue;
        }

        std::string expect = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();

        auto fp = uri_fingerprint(uri);

        STRCMP_EQUAL(expect.c_str(), fp.c_str());
    }
}

int main(int argc, char** argv) { CommandLineTestRunner::RunAllTests(argc, argv); }