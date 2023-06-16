/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.0.0
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>
#include <finger/fingerprint_c.h>
#include <test/dataset.hpp>
#include <cstdlib>

// clang-format off
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
// clang-format on

TEST_GROUP(Basic) {};
TEST_GROUP(C) {};

TEST(Basic, FingerprintURINoext) {
    auto set = dataset_use("test/data/dataset_basic.json", { "sets", "uri-noext" });

    for (auto& entry: set) {
        if (!dataset_contains(entry, { "uri", "fingerprint" })) {
            continue;
        }

        std::string expected = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();

        auto fp = uri_fingerprint(uri);

        STRCMP_EQUAL(expected.c_str(), fp.c_str());
    }
}

TEST(Basic, FingerprintURIExt) {
    auto set = dataset_use("test/data/dataset_basic.json", { "sets", "uri-ext" });

    for (auto& entry: set) {
        if (!dataset_contains(entry, { "uri", "fingerprint" })) {
            continue;
        }

        std::string expected = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();

        auto fp = uri_fingerprint(uri);

        STRCMP_EQUAL(expected.c_str(), fp.c_str());
    }
}

TEST(Basic, FingerprintFullNopayload) {
    auto set = dataset_use("test/data/dataset_basic.json", { "sets", "full-nopayload" });

    for (auto& entry: set) {
        if (!dataset_contains(entry, { "uri", "method", "version", "headers", "fingerprint" })) {
            continue;
        }

        std::string expected = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();
        std::string method = entry["method"].get<std::string>();
        std::string version = entry["version"].get<std::string>();
        std::vector<std::string> headers = entry["headers"].get<std::vector<std::string>>();

        HTTPRequest req(uri, method, version, headers);

        auto fp = fingerprint(req);

        STRCMP_EQUAL(expected.c_str(), fp.c_str());
    }
}

TEST(Basic, FingerprintFullPayload) {
    auto set = dataset_use("test/data/dataset_full.json", { "sets", "full" });

    for (auto& entry: set) {
        if (!dataset_contains(
            entry, { "uri", "method", "version", "headers", "payload", "fingerprint" })) {
            continue;
        }

        std::string expected = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();
        std::string method = entry["method"].get<std::string>();
        std::string version = entry["version"].get<std::string>();
        std::vector<std::string> headers = entry["headers"].get<std::vector<std::string>>();
        std::string payload = entry["payload"].get<std::string>();

        HTTPRequest req(uri, method, version, headers, payload);

        auto fp = fingerprint(req);

        STRCMP_EQUAL(expected.c_str(), fp.c_str());
    }
}

TEST(C, FingerprintFullPayload) {
    auto set = dataset_use("test/data/dataset_full.json", { "sets", "full" });

    for (auto& entry: set) {
        if (!dataset_contains(
            entry, { "uri", "method", "version", "headers", "payload", "fingerprint" })) {
            continue;
        }

        std::string expected = entry["fingerprint"].get<std::string>();
        std::string uri = entry["uri"].get<std::string>();
        std::string method = entry["method"].get<std::string>();
        std::string version = entry["version"].get<std::string>();
        std::vector<std::string> headers = entry["headers"].get<std::vector<std::string>>();
        std::string payload = entry["payload"].get<std::string>();

        size_t headers_count;
        char* headers_c[99];

        for(headers_count = 0; headers_count < headers.size(); headers_count++) {
            headers_c[headers_count] = (char*) headers[headers_count].c_str();
        }

        const char* fp = fingerprint_c(uri.c_str(), method.c_str(), version.c_str(), (const char**) headers_c, headers_count, payload.c_str());

        STRCMP_EQUAL(expected.c_str(), fp);

        free((char*)fp);
    }
}

int main(int argc, char** argv) { return CommandLineTestRunner::RunAllTests(argc, argv); }