/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.0.0
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>
#include <test/dataset.hpp>
#include <boost/algorithm/string.hpp>

// clang-format off
#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>
// clang-format on

TEST_GROUP(Basic) {};

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

TEST(Basic, FingerprintFullPayloadInC) {
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
        std::string joinedHeaders = boost::join(headers, "\n");
        std::string payload = entry["payload"].get<std::string>();

        HTTPRequest_C req(
            const_cast<char*>(uri.c_str()),
            const_cast<char*>(method.c_str()),
            const_cast<char*>(version.c_str()),
            const_cast<char*>(joinedHeaders.c_str()),
            const_cast<char*>(payload.c_str())
        );

        auto fp = fingerprint_c(&req);

        STRCMP_EQUAL(expected.c_str(), fp);
    }
}

int main(int argc, char** argv) { return CommandLineTestRunner::RunAllTests(argc, argv); }