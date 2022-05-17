/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.2
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

TEST(Basic, Fingerprint) {
    std::vector<std::string> headers = {
        "Host: 127.0.0.1:8080",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 "
        "Firefox/100.0",
        "Accept: "
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding: gzip, deflate, br",
        "Connection: keep-alive",
        "Cookie: JSESSIONID=r_Qoq_zJ8AhdHxiMyEJB4hVOHaiMLGllXupEQNX5",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: same-origin"
    };

    HTTPRequest req("/WebGoat/start.mvc", "GET", "1.1", headers);

    auto fp = fingerprint(req);

    STRCMP_EQUAL("1.3|2|0.9|||||GE|1|ho,us-ag,ac,ac-la,ac-en,co,ck,u-i-r,975a9022,a602679,7e369551|"
                 "us-ag:717348c0/ac:6cc9e5e/ac-la:686a865e/ac-en:gz,de,br/co:ke-al|||",
                 fp.c_str());
}

TEST(Basic, FingerprintPOST) {
    std::vector<std::string> headers = {
        "Host: 127.0.0.1:8080",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 "
        "Firefox/100.0",
        "Accept: "
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding: gzip, deflate, br",
        "Content-Type: application/x-www-form-urlencoded",
        "Content-Length: 39",
        "Origin: http://127.0.0.1:8080",
        "Connection: keep-alive",
        "Referer: http://127.0.0.1:8080/WebGoat/login",
        "Cookie: JSESSIONID=hAJmPjkgr3Wz_bpXTdw1Q08DMu4daM0tuVgoI1sJ",
        "Upgrade-Insecure-Requests: 1",
        "Sec-Fetch-Dest: document",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-User: ?1"
    };

    HTTPRequest req("/WebGoat/login", "POST", "1.1", headers);

    auto fp = fingerprint(req);

    STRCMP_EQUAL("1.1|2|0.8|||||PO|1|ho,us-ag,ac,ac-la,ac-en,co-ty,co-le,or,co,re,ck,u-i-r,"
                 "975a9022,a602679,7e369551,206f7215|us-ag:717348c0/ac:6cc9e5e/ac-la:686a865e/"
                 "ac-en:gz,de,br/co-ty:ap-x-w-f-u/co:ke-al|A|3.5|1.6",
                 fp.c_str());
}

int main(int argc, char** argv) { return CommandLineTestRunner::RunAllTests(argc, argv); }