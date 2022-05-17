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

// TEST(Basic, URIFingerprint) {
//     HTTPRequest req(
//     "/www.appinf.com:88/sample/anothersubdir/just_a_test/a?example-query=a&other=value#frag",
//     "GET", "");

//     auto fp = uri_fingerprint(req.uri);

//     STRCMP_EQUAL("1.9|5|1.0||1.4|2|0.5", fp.c_str());
// }

// TEST(Basic, URIFingerprintExt) {
//     HTTPRequest req("/mutillidae/index.php?page=redirectandlog.php&forwardurl=http://www.evil.com",
//                     "GET", "");

//     auto fp = uri_fingerprint(req.uri);

//     STRCMP_EQUAL("1.9|2|1.0|php|1.7|2|1.3", fp.c_str());
// }

TEST(Basic, HeaderFingerprint) {
    std::vector<std::string> headers = {
        "Host: 127.0.0.1:8080",
        "Connection: keep-alive",
        "Pragma: no-cache",
        "Cache-Control: no-cache",
        "Upgrade-Insecure-Requests: 1",
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-GPC: 1",
        "Sec-Fetch-Site: same-origin",
        "Sec-Fetch-Mode: navigate",
        "Sec-Fetch-User: ?1",
        "Sec-Fetch-Dest: document",
        "Referer: http://127.0.0.1:8080/WebGoat/login",
        "Accept-Encoding: gzip, deflate, br",
        "Accept-Language: en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7",
        "Cookie: JSESSIONID=XgezLtp8tl-G1qOd_avkcrhP7f5958rHruN196SV"
    };

    HTTPRequest req(
        "/WebGoat/registration", 
        "GET", 
        "1.1",
        headers);

    auto fp = fingerprint(req);

    STRCMP_EQUAL("1.3|2|1.0|||||GE|1|ho,co,pr,ca-co,u-i-r,us-ag,ac,1586472b,7e369551,a602679,206f7215,975a9022,re,ac-en,ac-la,ck|co:ke-al/ca-co:nc/us-ag:92028000/ac:f159e9d0/ac-en:gz,de,br/ac-la:b88ab870|||", fp.c_str());
}

int main(int argc, char** argv) { CommandLineTestRunner::RunAllTests(argc, argv); }