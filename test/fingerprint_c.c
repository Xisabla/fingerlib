#include <finger/fingerprint_c.h>
#include <stdlib.h>
#include <string.h>

#include <test/crunner.h>

int C_TEST_FINGERPRINT() {
    // Test data
    char* uri = "/WebGoat";
    char* method = "GET";
    char* version = "1.1";
    char* headers[14];
    headers[0] = "Host: localhost:8080";
    headers[1] = "Connection: keep-alive";
    headers[2] = "Cache-Control: max-age=0";
    headers[3] = "Upgrade-Insecure-Requests: 1";
    headers[4] = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
                 "like Gecko) Chrome/101.0.4951.67 Safari/537.36";
    headers[5] = "Accept: "
                 "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/"
                 "webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
    headers[6] = "Sec-GPC: 1";
    headers[7] = "Sec-Fetch-Site: none";
    headers[8] = "Sec-Fetch-Mode: navigate";
    headers[9] = "Sec-Fetch-User: ?1";
    headers[10] = "Sec-Fetch-Dest: document";
    headers[11] = "Accept-Encoding: gzip, deflate, br";
    headers[12] = "Accept-Language: en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7";
    headers[13] = "Cookie: JSESSIONID=CY7pJ_5MW7-s4IMlKlhpgPi467TSwS6O-4lrrGZH; "
                  "JSESSIONID=fD09zlMeWuY0Htn8gyRU9A.node0; io=YCQULPy6oHI7HkLxAAA5";
    char* payload = "";

    // Expected result
    char* expected = "0.9|1|0.8|||||GE|1|ho,co,ca-co,u-i-r,us-ag,ac,1586472b,7e369551,a602679,"
                     "206f7215,975a9022,ac-en,ac-la,ck|co:ke-al/ca-co:916a0a82/us-ag:92028000/"
                     "ac:f159e9d0/ac-en:gz,de,br/ac-la:b88ab870|||";

    const char* fp = fingerprint_c(uri, method, version, (const char**) headers, 14, payload);

    int diff = strcmp(expected, fp);

    // Do not forget
    free((char*) fp);

    return diff;
}

int C_TEST_URI_FINGERPRINT() {
    // Test data
    char* uri =
    "/www.appinf.com:88/sample/anothersubdir/just_a_test/a?example-query=a&other=value#fra";

    // Expected result
    char* expected = "1.9|5|1.0||1.4|2|0.5";


    const char* fp = uri_fingerprint_c(uri);

    int diff = strcmp(expected, fp);

    // Do not forget
    free((char*) fp);

    return diff;
}

int main() {
    CTEST_INIT();

    CTEST_RUN(C_TEST_FINGERPRINT);
    CTEST_RUN(C_TEST_URI_FINGERPRINT);

    CTEST_END();
}