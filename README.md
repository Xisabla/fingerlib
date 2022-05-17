# fingerlib

[![Linux build](https://github.com/Xisabla/fingerlib/actions/workflows/build-and-test.yaml/badge.svg)](https://github.com/Xisabla/fingerlib/actions/workflows/build-and-test.yaml)

HTTP Fingerprint generation and distance computation library in C++

## Requirements

- [`faup`](https://github.com/stricaud/faup)
- [`libboost`](https://www.boost.org/) >= **1.71**
- [`clang-format`](https://clang.llvm.org/docs/ClangFormat.html) & [`clang-tidy`](https://clang.llvm.org/extra/clang-tidy/) for code formatting
- [`cpputest`](https://cpputest.github.io/) as test framework >= **3.8**

## Getting started

### Building the library

```bash
make
```

The library should be located in `out/` as `out/fingerlib.so`

### Using the library

```cpp
#include "include/finger/fingerprint.hpp"

int main() {
    // Computes and print the fingerprint
    std::cout << fingerprint({ ... }) << std::endl;
}
```

## Dataset

### Run server

We use [OWASP webgoat](https://owasp.org/www-project-webgoat/) as test server to feed our dataset.

The custom docker image also runs `tshark` in background to capture requests

First build the docker image:

```bash
cd server
docker build . -t fingerlib/server
```

Then run it:

```bash
docker run -it -p 8080:8080 -v "$(pwd)/out:/out" fingerlib/server
```

OWASP Goat server will be running on http://127.0.0.1:8080/WebGoat/, pcap files will be available under `out` directory.

If you need more specifics captures, feel fire to run `docker exec` to enter the running container, write your output files to `/out` to get them the mounted volume, such as:

```bash
docker exec -u root -it <container name> bash
$ chown -R root:root /out  # fix possible right issues
$ tshark -w /out/pcap-oneshot.pcap -i eth0
```

### Compute fingerprints

**Once the capture is finished (container must be stopped)**, you can use the script `script/pcap_to_json.py` to compute the fingerprints from your pcap.

```bash
script/pcap_to_json.py server/out/capture.pcap server/fingerprints.json
```

It will keep trace of your the original request and the fingerprint computed by `hfinger`

This data will be used to forge datasets or as fingerlib test data

Example output:

```json
[[{
  "raw_request": "Layer HTTP:\n\tExpert Info (Chat/Sequence): GET /WebGoat/login HTTP/1.1\\r\\n\n\tGET /WebGoat/login HTTP/1.1\\r\\n\n\tSeverity level: Chat\n\tGroup: Sequence\n\tRequest Method: GET\n\tRequest URI: /WebGoat/login\n\tRequest Version: HTTP/1.1\n\tHost: localhost:8080\\r\\n\n\tConnection: keep-alive\\r\\n\n\tCache-Control: no-cache\\r\\n\n\tUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36\\r\\n\n\tAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9\\r\\n\n\tReferer: http://localhost:8080/WebGoat/start.mvc\\r\\n\n\tAccept-Encoding: gzip, deflate, br\\r\\n\n\tAccept-Language: en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7\\r\\n\n\tCookie: JSESSIONID=TsIZ1CadVt9B9xXNPHgGDT2gUlIws25n7efcPx2q; JSESSIONID=fD09zlMeWuY0Htn8gyRU9A.node0; io=YCQULPy6oHI7HkLxAAA5\\r\\n\n\tCookie pair: JSESSIONID=TsIZ1CadVt9B9xXNPHgGDT2gUlIws25n7efcPx2q\n\tFull request URI: http://localhost:8080/WebGoat/login\n\tHTTP request 1/1\n\tPragma: no-cache\\r\\n\n\tUpgrade-Insecure-Requests: 1\\r\\n\n\tSec-GPC: 1\\r\\n\n\tSec-Fetch-Site: same-origin\\r\\n\n\tSec-Fetch-Mode: navigate\\r\\n\n\tSec-Fetch-User: ?1\\r\\n\n\tSec-Fetch-Dest: document\\r\\n\n\tCookie pair: JSESSIONID=fD09zlMeWuY0Htn8gyRU9A.node0\n\tCookie pair: io=YCQULPy6oHI7HkLxAAA5\n",
  "request": {
    "_ws.expert": "Expert Info (Chat/Sequence): GET /WebGoat/login HTTP/1.1\\r\\n",
    "http.chat": "GET /WebGoat/login HTTP/1.1\\r\\n",
    "_ws.expert.message": "GET /WebGoat/login HTTP/1.1\\r\\n",
    "_ws.expert.severity": "2097152",
    "_ws.expert.group": "33554432",
    "http.request.method": "GET",
    "http.request.uri": "/WebGoat/login",
    "http.request.version": "HTTP/1.1",
    "http.host": "localhost:8080",
    "http.request.line": "Host: localhost:8080\\xd\\xa",
    "http.connection": "keep-alive",
    "http.cache_control": "no-cache",
    "http.user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.67 Safari/537.36",
    "http.accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "http.referer": "http://localhost:8080/WebGoat/start.mvc",
    "http.accept_encoding": "gzip, deflate, br",
    "http.accept_language": "en-US,en;q=0.9,fr;q=0.8,fr-FR;q=0.7",
    "http.cookie": "JSESSIONID=TsIZ1CadVt9B9xXNPHgGDT2gUlIws25n7efcPx2q; JSESSIONID=fD09zlMeWuY0Htn8gyRU9A.node0; io=YCQULPy6oHI7HkLxAAA5",
    "http.cookie_pair": "JSESSIONID=TsIZ1CadVt9B9xXNPHgGDT2gUlIws25n7efcPx2q",
    "http.request.full_uri": "http://localhost:8080/WebGoat/login",
    "http.request": "1",
    "http.request_number": "1"
  },
  "fingerprint": "1.1|2|0.8|||||GE|1|ho,co,pr,ca-co,u-i-r,us-ag,ac,1586472b,7e369551,a602679,206f7215,975a9022,re,ac-en,ac-la,ck|co:ke-al/ca-co:nc/us-ag:92028000/ac:f159e9d0/ac-en:gz,de,br/ac-la:b88ab870|||"
}]
```
