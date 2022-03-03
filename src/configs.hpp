#ifndef INCLUDE_CONFIGS_HPP
#define INCLUDE_CONFIGS_HPP

#include <map>
#include <vector>
#include <string>

static const std::map<std::string, std::string> AEVAL = {
    {"gzip", "gz"},
    {"deflate", "de"},
    {"identity", "id"},
    {"none", "no"},
    {"sdch", "sd"},
    {"br", "br"},
    {"compress", "co"},
    {"*", "as"},
    {"chunked", "ch"},
};

static const std::map<std::string, std::string> CONNVAL = {
    {"Keep-Alive", "Ke-Al"},
    {"keep-alive", "ke-al"},
    {"close", "cl"},
    {"Close", "Cl"},
    {"Upgrade", "Up"},
};

static const std::map<std::string, std::string> CONTENC = {
    {"gzip", "gz"},
    {"deflate", "de"},
    {"identity", "id"},
    {"binary", "bi"},
    {"br", "bt"},
    {"compress", "co"},
    {"UTF8", "UT"},
};

static const std::map<std::string, std::string> CACHECONT = {
    {"max-age", "ma"},
    {"no-cache", "nc"},
    {"no-store", "ns"},
    {"no-transform", "nt"},
    {"only-if-cached", "oic"},
};

static const std::map<std::string, std::string> TE = {
    {"gzip", "gz"},
    {"deflate", "de"},
    {"compress", "co"},
    {"http", "ht"},
    {"trailers", "tr"},
};

static const std::map<std::string, std::string> ACCPTCHAR = {
    {"windows-1251", "w1"}, 
    {"utf-8", "ut"}, 
    {"*", "as"}, 
    {"iso-8859-1", "is"}
};

static const std::map<std::string, std::string> FEATURESET = {
    {"gzip", "gz"},
    {"deflate", "de"},
    {"compress", "co"},
    {"http", "ht"},
    {"trailers", "tr"},
};

static const std::vector<std::map<int, std::string>> FEATURESET = {
    {
        {1, "s"},
        {2, "i"},
        {3, "s"},
        {6, "f"},
        {9, "s"},
        {10, "s"},
        {13, "f"},
    },
    {
        {0, "i"},
        {1, "s"},
        {2, "i"},
        {3, "s"},
        {4, "i"},
        {5, "s"},
        {6, "i"},
        {7, "s"},
        {8, "s"},
        {9, "s"},
        {10, "s"},
        {11, "s"},
        {12, "i"},
        {13, "i"},
    },
    {
        {0, "i"},
        {1, "s"},
        {2, "i"},
        {3, "s"},
        {6, "f"},
        {7, "s"},
        {8, "s"},
        {9, "s"},
        {10, "s"},
        {11, "s"},
        {12, "i"},
        {13, "f"},
    },
    {
        {0, "i"},
        {2, "i"},
        {3, "s"},
        {6, "i"},
        {9, "s"},
    },
    {
        {0, "f"},
        {1, "s"},
        {2, "f"},
        {3, "s"},
        {4, "f"},
        {6, "f"},
        {7, "s"},
        {8, "s"},
        {9, "s"},
        {10, "s"},
        {11, "s"},
        {12, "f"},
        {13, "f"},
    },
};


static const std::vector<std::string> METHODS = {
    "GET",
    "POST",
    "HEAD",
    "PUT",
    "DELETE",
    "CONNECT",
    "OPTIONS",
    "TRACE",
    "PATCH",
};

#endif // INCLUDE_CONFIGS_HPP