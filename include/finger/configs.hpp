/**
 * @file configs.hpp
 * @author Paul Bucamp
 * @brief Values mapping used for the fingerprint generation
 * @version 1.0
 * @date 2022-03-03
 */
#ifndef FINGER_CONFIGS_HPP
#define FINGER_CONFIGS_HPP

#include <map>
#include <string>
#include <vector>

/**
 * @brief HTTP Request field "Accept-Encoding" values
 */
static const std::map<std::string, std::string> AE = {
    { "gzip", "gz" },     { "deflate", "de" }, { "identity", "id" },
    { "none", "no" },     { "sdch", "sd" },    { "br", "br" },
    { "compress", "co" }, { "*", "as" },       { "chunked", "ch" },
};

/**
 * @brief HTTP Request field "Connection" values
 */
static const std::map<std::string, std::string> CONN = {
    { "Keep-Alive", "Ke-Al" }, { "keep-alive", "ke-al" }, { "close", "cl" },
    { "Close", "Cl" },         { "Upgrade", "Up" },
};

/**
 * @brief HTTP Request field "Content-Encoding" values
 */
static const std::map<std::string, std::string> CONTENC = {
    { "gzip", "gz" }, { "deflate", "de" },  { "identity", "id" }, { "binary", "bi" },
    { "br", "bt" },   { "compress", "co" }, { "UTF8", "UT" },
};

/**
 * @brief HTTP Request field "Cache-Control" values
 */
static const std::map<std::string, std::string> CACHECONT = {
    { "max-age", "ma" },      { "no-cache", "nc" },        { "no-store", "ns" },
    { "no-transform", "nt" }, { "only-if-cached", "oic" },
};

/**
 * @brief HTTP Request field "TE" values
 */
static const std::map<std::string, std::string> TE = {
    { "gzip", "gz" }, { "deflate", "de" },  { "compress", "co" },
    { "http", "ht" }, { "trailers", "tr" },
};

/**
 * @brief HTTP Request field "Accept-Charset" values
 */
static const std::map<std::string, std::string> ACCPTCHAR = { { "windows-1251", "w1" },
                                                              { "utf-8", "ut" },
                                                              { "*", "as" },
                                                              { "iso-8859-1", "is" } };

static const std::vector<std::map<int, std::string>> FEATURESET = {
    {
    { 1, "s" },
    { 2, "i" },
    { 3, "s" },
    { 6, "f" },
    { 9, "s" },
    { 10, "s" },
    { 13, "f" },
    },
    {
    { 0, "i" },
    { 1, "s" },
    { 2, "i" },
    { 3, "s" },
    { 4, "i" },
    { 5, "s" },
    { 6, "i" },
    { 7, "s" },
    { 8, "s" },
    { 9, "s" },
    { 10, "s" },
    { 11, "s" },
    { 12, "i" },
    { 13, "i" },
    },
    {
    { 0, "i" },
    { 1, "s" },
    { 2, "i" },
    { 3, "s" },
    { 6, "f" },
    { 7, "s" },
    { 8, "s" },
    { 9, "s" },
    { 10, "s" },
    { 11, "s" },
    { 12, "i" },
    { 13, "f" },
    },
    {
    { 0, "i" },
    { 2, "i" },
    { 3, "s" },
    { 6, "i" },
    { 9, "s" },
    },
    {
    { 0, "f" },
    { 1, "s" },
    { 2, "f" },
    { 3, "s" },
    { 4, "f" },
    { 6, "f" },
    { 7, "s" },
    { 8, "s" },
    { 9, "s" },
    { 10, "s" },
    { 11, "s" },
    { 12, "f" },
    { 13, "f" },
    },
};

/**
 * @brief HTTP Request field "Method" values
 */
static const std::vector<std::string> METHODS = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
};

static std::map<std::string, std::string> HDRL = {
    { "accept", "ac" },
    { "accept-charset", "ac-ch" },
    { "accept-datetime", "ac-da" },
    { "accept-encoding", "ac-en" },
    { "accept-language", "ac-la" },
    { "access-control-request-headers", "a-c-r-h" },
    { "access-control-request-method", "a-c-r-m" },
    { "a-im", "a-i" },
    { "authorization", "au" },
    { "cache-control", "ca-co" },
    { "connection", "co" },
    { "content-length", "co-le" },
    { "content-type", "co-ty" },
    { "content-encoding", "co-en" },
    { "cookie", "ck" },
    { "date", "da" },
    { "dnt", "dn" },
    { "expect", "ex" },
    { "forwarded", "fo" },
    { "from", "fr" },
    { "front-end-https", "f-e-h" },
    { "host", "ho" },
    { "http2-settings", "ht-se" },
    { "if-match", "if-ma" },
    { "if-modified-since", "i-m-s" },
    { "if-none-match", "i-n-m" },
    { "if-range", "if-ra" },
    { "if-unmodified-since", "i-u-s" },
    { "keep-alive", "ke-al" },
    { "max-forwards", "ma-fo" },
    { "origin", "or" },
    { "pragma", "pr" },
    { "proxy-authorization", "pr-au" },
    { "proxy-connection", "pr-co" },
    { "range", "ra" },
    { "referer", "re" },
    { "save-data", "sa-da" },
    { "te", "te" },
    { "upgrade", "up" },
    { "upgrade-insecure-requests", "u-i-r" },
    { "user-agent", "us-ag" },
    { "via", "vi" },
    { "warning", "wa" },
    { "x-att-deviceid", "x-a-d" },
    { "x-correlation-id", "x-c-i" },
    { "x-csrf-token", "x-c-t" },
    { "x-forwarded-for", "x-f-f" },
    { "x-forwarded-host", "x-f-h" },
    { "x-forwarded-proto", "x-f-p" },
    { "x-http-method-override", "x-h-m-o" },
    { "x-requested-with", "x-r-w" },
    { "x-request-id", "x-r-i" }
};

static std::map<std::string, std::string> ACCPT = {
    { "*", "as" },
    { "*/*", "as-as" },
    { "application/*", "ap-as" },
    { "application/ecmascript", "ap-ec" },
    { "application/font-woff", "ap-f-w" },
    { "application/font-woff2", "ap-f-w-2" },
    { "application/javascript", "ap-ja" },
    { "application/json", "ap-js" },
    { "application/msword", "ap-m-w" },
    { "application/octet-stream", "ap-o-s" },
    { "application/vnd.ms-excel", "ap-m-e" },
    { "application/vnd.ms-powerpoint", "ap-m-p" },
    { "application/xaml+xml", "ap-xa-xm" },
    { "application/x-ecmascript", "ap-x-e" },
    { "application/xhtml+xml", "ap-xh+xm" },
    { "application/xml", "ap-xm" },
    { "application/x-ms-application", "ap-x-m-ap" },
    { "application/x-ms-xbap", "ap-x-m-xb" },
    { "application/x-shockwave-flash", "ap-x-sh-fl" },
    { "audio/*", "au-as" },
    { "image/*", "im-as" },
    { "image/gif", "im-gi" },
    { "image/jpeg", "im-jp" },
    { "image/pjpeg", "im-pj" },
    { "image/png", "im-pn" },
    { "image/svg+xml", "im-sv-xm" },
    { "image/webp", "im-we" },
    { "image/x-xbitmap", "im-x-xb" },
    { "text/*", "te-as" },
    { "text/css", "te-cs" },
    { "text/html", "te-ht" },
    { "text/javascript", "te-ja" },
    { "text/plain", "te-pl" },
    { "text/xml", "te-xm" },
    { "video/*", "vi-as" }
};

static std::map<std::string, std::string> CONTENTTYPE = {
    { "application/javascript", "ap-ja" },
    { "application/json", "ap-js" },
    { "application/octet-stream", "ap-os" },
    { "application/pdf", "ap-pd" },
    { "application/vnd.mozilla.metrics.bz2", "ap-bz" },
    { "application/xml", "ap-xm" },
    { "application/x-octet-stream", "ap-x-o-s" },
    { "application/x-www-form-urlencoded", "ap-x-w-f-u" },
    { "audio/mpeg", "au-mp" },
    { "binary", "bi" },
    { "image/gif", "im-gi" },
    { "image/jpeg", "im-jp" },
    { "image/png", "im-pn" },
    { "message/rfc822", "me-rf" },
    { "model/mesh", "mo-me" },
    { "multipart/form-data", "mu-f-d" },
    { "octet/binary", "oc-bi" },
    { "octet-stream", "oc-st" },
    { "text/csv", "te-cs" },
    { "text/html", "te-ht" },
    { "text/plain", "te-pl" },
    { "text/xml", "te-xm" },
    { "video/h264", "vi-h2" },
    { "video/mpeg", "vi-mp" }
};

#endif /* FINGER_CONFIGS_HPP */
