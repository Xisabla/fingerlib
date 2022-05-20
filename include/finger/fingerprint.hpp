/**
 * @file fingerprint.hpp
 * @author Gautier Miquet
 * @brief Declaration of HTTP Fingerprinting methods and objects
 * @version 1.0.0
 * @date 2022-03-03
 */

#ifndef FINGER_FINGERPRINT_HPP
#define FINGER_FINGERPRINT_HPP

#include <faup/decode.h>
#include <faup/faup.h>
#include <faup/options.h>
#include <faup/output.h>
#include <finger/configs.hpp>
#include <json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef DEBUG
#include <iostream>
#endif

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                        Macros                                        //
//                                                                                      //
//--------------------------------------------------------------------------------------//

// ---- Debug print macro ----------------------------------------------------------------

#ifdef DEBUG
#define D_PRINT(msg) std::cout << "[DEBUG] " << msg << std::endl;
#else
#define D_PRINT(msg)
#endif

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                   Data Structures                                    //
//                                                                                      //
//--------------------------------------------------------------------------------------//

/**
 * @brief Data used to forge a fingerprint from an HTTP Request
 */
struct HTTPRequest {
    std::string uri;
    std::string method;
    std::string version;
    std::vector<std::string> headers;
    std::string payload;

    HTTPRequest(std::string uri,
                std::string method,
                std::string version,
                std::vector<std::string> headers,
                std::string payload = "")
    : uri(std::move(uri)), method(std::move(method)), version(std::move(version)),
      headers(std::move(headers)), payload(std::move(payload)) { }
};

/**
 * @brief Computed data about the directories in the URI path
 */
struct URIDirectoryData {
    /**
     * @brief Number of directories in the path
     */
    int count;

    /**
     * @brief Average size of a directory name
     */
    float avg_size;

    /**
     * @brief log10 of the average size of a directory name
     */
    float avg_size_log;
};

/**
 * @brief Computed data about the queries in the URI
 */
struct URIQueryData {
    /**
     * @brief Size of the query string
     */
    int size;

    /**
     * @brief Number of query parameters
     */
    int count;

    /**
     * @brief Average size of a query parameter
     */
    float avg_size;

    /**
     * @brief log10 of the average size of a query parameter
     */
    float avg_size_log;
};

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                       Methods                                        //
//                                                                                      //
//--------------------------------------------------------------------------------------//

//--------------------------------------------------------------------------------------//
//                               Fingerprint Computation                                //
//--------------------------------------------------------------------------------------//

/**
 * @brief Computes a fingerprint from an HTTP Request
 *
 * @param req HTTP Request fields
 * @return std::string The computed fingerprint
 */
std::string fingerprint(const HTTPRequest& req);

/**
 * @brief Computes the fingerprint from the URI, is part of the whole HTTP Request fingerprint
 *
 * @param uri Request URI
 * @return std::string The computed URI fingerprint
 */
std::string uri_fingerprint(const std::string& uri);

/**
 * @brief Computes the fingerprint field for the HTTP method used, is part of the whole HTTP Request
 * fingerprint
 *
 * @param method Full HTTP method name (GET, POST, DELETE, ...)
 * @return std::string The computed method fingerprint (correspond to the first letter: G, P, D,
 * ...)
 */
std::string method_fingerprint(const std::string& method);

/**
 * @brief Computes the fingerprint field for the HTTP version used, is part of the whole HTTP
 * Request fingerprint
 *
 * @param version Full HTTP version (1.1, 1.0, ...)
 * @return std::string The computed version fingerprint (correspond to the first digit: 1, ...)
 */
std::string version_fingerprint(const std::string& version);

/**
 * @brief Computes the fingerprint from the headers, is part of the whole HTTP Request fingerprint
 *
 * @param headers Request headers
 * @return std::string The computed headers fingerprint
 */
std::string header_fingerprint(const std::vector<std::string>& headers);

/**
 * @brief Computes the fingerprint from the payload, is part of the whole HTTP Request fingerprint
 *
 * @param payload Full string encoded payload
 * @return std::string The computed payload fingerprint
 */
std::string payload_fingerprint(const std::string& payload);

// ---- Submethods -----------------------------------------------------------------------

/**
 * @brief Fowler–Noll–Vo hash function (non cryptographic hash)
 *
 * @param str String to hash
 * @return std::string Hashed string
 */
std::string fnv1a_32(const std::string& str);

// Headers

/**
 * @brief Get the hex value for usual header
 *
 * @param header Header
 * @param headerName Name of the header
 * @param headerValueTable Values table for the header
 * @return std::string Hex value of the header
 */
std::string getHeaderValue(const std::string& header,
                           const std::string& headerName,
                           const std::map<std::string, std::string>& headerValueTable);

/**
 * @brief Get the hex value from Content-Type header
 *
 * @param header Content-Type header
 * @return std::string Hex value of the Content-Type header
 */
std::string getContentType(const std::string& header);

/**
 * @brief Get the hex value from Accept-Language header
 *
 * @param header Accept-Language header
 * @return std::string Hex value of the Accept-Language header
 */
std::string getAcceptLanguageValue(const std::string& header);

/**
 * @brief Get the hex value from User-Agent header
 *
 * @param header User-Agent header
 * @return std::string Hex value of the User-Agent header
 */
std::string getUaValue(const std::string& header);

/**
 * @brief Get the case of the header
 *
 * @return true If the header is in upper case
 * @return false Otherwise
 */
bool getHeaderCase(const std::string& header);

/**
 * @brief Get the order of the headers
 */
std::string getHeaderOrder(const std::vector<std::string>& headers);


// URI

/**
 * @brief Decodes a hexadecimal-encoded string (adaptation of POCO::decode)
 * @note
 * https://github.com/pocoproject/poco/blob/9d1c428c861f2e5ccf09149bbe8d2149720c5896/Foundation/src/URI.cpp#L669
 * @param str Encoded string
 * @param decodedStr Decoded string
 * @return void
 */
void decode(const std::string& str, std::string& decodedStr);

/**
 * @brief Parses query parameters and values from given query
 * @note
 * https://github.com/pocoproject/poco/blob/9d1c428c861f2e5ccf09149bbe8d2149720c5896/Foundation/src/URI.cpp#L373
 * @param query
 * @return std::vector <std::pair<std::string, std::string>> list of key-value pairs (parameters and
 * their values)
 */
std::vector<std::pair<std::string, std::string>> get_query_parameters(const std::string& query);

/**
 * @brief Computes the average length of the directory in the path, keeps in track the size of the
 * path and the average value in log10
 *
 * @param path URI Path
 * @return URIDirectoryData The results containing the path size, average directory size and average
 * directory size in log10
 */
URIDirectoryData compute_uri_directory_data(const std::string& path);

/**
 * @brief Computes the query string size and average value size in log10
 *
 * @param uri Parsed Poco URI
 * @param faup_handler_t Faup handler containing parsed uri
 * @return URIQueryData The results containing the query string size, query count, average query
 * value size and average query value size in log10
 */
URIQueryData compute_uri_query_data(const std::string& uri, faup_handler_t* fh);

/**
 * @brief Computes the extension used in the URI from the path
 *
 * @param path URI Path
 * @return std::string The extensions used, empty if no extension is found
 */
std::string compute_uri_extention(const std::string& path);

// Others

/**
 * @brief Computes the entropy of a string
 */
float entropy(const std::string& str);

//--------------------------------------------------------------------------------------//
//                                       Helpers                                        //
//--------------------------------------------------------------------------------------//

/**
 * @brief Computes the occurrences of each character in a string
 */
std::map<char, int> charOccurrences(const std::string& str);

/**
 * @brief Get length magnitude of the input rounded to 1 decimal
 */
float log10length(const std::string& str);

/**
 * @brief Get the string representation of the given float with the given precision
 *
 * @param v Float value
 * @param p Precision
 * @return std::string The formatted string
 * @note The precision is the number of digits after the decimal point
 */
std::string floatPrecision(const float& v, const int& p);

#endif /* FINGER_FINGERPRINT_HPP */
