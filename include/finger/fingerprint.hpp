/**
 * @file fingerprint.hpp
 * @author Gautier Miquet
 * @brief Declaration of HTTP Fingerprinting methods and objects
 * @version 0.1
 * @date 2022-03-03
 */

#ifndef FINGER_FINGERPRINT_HPP
#define FINGER_FINGERPRINT_HPP

#include <Poco/URI.h>
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

// ---- Creation exception shortcut ------------------------------------------------------

#define NEW_EXCEPTION(name, msg)                                             \
    class name : public std::exception {                                     \
      private:                                                               \
        std::string message;                                                 \
                                                                             \
      public:                                                                \
        name(const std::string& message = (msg)): message(message) { }       \
        virtual ~name() throw() { }                                          \
        virtual const char* what() const throw() { return message.c_str(); } \
    };

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                   Data Structures                                    //
//                                                                                      //
//--------------------------------------------------------------------------------------//

/**
 * @brief
 * @note wip
 */
struct HTTPRequest {
    std::string uri;
    std::string method;

    HTTPRequest(std::string uri, std::string method)
    : uri(std::move(uri)), method(std::move(method)) { }
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
     * @brief Number of query parameteres
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
 * method
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

// ---- Submethods -----------------------------------------------------------------------

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
 * @return URIQueryData The results containing the query string size, query count, average query
 * value size and average query value size in log10
 */
URIQueryData compute_uri_query_data(const Poco::URI& uri);

/**
 * @brief Computes the extension used in the URI from the path
 *
 * @param path URI Path
 * @return std::string The extensions used, empty if no extension is found
 */
std::string compute_uri_extention(const std::string& path);

// /**
//  * @brief Computes the entropy of a string
//  */
// float entropy(const std::string& str);

// /**
//  * @return true If every element of the given header begins with a capital letter
//  * @return false Otherwise
//  */
// bool isHeaderCapitalized(const std::string& header);

// /**
//  * @brief Reads the configuration file and stores it in a global variable (HDRL, CONTENTTYPE,
//  ACCPT)
//  */
// nlohmann::json readConfig(const std::string& path);


// /**
//  * @brief Get the case of the header
//  *
//  * @return true If the header is in upper case
//  * @return false Otherwise
//  */
// bool getHeaderCase(const std::string& header);

// /**
//  * @brief Get the method and version of the request in the form of "method|version"
//  */
// std::string getMethodVersion(const std::vector<std::string>& requestSplit);

// /**
//  * @brief Get the order of the headers
//  */
// std::string getHeaderOrder(const std::vector<std::string>& requestSplit);

// /**
//  * @brief Get the User-Agent value of the header
//  */
// std::string getUserAgentValue(const std::string& header);

// /**
//  * @brief Get the value of a header
//  *
//  * @param header
//  * @param headerName
//  * @param headerValues
//  * @return std::string
//  */
// std::string getHeaderValue(const std::string& header,
//                            const std::string& headerName,
//                            const std::map<std::string, std::string>& headerValues);

// /**
//  * @brief Get the content type of the header
//  *
//  * @param header
//  * @return std::string
//  */
// std::string getContentType(const std::string& header);

// /**
//  * @brief Get the accept language value of the header
//  *
//  * @param header
//  * @return std::string
//  */
// std::string getAcceptLanguageValue(const std::string& header);

// /**
//  * @brief Get all the values of the header in the form of "val1/val2/val3..."
//  *
//  * @param requestSplit
//  * @return std::string
//  */
// std::string getPopHeaderValues(const std::vector<std::string>& requestSplit);

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

// std::vector<std::string> split(std::string str, const std::string& delimiter);

/*
std::map<std::string, int> getCounter(const std::vector<std::string>& items);

std::vector<std::string> split(std::string str, const std::string& delimiter);

std::string join(std::vector<std::string> strings, const std::string& delimiter);

std::string toUpper(const std::string& str);

std::string toLower(const std::string& str);

std::string strip(const std::string& str);*/

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                      Exceptions                                      //
//                                                                                      //
//--------------------------------------------------------------------------------------//

NEW_EXCEPTION(BadReportmodeVariable, "Problem with 'reportmode' variable value.")
NEW_EXCEPTION(NotAPcap, "The provided file is not a valid pcap file.")

#endif /* FINGER_FINGERPRINT_HPP */
