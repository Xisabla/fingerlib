/**
 * @file fingerprint.hpp
 * @author Gautier Miquet
 * @brief Declaration of HTTP Fingerprinting methods and objects
 * @version 0.1
 * @date 2022-03-03
 */

#ifndef FINGER_FINGERPRINT_HPP
#define FINGER_FINGERPRINT_HPP

#include <finger/configs.hpp>
#include <json.hpp>
#include <stdexcept>
#include <string>
#include <vector>

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                        Macros                                        //
//                                                                                      //
//--------------------------------------------------------------------------------------//

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

struct HTTPRequest {
    std::string uri;
    std::string method;

    HTTPRequest(std::string uri, std::string method)
    : uri(std::move(uri)), method(std::move(method)) { }
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
 * @brief Computes the entropy of a string
 */
float entropy(const std::string& str);

/**
 * @brief Get length magnitude of the input rounded to 1 decimal
 */
float log10length(const std::string& str);

bool isHeaderCapitalized(const std::string& header);

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

std::map<char, int> charOccurrences(const std::string& str);

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
