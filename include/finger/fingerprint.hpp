#ifndef FINGER_FINGERPRINT_HPP
#define FINGER_FINGERPRINT_HPP

#include <string>
#include <exception>
#include <utility>

#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <numeric>
#include <cmath>
#include <fstream>
#include <filesystem>

#include <configs.hpp>
#include <json.hpp>
#include <finger/utils.hpp>

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
//                                       Methods                                        //
//                                                                                      //
//--------------------------------------------------------------------------------------//

struct HTTPRequest {
    // TODO: Write content
 };

/**
 * @brief Simple testing method, prints "hello world"
 */
void hello();

/**
 * @brief Computes a fingerprint from an HTTP Request, is an adapted version of hfinger give_fing method
 * 
 * @ref https://github.com/CERT-Polska/hfinger/blob/master/hfinger/uri_reader.py#L53
 * @param req HTTP Request fields
 * @return std::string The computed fingerprint
 */
std::string fingerprint(HTTPRequest req);

/**
 * @brief Reads the configuration file and stores it in a global variable (HDRL, CONTENTTYPE, ACCPT)
 */
nlohmann::json readConfig(const std::string& path);

/**
 * @brief Computes the entropy of a vector of strings
 */
float entropy(const std::vector<std::string>& bstr);

/**
 * @brief Get the entropy rounded to 1 decimal
 */
std::string getEntropy(const std::vector<std::string>& bstr);

/**
 * @brief Get the magnitude of the length of the input rounded to 1 decimal
 */
std::string getLog10Length(const std::vector<std::string>& bstr);

/**
 * @brief Get the case of the header
 * 
 * @return true If the header is in upper case
 * @return false Otherwise
 */
bool getHeaderCase(const std::string& header);

/**
 * @brief Get the method and version of the request in the form of "method|version"
 */
std::string getMethodVersion(const std::vector<std::string>& requestSplit);

/**
 * @brief Get the order of the headers
 */
std::string getHeaderOrder(const std::vector<std::string>& requestSplit);

/**
 * @brief Get the User-Agent value of the header
 */
std::string getUserAgentValue(const std::string& header);

/**
 * @brief Get the value of a header
 * 
 * @param header 
 * @param headerName 
 * @param headerValues 
 * @return std::string 
 */
std::string getHeaderValue(const std::string& header, const std::string& headerName, const std::map<std::string, std::string>& headerValues);

/**
 * @brief Get the content type of the header
 * 
 * @param header 
 * @return std::string 
 */
std::string getContentType(const std::string& header);

/**
 * @brief Get the accept language value of the header
 * 
 * @param header 
 * @return std::string 
 */
std::string getAcceptLanguageValue(const std::string& header);

/**
 * @brief Get all the values of the header in the form of "val1/val2/val3..."
 * 
 * @param requestSplit 
 * @return std::string 
 */
std::string getPopHeaderValues(const std::vector<std::string>& requestSplit);

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                      Exceptions                                      //
//                                                                                      //
//--------------------------------------------------------------------------------------//

NEW_EXCEPTION(BadReportmodeVariable, "Problem with 'reportmode' variable value.")
NEW_EXCEPTION(NotAPcap, "The provided file is not a valid pcap file.")

#endif // FINGER_FINGERPRINT_HPP
