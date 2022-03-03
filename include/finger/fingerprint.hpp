/**
 * @file fingerprint.hpp
 * @author Gautier Miquet
 * @brief Declaration of HTTP Fingerprinting methods and objects
 * @version 0.1
 * @date 2022-03-03
 */

#ifndef FINGER_FINGERPRINT_HPP
#define FINGER_FINGERPRINT_HPP

#include <exception>
#include <string>
#include <utility>

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

    HTTPRequest(std::string uri, std::string method): uri(uri), method(method) { }
};

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                       Methods                                        //
//                                                                                      //
//--------------------------------------------------------------------------------------//


/**
 * @brief Computes a fingerprint from an HTTP Request
 * method
 *
 * @ref https://github.com/CERT-Polska/hfinger/blob/master/hfinger/uri_reader.py#L53
 * @param req HTTP Request fields
 * @return std::string The computed fingerprint
 */
std::string fingerprint(HTTPRequest req);

/* std::string uri_fingerprint(std::string uri); */

//--------------------------------------------------------------------------------------//
//                                                                                      //
//                                      Exceptions                                      //
//                                                                                      //
//--------------------------------------------------------------------------------------//

NEW_EXCEPTION(BadReportmodeVariable, "Problem with 'reportmode' variable value.")
NEW_EXCEPTION(NotAPcap, "The provided file is not a valid pcap file.")

#endif // FINGER_FINGERPRINT_HPP
