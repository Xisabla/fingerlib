/**
 * @file fingerprint.cpp
 * @author Gautier Miquet
 * @brief Implementation of HTTP Fingerprinting methods
 * @version 1.0
 * @date 2022-03-03
 */
#include <Poco/URI.h>
#include <boost/algorithm/string.hpp>
#include <finger/fingerprint.hpp>
#include <iomanip>
#include <map>
#include <sstream>

//--------------------------------------------------------------------------------------//
//                               Fingerprint Computation                                //
//--------------------------------------------------------------------------------------//

std::string fingerprint(const HTTPRequest& req) { return uri_fingerprint(req.uri); }

std::string uri_fingerprint(const std::string& uri) {
    std::stringstream uri_len;

    Poco::URI uri_parsed(uri);

    uri_len << std::fixed << std::setprecision(1) << log10length(uri);

    if (uri.size() <= 1) {
        return uri_len.str() + "||||||";
    }

    return "";
}

// ---- Submethods -----------------------------------------------------------------------

float entropy(const std::string& str) {
    float entropy = 0;

    const auto occurrences = charOccurrences(str);

    for (const auto& item: occurrences) {
        float p = item.second / static_cast<float>(str.size());
        entropy += p * std::log2f(p);
    }

    // return -entropy;
    return std::roundf((-entropy) * 10) / 10;
}

float log10length(const std::string& str) { return std::roundf(log10f(str.size()) * 10) / 10; }

bool isHeaderCapitalized(const std::string& header) {
    if (header.find('-') == std::string::npos) {
        return isupper(header[0]) == 0;
    }

    // std::vector<std::string> fields = split(header, "-");
    std::vector<std::string> fields;

    boost::split(fields, header, boost::is_any_of("-"));

    for (auto& field: fields) {
        if (islower(field[0]) != 0) {
            return false;
        }
    }

    return true;
}

// std::string getMethodVersion(const std::vector<std::string>& requestSplit) {
//     std::string rVer;
//     std::string rMeth;

//     // Checking if HTTP version is provided, if not assuming it is HTTP 0.9 per
//     // www.w3.org/Protocols/HTTP/Request.html
//     if (requestSplit[0].find(" HTTP/") == std::string::npos) {
//         rVer = "9";

//         // take first seven characters of the first line of request to look for method (methods
//         have
//         // up to 7 chars)
//         std::string t2 = strip(toUpper(requestSplit[0].substr(0, 7)));

//         // if method shorter than 7 chars we will have part of URL in t2
//         // we should find space between method and URL and cut the string on it
//         auto it = requestSplit[0].find(' ');
//         std::string meth = t2.substr(0, it);
//         if (it == std::string::npos) {
//             // method has 7 chars, so no need to cut t2
//             meth = t2;
//         }

//         if (std::find(METHODS.begin(), METHODS.end(), meth) != METHODS.end()) {
//             rMeth = meth.substr(0, 2);
//         }
//     } else {
//         auto t = split(requestSplit[0], " HTTP/");

//         std::string t1 = strip(t[0]);

//         // check if method is present by taking first 7 characters and searching there for method
//         // (methods have up to 7 chars)
//         std::string t2 = strip(toUpper(t1.substr(0, 7)));

//         // if method shorter than 7 chars we will have part of URL in t2
//         // we should find space between method and URL and cut the string on it
//         auto it = t1.find(' ');
//         std::string meth = t2.substr(0, it);

//         if (it == std::string::npos) {
//             // method has 7 chars, so no need to cut t2
//             meth = t2;
//         }

//         if (std::find(METHODS.begin(), METHODS.end(), meth) != METHODS.end()) {
//             rMeth = meth.substr(0, 2);

//             if (t[1].find("1.1") != std::string::npos) {
//                 rVer = "1";
//             } else {
//                 rVer = "0";
//             }
//         }
//     }

//     return rMeth + "|" + rVer;
// }

// // Checking header order - assuming that header field contains ":"
// std::string getHeaderOrder(const std::vector<std::string>& requestSplit) {
//     std::vector<std::string> ret;

//     for (const auto& reqline: requestSplit) {
//         std::string header = split(reqline, ":")[0];
//         std::string headerLower = toLower(header);

//         int fnv1a_32 = 29; // TODO : replace with corresponding FNV1a_32 hash
//         std::string headerCoded;
//         // Convert fnv1a_32 to hex
//         std::stringstream ss;
//         ss << std::hex << fnv1a_32;
//         headerCoded = ss.str();

//         if (HDRL.find(headerLower) != HDRL.end()) {
//             if (getHeaderCase(header)) {
//                 headerCoded = HDRL[headerLower];
//             } else {
//                 headerCoded = "!" + HDRL[headerLower].get<std::string>();
//             }
//         }

//         ret.push_back(headerCoded);
//     }

//     return join(ret, ",");
// }

// std::string getUserAgentValue(const std::string& header) {
//     std::string val = split(header, ":")[1];
//     if (val[0] == ' ') {
//         val = val.substr(1);
//     }
//     std::string name = HDRL["user-agent"];
//     int fnv1a_32 = 29; // TODO : replace with corresponding FNV1a_32 hash
//     std::string ret = name + ":" + std::to_string(fnv1a_32); // fnv1a_32(val.c_str()));
//     return ret;
// }

// std::string getHeaderValue(const std::string& header,
//                            const std::string& headerName,
//                            const std::map<std::string, std::string>& headerValues) {
//     std::string val = split(header, ":")[1];
//     if (val[0] == ' ') {
//         val = val.substr(1);
//     }

//     std::string headerCoded = HDRL[headerName];
//     std::vector<std::string> ret;

//     if (val.find(',') != std::string::npos) {
//         // simple splitting of compound values
//         if (val.find(";q=") != std::string::npos) {
//             // we do not tokenize compound values with quality parameters at this moment
//             return headerCoded + std::to_string(29); // TODO : replace with corresponding
//             FNV1a_32
//                                                      // hash -> format(fnv1a_32(val.encode()),
//                                                      "x")
//         }
//         std::vector<std::string> t;
//         if (val.find(", ") != std::string::npos) {
//             t = split(val, ", ");
//         } else {
//             t = split(val, ",");
//         }
//         for (auto& j: t) {
//             if (j.empty()) {
//                 return headerCoded +
//                        std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash ->
//                                            // format(fnv1a_32(val.encode()), "x")
//             }
//             if (headerValues.find(j) == headerValues.end()) {
// #ifdef DEBUG
//                 std::cout << "Unknown header value - " << header << std::endl;
// #endif
//                 return headerCoded +
//                        std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash ->
//                                            // format(fnv1a_32(val.encode()), "x")
//             }
//             ret.push_back(headerValues.at(j));
//         }
//     } else {
//         std::string k;
//         if (headerValues.find(val) != headerValues.end()) {
//             k = headerValues.at(val);
//         } else {
// #ifdef DEBUG
//             std::cout << "Unknown header value - " << header << std::endl;
// #endif
//             k = std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash ->
//                                     // format(fnv1a_32(val.encode()), "x")
//         }
//         ret.push_back(k);
//     }
//     return headerCoded + join(ret, ",");
// }

// std::string getContentType(const std::string& header) {
//     std::string val = split(header, ":")[1];
//     if (val[0] == ' ') {
//         val = val.substr(1);
//     }
//     std::string hdr_coded = HDRL["content-type"].get<std::string>() + ":";
//     std::vector<std::string> ret;

//     if (val.find(',') != std::string::npos) {
//         std::vector<std::string> vals;
//         if (val.find(", ") != std::string::npos) {
//             vals = split(val, ", ");
//         } else {
//             vals = split(val, ",");
//         }

//         for (auto& itv: vals) {
//             if (itv.find(';') != std::string::npos) {
//                 if (itv.find("boundary=") != std::string::npos) {
//                     size_t bnd_ind = itv.find("boundary=");
//                     int bnd_offset = std::string("boundary=").length();
//                     std::string val_bnd = itv.substr(0, bnd_ind + bnd_offset);
//                     return hdr_coded +
//                            std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash
//                            ->
//                                                // format(fnv1a_32(val_bnd.encode()), "x")
//                 }
//                 ret.push_back(std::to_string(29)); // TODO : replace with corresponding FNV1a_32
//                                                    // hash -> format(fnv1a_32(itv.encode()), "x")

//             } else {
//                 std::string k = std::to_string(29); // TODO : replace with corresponding FNV1a_32
//                                                     // hash -> format(fnv1a_32(itv.encode()),
//                                                     "x")

//                 if (CONTENTTYPE.find(itv) != CONTENTTYPE.end()) {
//                     k = CONTENTTYPE.at(itv);
//                 } else {
// #ifdef DEBUG
//                     std::cout << "Unknown Content-Type value - " << header << std::endl;
// #endif
//                 }
//                 ret.push_back(k);
//             }
//         }
//     } else {
//         if (val.find(';') != std::string::npos) {
//             if (val.find("boundary=") == std::string::npos) {
//                 return hdr_coded +
//                        std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash ->
//             }
//             // format(fnv1a_32(val.encode()), "x")
//             size_t bnd_ind = val.find("boundary=");
//             int bnd_offset = std::string("boundary=").length();
//             std::string val_bnd = val.substr(0, bnd_ind + bnd_offset);
//             return hdr_coded +
//                    std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash ->
//                                        // format(fnv1a_32(val_bnd.encode()), "x")
//         }
//         std::string k = std::to_string(29); // TODO : replace with corresponding FNV1a_32 hash
//                                             // -> format(fnv1a_32(val.encode()), "x")
//         if (CONTENTTYPE.find(val) != CONTENTTYPE.end()) {
//             k = CONTENTTYPE.at(val);
//         } else {
// #ifdef DEBUG
//             std::cout << "Unknown Content-Type value - " << header << std::endl;
// #endif
//         }
//         ret.push_back(k);
//     }
//     return hdr_coded + join(ret, ",");
// }

// std::string getAcceptLanguageValue(const std::string& header) {
//     std::string val = split(header, ":")[1];
//     std::string name = HDRL["accept-language"];
//     int fnv1a_32 = 29; // TODO : replace with corresponding FNV1a_32 hash
//     std::string ret = name + ":" + std::to_string(fnv1a_32); // format(fnv1a_32(val.encode()),
//     "x") return ret;
// }

// std::string getPopHeaderValues(const std::vector<std::string>& requestSplit) {
//     std::vector<std::string> r;

//     for (size_t i = 1; i < requestSplit.size(); i++) {
//         const auto& reqline = requestSplit[i];

//         if (reqline.find(':') != std::string::npos) {
//             std::string headerLower = toLower(split(reqline, ":")[0]);

//             if (headerLower == "connection") {
//                 r.push_back(getHeaderValue(reqline, "connection", CONNVAL));
//             } else if (headerLower == "accept-encoding") {
//                 r.push_back(getHeaderValue(reqline, "accept-encoding", AEVAL));
//             } else if (headerLower == "content-encoding") {
//                 r.push_back(getHeaderValue(reqline, "content-encoding", CONTENC));
//             } else if (headerLower == "cache-control") {
//                 r.push_back(getHeaderValue(reqline, "cache-control", CACHECONT));
//             } else if (headerLower == "te") {
//                 r.push_back(getHeaderValue(reqline, "te", TE));
//             } else if (headerLower == "accept-charset") {
//                 r.push_back(getHeaderValue(reqline, "accept-charset", ACCPTCHAR));
//             } else if (headerLower == "content-type") {
//                 r.push_back(getContentType(reqline));
//             } else if (headerLower == "accept") {
//                 r.push_back(getHeaderValue(reqline, "accept", ACCPT));
//             } else if (headerLower == "accept-language") {
//                 r.push_back(getAcceptLanguageValue(reqline));
//             } else if (headerLower == "user-agent") {
//                 r.push_back(getUserAgentValue(reqline));
//             }
// #ifdef DEBUG
//             else {
//                 std::cout << "No colon in line: " << reqline << std::endl;
//             }
// #endif
//         }
//     }
//     std::string ret = join(r, "/");
//     return ret;
// }


// namespace fs = std::filesystem;

// nlohmann::json readConfig(const std::string& path) {
//     std::ifstream file(fs::current_path() / fs::path("configs") / path);
//     nlohmann::json config;
//     file >> config;
//     file.close();
//     return config;
// }

// static const nlohmann::json HDRL = readConfig("headerslow.json");
// static const nlohmann::json CONTENTTYPE = readConfig("content-type.json");
// static const nlohmann::json ACCPT = readConfig("accept.json");

//--------------------------------------------------------------------------------------//
//                                       Helpers                                        //
//--------------------------------------------------------------------------------------//

std::map<char, int> charOccurrences(const std::string& str) {
    std::map<char, int> occurrences;

    for (const char& c: str) {
        if (occurrences.find(c) == occurrences.end()) {
            occurrences[c] = 1;
        } else {
            occurrences[c]++;
        }
    }

    return occurrences;
}

// std::vector<std::string> split(std::string str, const std::string& delimiter) {
//     std::vector<std::string> tokens;
//     size_t pos = 0;
//     std::string token;
//     while ((pos = str.find(delimiter)) != std::string::npos) {
//         token = str.substr(0, pos);
//         tokens.push_back(token);
//         str.erase(0, pos + delimiter.length());
//     }
//     tokens.push_back(str);
//     return tokens;
// }
