/**
 * @file fingerprint.cpp
 * @author Gautier Miquet
 * @brief Implementation of HTTP Fingerprinting methods
 * @version 0.2
 * @date 2022-03-03
 */
#include <boost/algorithm/string.hpp>
#include <filesystem>
#include <finger/fingerprint.hpp>
#include <iomanip>
#include <map>

//--------------------------------------------------------------------------------------//
//                               Fingerprint Computation                                //
//--------------------------------------------------------------------------------------//

std::string fingerprint(const HTTPRequest& req) { return uri_fingerprint(req.uri); }

std::string uri_fingerprint(const std::string& uri) {
    float uri_length = log10length(uri);

    // Skip if the URI is too short
    if (uri.size() <= 1) {
        return floatPrecision(uri_length, 1) + "||||||";
    }

    std::stringstream fingerprint;

    // faup_options_new() is not thread safe, and should only be runned once per
    // code, it is also the part that loads the cached publicsuffix.org file
    faup_options_t* faup_opts;
    faup_opts = faup_options_new();

    // no need for the default csv output
    faup_opts->output = FAUP_OUTPUT_NONE;

    // modules slow down faup_init(), should be loaded only when needed
    faup_opts->exec_modules = FAUP_MODULES_NOEXEC;

    // fh is a pointer to a c struct that has, among others, all the positions
    // where the uri splits in host, tld, etc.
    faup_handler_t* fh;

    // init the faup handler
    fh = faup_init(faup_opts);

    faup_decode(fh, uri.c_str(), uri.size());

    // get path with faup
    const std::string path =
    uri.substr(faup_get_resource_path_pos(fh), faup_get_resource_path_size(fh));

    // Compute fields
    URIDirectoryData uri_dir_data = compute_uri_directory_data(path);
    URIQueryData uri_query_data = compute_uri_query_data(uri, fh);
    std::string ext = compute_uri_extention(path);

    // Forge fingerprint
    fingerprint << floatPrecision(uri_length, 1) << "|";
    fingerprint << std::to_string(uri_dir_data.count) << "|"
                << floatPrecision(uri_dir_data.avg_size_log, 1) << "|";
    fingerprint << ext << "|";
    fingerprint << floatPrecision(log10f(static_cast<float>(uri_query_data.size)), 1) << "|"
                << std::to_string(uri_query_data.count) << "|"
                << floatPrecision(uri_query_data.avg_size_log, 1);

    // Free pointers
    faup_options_free(faup_opts);
    faup_terminate(fh);

    return fingerprint.str();
}

// ---- Submethods -----------------------------------------------------------------------

URIDirectoryData compute_uri_directory_data(const std::string& path) {
    URIDirectoryData res = { 0, .0, .0 };
    std::vector<std::string> tokenized_path;
    boost::split(tokenized_path, path, boost::is_any_of("/"));

    // Remove first element of tokenized_path as it is empty
    tokenized_path.erase(tokenized_path.begin());

    res.count = tokenized_path.size();

    if (res.count == 0) {
        return res;
    }

    // Compute average directory size
    for (auto& dir: tokenized_path) {
        res.avg_size += dir.size();
    }
    res.avg_size = res.avg_size / static_cast<float>(res.count);

    // Convert to log10
    res.avg_size_log = log10f(res.avg_size);

    return res;
}

URIQueryData compute_uri_query_data(const std::string& uri, faup_handler_t* fh) {
    URIQueryData res = { 0, 0, .0, .0 };

    std::string query = uri.substr(faup_get_query_string_pos(fh), faup_get_query_string_size(fh));
    auto queries = get_query_parameters(query);

    res.size = query.size();
    res.count = queries.size();

    if (res.count == 0) {
        return res;
    }

    // Compute average query size
    for (auto& q: queries) {
        res.avg_size += q.second.size();
    }
    res.avg_size = res.avg_size / static_cast<float>(res.count);

    // Convert to log10
    res.avg_size_log = log10f(res.avg_size);

    return res;
}

std::string compute_uri_extention(const std::string& path) {
    namespace fs = std::filesystem;

    std::string ext = fs::path(path).extension().string();

    if (ext.empty()) {
        return ext;
    }

    ext.erase(0, 1);

    return ext;
}

// Function adapted from POCO library
// https://github.com/pocoproject/poco/blob/9d1c428c861f2e5ccf09149bbe8d2149720c5896/Foundation/src/URI.cpp#L669
void decode(const std::string& str, std::string& decodedStr) {
    std::string::const_iterator it = str.begin();
    std::string::const_iterator end = str.end();
    const int OFFSET = 10;
    const int HEX_OFFSET = 16;
    while (it != end) {
        int c = *it++;
        if (c == '%') {
            if (it == end) {
                throw std::exception();
            }
            int hi = *it++;
            if (it == end) {
                throw std::exception();
            }
            int lo = *it++;
            if (hi >= '0' && hi <= '9') {
                c = hi - '0';
            } else if (hi >= 'A' && hi <= 'F') {
                c = hi - 'A' + OFFSET;
            } else if (hi >= 'a' && hi <= 'f') {
                c = hi - 'a' + OFFSET;
            } else {
                throw std::exception();
            }
            c *= HEX_OFFSET;
            if (lo >= '0' && lo <= '9') {
                c += lo - '0';
            } else if (lo >= 'A' && lo <= 'F') {
                c += lo - 'A' + OFFSET;
            } else if (lo >= 'a' && lo <= 'f') {
                c += lo - 'a' + OFFSET;
            } else {
                throw std::exception();
            }
        }
        decodedStr += std::to_string(c);
    }
}

// Function adapted from POCO library
// https://github.com/pocoproject/poco/blob/9d1c428c861f2e5ccf09149bbe8d2149720c5896/Foundation/src/URI.cpp#L373
std::vector<std::pair<std::string, std::string>> get_query_parameters(const std::string& query) {
    std::vector<std::pair<std::string, std::string>> result;
    std::string::const_iterator it(query.begin());
    std::string::const_iterator end(query.end());
    while (it != end) {
        std::string name;
        std::string value;
        while (it != end && *it != '=' && *it != '&') {
            if (*it == '+') {
                name += ' ';
            } else {
                name += *it;
            }
            ++it;
        }
        if (it != end && *it == '=') {
            ++it;
            while (it != end && *it != '&') {
                if (*it == '+') {
                    value += ' ';
                } else {
                    value += *it;
                }
                ++it;
            }
        }
        std::string decodedName;
        std::string decodedValue;
        decode(name, decodedName);
        decode(value, decodedValue);
        result.push_back(std::make_pair(decodedName, decodedValue));
        if (it != end && *it == '&') {
            ++it;
        }
    }
    return result;
}

// float entropy(const std::string& str) {
//     float entropy = 0;

//     const auto occurrences = charOccurrences(str);

//     for (const auto& item: occurrences) {
//         float p = item.second / static_cast<float>(str.size());
//         entropy += p * std::log2f(p);
//     }

//     // return -entropy;
//     return std::roundf((-entropy) * 10) / 10;
// }

// bool isHeaderCapitalized(const std::string& header) {
//     if (header.find('-') == std::string::npos) {
//         return isupper(header[0]) == 0;
//     }

//     // std::vector<std::string> fields = split(header, "-");
//     std::vector<std::string> fields;

//     boost::split(fields, header, boost::is_any_of("-"));

//     for (auto& field: fields) {
//         if (islower(field[0]) != 0) {
//             return false;
//         }
//     }

//     return true;
// }

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

float log10length(const std::string& str) {
    return std::roundf(log10f(str.size()) * 10) / 10; // NOLINT(readability-magic-numbers)
}

std::string floatPrecision(const float& v, const int& p) {
    std::stringstream ss;

    ss << std::fixed << std::setprecision(p) << v;

    return ss.str();
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
