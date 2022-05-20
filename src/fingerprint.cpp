/**
 * @file fingerprint.cpp
 * @author Gautier Miquet
 * @brief Implementation of HTTP Fingerprinting methods
 * @version 1.0.0
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

std::string fingerprint(const HTTPRequest& req) {
    std::stringstream fingerprint;

    fingerprint << uri_fingerprint(req.uri) << "|";
    fingerprint << method_fingerprint(req.method) << "|";
    fingerprint << version_fingerprint(req.version) << "|";
    fingerprint << header_fingerprint(req.headers) << "|";
    fingerprint << payload_fingerprint(req.payload);

    return fingerprint.str();
}

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

    if (std::find(EXT.begin(), EXT.end(), ext) == EXT.end()) {
        ext = "";
    }

    // Forge fingerprint
    fingerprint << floatPrecision(uri_length, 1) << "|";
    fingerprint << std::to_string(uri_dir_data.count) << "|"
                << floatPrecision(uri_dir_data.avg_size_log, 1) << "|";
    fingerprint << ext << "|";

    if (uri_query_data.size != 0 || uri_query_data.count != 0 || uri_query_data.avg_size != .0 ||
        uri_query_data.avg_size_log != .0) {
        fingerprint << floatPrecision(log10f(static_cast<float>(uri_query_data.size)), 1) << "|"
                    << std::to_string(uri_query_data.count) << "|"
                    << floatPrecision(uri_query_data.avg_size_log, 1);
    } else {
        fingerprint << "||";
    }

    // Free pointers
    faup_options_free(faup_opts);
    faup_terminate(fh);

    return fingerprint.str();
}

std::string method_fingerprint(const std::string& method) {
    std::string res(method, 0, 2);

    return res;
}

std::string version_fingerprint(const std::string& version) {
    if (version.empty()) {
        return "9";
    }

    std::string res(version, 0, 1);

    return res;
}

std::string header_fingerprint(const std::vector<std::string>& headers) {
    std::string header_order = getHeaderOrder(headers);
    std::vector<std::string> result;

    // Compute fields
    for (const std::string& header: headers) {
        std::vector<std::string> res;
        boost::split(res, header, boost::is_any_of(":"));
        std::string headerLower = boost::to_lower_copy(res[0]);

        if (headerLower == "connection") {
            result.emplace_back(getHeaderValue(header, headerLower, CONN));
        } else if (headerLower == "accept-encoding") {
            result.emplace_back(getHeaderValue(header, headerLower, AE));
        } else if (headerLower == "content-encoding") {
            result.emplace_back(getHeaderValue(header, headerLower, CONTENC));
        } else if (headerLower == "cache-control") {
            result.emplace_back(getHeaderValue(header, headerLower, CACHECONT));
        } else if (headerLower == "te") {
            result.emplace_back(getHeaderValue(header, headerLower, TE));
        } else if (headerLower == "accept-charset") {
            result.emplace_back(getHeaderValue(header, headerLower, ACCEPTCHAR));
        } else if (headerLower == "content-type") {
            result.emplace_back(getContentType(header));
        } else if (headerLower == "accept") {
            result.emplace_back(getHeaderValue(header, headerLower, ACCEPT));
        } else if (headerLower == "accept-language") {
            // No trim for this header
            result.emplace_back(getAcceptLanguageValue(header));
        } else if (headerLower == "user-agent") {
            result.emplace_back(getUaValue(header));
        }
    }

    return header_order + "|" + boost::join(result, "/");
}

std::string payload_fingerprint(const std::string& payload) {
    if (payload.empty()) {
        return "||";
    }

    std::stringstream res;

    res << "A|" << entropy(payload) << "|" << log10length(payload);

    return res.str();
}

// ---- Submethods -----------------------------------------------------------------------

std::string fnv1a_32(const std::string& str) {
    // FNV-1a 32bit hash
    // https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
    // https://tools.ietf.org/html/draft-eastlake-fnv-03

    uint32_t hash = 2166136261U; // NOLINT(readability-magic-numbers)

    for (const char& c: str) {
        hash ^= c;
        hash *= 16777619U; // NOLINT(readability-magic-numbers)
    }

    return std::to_string(hash);
}

// Headers

std::string getHeaderValue(const std::string& header,
                           const std::string& headerName,
                           const std::map<std::string, std::string>& headerValueTable) {
    std::vector<std::string> header_values;

    boost::split(header_values, header, boost::is_any_of(":"));
    std::string val = header_values[1];
    boost::trim(val);

    std::string header_coded = HEADERS[headerName] + ":";

    std::vector<std::string> res;

    if (val.find(',') != std::string::npos) {
        // simple splitting of compound values
        if (val.find(";q=") != std::string::npos || val.find("; q=") != std::string::npos) {
            // we do not tokenize compound values with quality parameters at this moment
            std::stringstream str;
            str << std::hex << stol(fnv1a_32(val));

            return header_coded + str.str();
        }

        std::vector<std::string> t;
        boost::split(t, val, boost::is_any_of(","));

        for (std::string& j: t) {
            boost::trim_left(j);
            std::stringstream str;
            str << std::hex << stol(fnv1a_32(j));
            if (j.empty() || headerValueTable.find(j) == headerValueTable.end()) {
                return header_coded + str.str();
            }
            res.emplace_back(headerValueTable.at(j));
        }
    } else {
        std::string k;

        if (headerValueTable.find(val) != headerValueTable.end()) {
            k = headerValueTable.at(val);
        } else {
            std::stringstream str;
            str << std::hex << stol(fnv1a_32(val));
            k = str.str();
        }

        res.emplace_back(k);
    }

    return header_coded + boost::join(res, ",");
}

std::string getContentType(const std::string& header) {
    std::vector<std::string> header_values;

    boost::split(header_values, header, boost::is_any_of(":"));
    std::string val = header_values[1];
    boost::trim(val);

    std::string header_coded = HEADERS["content-type"] + ":";
    std::vector<std::string> res;

    if (val.find(',') != std::string::npos) {
        // Multiple values
        std::vector<std::string> vals;

        boost::split(vals, val, boost::is_any_of(","));

        // Loop over values
        for (std::string& val: vals) {
            boost::trim_left(val);
            std::stringstream str;
            str << std::hex;

            if (val.find(';') != std::string::npos) {
                if (val.find("boundary=") != std::string::npos) {
                    int boundIndex = val.find("boundary=");
                    int boundOffset = std::strlen("boundary=");

                    std::string valBound = val.substr(boundIndex + boundOffset);

                    str << stol(fnv1a_32(valBound));

                    return header_coded + str.str();
                }

                str << stol(fnv1a_32(val));
                res.emplace_back(str.str());

            } else {
                str << stol(fnv1a_32(val));
                std::string k = str.str();

                if (CONTENT_TYPE.find(val) != CONTENT_TYPE.end()) {
                    k = CONTENT_TYPE.at(val);
                }

                res.emplace_back(k);
            }
        }
    } else {
        // Only one value
        std::stringstream str;
        str << std::hex;

        if (val.find(';') != std::string::npos) {
            if (val.find("boundary=") == std::string::npos) {
                str << stol(fnv1a_32(val));
                return header_coded + str.str();
            }

            int boundIndex = val.find("boundary=");
            int boundOffset = std::strlen("boundary=");

            std::string valBound = val.substr(boundIndex + boundOffset);

            str << stol(fnv1a_32(valBound));

            return header_coded + str.str();
        }

        str << stol(fnv1a_32(val));
        std::string k = str.str();

        if (CONTENT_TYPE.find(val) != CONTENT_TYPE.end()) {
            k = CONTENT_TYPE.at(val);
        }

        res.emplace_back(k);
    }

    return header_coded + boost::join(res, ",");
}

std::string getAcceptLanguageValue(const std::string& header) {
    std::vector<std::string> header_values;

    boost::split(header_values, header, boost::is_any_of(":"));
    std::string val = header_values[1];

    std::string name = HEADERS["accept-language"];
    std::stringstream str;

    str << name << ":" << std::hex << stol(fnv1a_32(val));

    return str.str();
}

std::string getUaValue(const std::string& header) {
    std::vector<std::string> header_values;

    boost::split(header_values, header, boost::is_any_of(":"));
    std::string val = header_values[1];
    boost::trim(val);

    std::string name = HEADERS["user-agent"];
    std::stringstream str;

    str << name << ":" << std::hex << stol(fnv1a_32(val));

    return str.str();
}

// Checking header order - assuming that header field contains ":"
std::string getHeaderOrder(const std::vector<std::string>& headers) {
    std::vector<std::string> ret;

    for (const auto& reqline: headers) {
        std::vector<std::string> fields;
        boost::split(fields, reqline, boost::is_any_of(":"));
        std::string header = fields[0];
        std::string headerLower = boost::to_lower_copy(header);

        std::string fnv1a = fnv1a_32(header);
        std::string headerCoded;

        // Convert fnv1a_32 to hex
        std::stringstream ss;
        ss << std::hex << stol(fnv1a);
        headerCoded = ss.str();

        if (HEADERS.find(headerLower) != HEADERS.end()) {
            if (getHeaderCase(header)) {
                headerCoded = HEADERS[headerLower];
            } else {
                headerCoded = "!" + HEADERS[headerLower];
            }
        }
        ret.emplace_back(headerCoded);
    }

    return boost::join(ret, ",");
}

bool getHeaderCase(const std::string& header) {
    if (header.find('-') == std::string::npos) {
        return isupper(header[0]) != 0;
    }

    std::vector<std::string> field;
    boost::split(field, header, boost::is_any_of("-"));

    for (const auto& c: field) {
        if (islower(c[0]) != 0) {
            return false;
        }
    }

    return true;
}


// URI

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

    auto string_pos = faup_get_query_string_pos(fh);
    auto string_size = faup_get_query_string_size(fh);

    if (string_pos == -1) {
        return res;
    }

    std::string query = uri.substr(string_pos, string_size);
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

        decodedStr += static_cast<char>(c);
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

// Others

float entropy(const std::string& str) {
    float entropy = 0;

    const auto occurrences = charOccurrences(str);

    for (const auto& item: occurrences) {
        float p = item.second / static_cast<float>(str.size());
        entropy += p * std::log2f(p);
    }

    return std::roundf((-entropy) * 10) / 10; // NOLINT(readability-magic-numbers)
}

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
