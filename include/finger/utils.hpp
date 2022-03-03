/**
 * @file utils.hpp
 * @author Paul Bucamp
 * @brief Utilities and helpers methods such a string manipulation
 * @version 0.1
 * @date 2022-03-03
 */
#ifndef FINGER_UTILS_HPP
#define FINGER_UTILS_HPP

#include <map>
#include <sstream>
#include <string>
#include <vector>

/**
 * @brief Count the number of each element in a vector
 *
 * @ref https://docs.python.org/3/library/collections.html#collections.Counter
 * @param items The items to be counted
 * @return A mapping of each element and their occurrence count
 */
std::map<std::string, int> getCounter(const std::vector<std::string>& items) {
    std::map<std::string, int> counter;
    for (const auto& item: items) {
        if (counter.find(item) == counter.end()) {
            counter[item] = 1;
        } else {
            counter[item]++;
        }
    }
    return counter;
}

/**
 * @brief Split a string into a vector of strings based on a delimiter
 *
 * @param str The string to be split
 * @param delimiter The delimiter to split the string by
 * @return A vector containing each segment of the split string
 */
std::vector<std::string> split(std::string str, const std::string& delimiter) {
    std::vector<std::string> tokens;
    size_t pos = 0;
    std::string token;
    while ((pos = str.find(delimiter)) != std::string::npos) {
        token = str.substr(0, pos);
        tokens.push_back(token);
        str.erase(0, pos + delimiter.length());
    }
    tokens.push_back(str);
    return tokens;
}

/**
 * @brief Join a vector of strings into a string based on a delimiter
 *
 * @param strings The strings to be joined
 * @param delimiter The delimiter to join the strings by
 * @return std::string
 */
std::string join(std::vector<std::string> strings, const std::string& delimiter) {
    std::stringstream ss;

    for (size_t i = 0; i < strings.size(); i++) {
        ss << strings[i];
        if (i != strings.size() - 1) {
            {
                ss << delimiter;
            }
        }
    }
    return ss.str();
}

/**
 * @brief Uppercase a string
 */
std::string toUpper(const std::string& str) {
    std::string upper;
    for (const auto& item: str) {
        upper += toupper(item);
    }
    return upper;
}

/**
 * @brief Lowercase a string
 *
 * @param str
 * @return std::string
 */
std::string toLower(const std::string& str) {
    std::string upper;
    for (const auto& item: str) {
        upper += tolower(item);
    }
    return upper;
}

/**
 * @brief Strip a string of its whitespaces
 */
std::string strip(const std::string& str) {
    auto start_it = str.begin();
    auto end_it = str.rbegin();
    while (std::isspace(*start_it) != 0) {
        ++start_it;
    }
    while (std::isspace(*end_it) != 0) {
        ++end_it;
    }
    return std::string(start_it, end_it.base());
}

#endif /* FINGER_UTILS_HPP */
