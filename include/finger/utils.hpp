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
std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }
    return tokens;
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
