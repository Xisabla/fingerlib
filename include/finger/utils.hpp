#ifndef INCLUDE_FINGER_UTILS
#define INCLUDE_FINGER_UTILS

#include <map>
#include <vector>
#include <string>
#include <sstream>

/**
 * @brief Get the equivalent of Python Counter object
 * 
 * @param items The items to be counted
 * @return std::map<std::string, int> 
 */
std::map<std::string, int> getCounter(const std::vector<std::string>& items)
{
    std::map<std::string, int> counter;
    for (auto& item : items)
    {
        if (counter.find(item) == counter.end())
        {
            counter[item] = 1;
        }
        else
        {
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
 * @return std::vector<std::string> 
 */
std::vector<std::string> split(const std::string& str, char delimiter)
{
    std::vector<std::string> tokens;
    std::string token;
    std::stringstream tokenStream(str);
    while (std::getline(tokenStream, token, delimiter))
    {
        tokens.push_back(token);
    }
    return tokens;
}

/**
 * @brief Uppercase a string
 * 
 * @param str 
 * @return std::string 
 */
std::string toUpper(const std::string& str)
{
    std::string upper;
    for (const auto& item : str)
    {
        upper += toupper(item);
    }
    return upper;
}

/**
 * @brief Strip a string of its whitespaces
 * 
 * @param str 
 * @return std::string 
 */
std::string strip(const std::string& str)
{
    auto start_it = str.begin();
    auto end_it = str.rbegin();
    while (std::isspace(*start_it))
        ++start_it;
    while (std::isspace(*end_it))
        ++end_it;
    return std::string(start_it, end_it.base());
}

#endif /* INCLUDE_FINGER_UTILS */
