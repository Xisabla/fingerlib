/**
 * @file dataset.hpp
 * @author Gautier Miquet
 * @brief Helpers declaration for dataset reading in tests
 * @version 0.1
 * @date 2022-04-23
 */
#ifndef TEST_DATASET_HPP
#define TEST_DATASET_HPP

#include <json.hpp>
#include <vector>

/**
 * @brief Reads a dataset from the given json file
 * 
 * @param filepath Path to the json file containing the dataset
 * @param dataset_path Path (as field list) to the desired value (eg: ".my_set.my_entries" would be { "my_set", "my_entries" })
 * @return nlohmann::json JSON Object found
 */
nlohmann::json dataset_use(const std::string& filepath, std::vector<std::string> dataset_path = {});

/**
 * @brief Checks if the given fields are contained is the given json object
 * 
 * @param j JSON object to check
 * @param fields Fields to check
 * @return false If one of the fields is missing 
 * @return true Otherwise
 */
bool dataset_contains (nlohmann::json j, std::vector<std::string> fields);

#endif // TEST_DATASET_HPP
