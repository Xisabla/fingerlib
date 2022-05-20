/**
 * @file dataset.cpp
 * @author Gautier Miquet
 * @brief Helpers implementation for dataset reading in tests
 * @version 0.1.0
 * @date 2022-04-23
 *
 */
#include <fstream>
#include <stdexcept>
#include <test/dataset.hpp>

nlohmann::json dataset_use(const std::string& filepath,
                           const std::vector<std::string> dataset_path) {
    nlohmann::json j;

    std::ifstream dataset_file(filepath);

    // Error if file can't be opened
    if (!dataset_file.is_open()) {
        throw std::runtime_error("Unable to open dataset: " + filepath);
    }

    dataset_file >> j;

    for (auto& field: dataset_path) {
        // Error if field can't be reached
        if (j.find(field) == j.end())
            throw std::runtime_error("Field " + field + " isn't reachable in " + filepath);

        j = j[field];
    }

    return j;
}

bool dataset_contains(nlohmann::json j, const std::vector<std::string> fields) {
    for (auto& field: fields) {
        if (j.find(field) == j.end()) return false;
    }

    return true;
}
