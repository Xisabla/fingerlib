/**
 * @file basic.cpp
 * @author Gautier Miquet
 * @brief Very first and basic test
 * @version 1.0
 * @date 2022-03-03
 */
#include <finger/fingerprint.hpp>
#include <finger/utils.hpp>

#include <CppUTest/CommandLineTestRunner.h>
#include <CppUTest/TestHarness.h>

TEST_GROUP(FirstTestGroup) { };

TEST(FirstTestGroup, FirstTest) { CHECK(true); }

int main(int argc, char** argv) {
    CommandLineTestRunner::RunAllTests(argc, argv);
}