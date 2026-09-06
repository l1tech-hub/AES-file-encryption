cmake_minimum_required(VERSION 3.20)

project(AES-file-encryption)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)

find_package(GTest REQUIRED)
include(GoogleTest)


# LIBRARIES #

add_library(aes STATIC AES.c)



# TESTS #

add_executable(aes_tests
    AES_test.cpp
)
target_link_libraries(aes_tests
    PRIVATE 
        aes 
        GTest::GTest
        GTest::Main
)

gtest_discover_tests(aes_tests)





