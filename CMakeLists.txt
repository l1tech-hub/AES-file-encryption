cmake_minimum_required(VERSION 3.20)

project(AES-file-encryption)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)



add_subdirectory(src)



option(BUILD_TESTS "Build tests" ON)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

