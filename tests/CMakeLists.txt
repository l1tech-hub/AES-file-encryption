find_package(GTest REQUIRED)
enable_testing()
include(GoogleTest)

add_executable(aes_tests
    AES_test.cpp
)
target_sources(aes_tests
    PRIVATE
        ../src/AES-CTR/AES.h
        ../src/AES-CTR/AES.c
)
target_link_libraries(aes_tests
    PRIVATE 
        aes 
        GTest::GTest
        GTest::Main
)

gtest_discover_tests(aes_tests)





