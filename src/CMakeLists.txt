add_library(aes
    STATIC 
        AES-CTR/AES.c
)

target_include_directories(aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/AES-CTR)

