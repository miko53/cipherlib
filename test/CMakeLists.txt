
include_directories(${CIPHER_INCLUDE_DIR})

add_executable(cipher_test main.c)
target_link_libraries(cipher_test cipher)

add_executable(cipher_test1 main_cryp.c)
target_link_libraries(cipher_test1 cipher)
