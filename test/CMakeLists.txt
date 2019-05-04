
include_directories(${CIPHER_INCLUDE_DIR})

# add_executable(cipher_test main.c)
# target_link_libraries(cipher_test cipher)
# 
# add_executable(cipher_test1 main_cryp.c)
# target_link_libraries(cipher_test1 cipher)

add_executable(des_tests des_tst_main.c)
target_link_libraries(des_tests cipher)

add_executable(aes_tests aes_tst_main.c)
target_link_libraries(aes_tests cipher)

add_executable(aes_tst_block_ecb_main aes_tst_block_ecb_main.c)
target_link_libraries(aes_tst_block_ecb_main cipher)

add_executable(aes_tst_block_cbc aes_tst_block_cbc.c)
target_link_libraries(aes_tst_block_cbc cipher)

add_test(test_des des_tests)
add_test(test_aes aes_tests)
add_test(test_aes aes_tst_block_ecb_main)
add_test(test_aes aes_tst_block_cbc)
