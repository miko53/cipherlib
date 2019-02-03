project(cipherlib)
cmake_minimum_required(VERSION 2.8.8)

set(CIPHER_LIB_SRC_FILES aes/aes.cpp)
set(CIPHER_LIB_SRC_FILES des/des.c)
set(CIPHER_LIB_SRC_FILES des/listeSimple.c)

add_library(cipher SHARED ${CIPHER_LIB_SRC_FILES})
