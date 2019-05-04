project(cipherlib)
cmake_minimum_required(VERSION 2.8.8)

set(CMAKE_C_FLAGS 
    "${CMAKE_C_FLAGS} --std=gnu99 -W -Wall -Wextra -Wno-aggregate-return -Wno-suggest-attribute=format -Wno-undef -fms-extensions -Wno-pointer-sign -g -O0")

enable_testing()

add_subdirectory(lib_src)
add_subdirectory(test)
