cmake_minimum_required(VERSION 3.11)
project(sigdream LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

string(APPEND CMAKE_C_FLAGS " -Wno-deprecated-declarations")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(DEBUG)
    string(APPEND CMAKE_C_FLAGS " -Wall -Wextra -Wpedantic -g")
endif()

include_directories(src)

add_library(sigdream_lib STATIC "src/sigdream.c")
target_link_libraries(sigdream_lib ${OPENSSL_LIBRARIES})

add_executable(sigdream "src/main.c")
target_link_libraries(sigdream sigdream_lib ${OPENSSL_LIBRARIES})
