cmake_minimum_required(VERSION 3.25)

project (cryptoutils VERSION 1.0 LANGUAGES CXX C)

list(APPEND SOURCES
    src/algos.cpp
    src/handlers.cpp
    src/main.cpp
)

set(CMAKE_CXX_FLAGS "-Wall -Wextra -Wconversion -std=c++17")
set(CMAKE_CXX_COMPILER "g++")

add_executable(cryptoutils ${SOURCES})
target_include_directories(cryptoutils PUBLIC include)
target_link_libraries(cryptoutils PRIVATE m fmt)
