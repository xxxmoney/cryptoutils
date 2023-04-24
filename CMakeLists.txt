cmake_minimum_required(VERSION 3.25)

project (cryptoutils VERSION 1.0 LANGUAGES CXX C)

list(APPEND CMAKE_PREFIX_PATH "C:/fmt")

find_package(FMT REQUIRED)

list(APPEND SOURCES
    src/algos.cpp
    src/handlers.cpp
    src/main.cpp
)

set(gcc_like_cxx "$<COMPILE_LANG_AND_ID:CXX,ARMClang,AppleClang,Clang,GNU,LCC>")
set(msvc_cxx "$<COMPILE_LANG_AND_ID:CXX,MSVC>")

set(CMAKE_BUILD_TYPE Release)

add_executable(cryptoutils ${SOURCES})
target_include_directories(cryptoutils PUBLIC include)
target_link_libraries(cryptoutils PRIVATE fmt::fmt)
target_compile_options(cryptoutils INTERFACE "$<${gcc_like_cxx}:-Wall;-Wextra;-Wconversion>"
                                             "$<${msvc_cxx}:-W3>")
set_property(TARGET cryptoutils PROPERTY CXX_STANDARD 20)
