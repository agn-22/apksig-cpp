cmake_minimum_required(VERSION 3.10)
project(apksig CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

add_subdirectory(external/fmt)
add_subdirectory(external/mbedtls)

add_executable(app main.cpp src/apksig.cpp)
target_link_libraries(app PRIVATE fmt::fmt mbedcrypto)
target_compile_options(app PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast -Wnon-virtual-dtor -Wformat=2)
target_include_directories(app PRIVATE include)
