cmake_minimum_required(VERSION 3.16)
project(PacketRush LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/O2 /W4 /arch:AVX2)
else()
    add_compile_options(-O3 -Wall -Wextra -march=native)
endif()

include_directories(include)

add_executable(packet_rush_benchmark
    evaluator/benchmark.cpp
    baseline/linear_classifier.cpp
    starter/classifier.cpp
)
