# CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(NGFW_Simulator VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include_directories(${PROJECT_SOURCE_DIR}/core/shared-headers)

find_package(Threads REQUIRED)

# Executables mapped to your project structure
add_executable(capture core/packet/capture.cpp)
target_link_libraries(capture pcap Threads::Threads)
# Note: Requires nlohmann-json installed system-wide

add_executable(pep core/heart/policy-enf-point/pep.cpp)
target_link_libraries(pep Threads::Threads)

add_executable(pe core/heart/policy-engine/pe.cpp)
target_link_libraries(pe Threads::Threads)

add_executable(controller core/heart/controller/controller.cpp)
target_link_libraries(controller Threads::Threads)