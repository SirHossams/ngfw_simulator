cmake_minimum_required(VERSION 3.10)
project(NGFW_Simulator)

set(CMAKE_CXX_STANDARD 17)

# Ensure the build directory exists for outputs
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

# Add Executables
add_executable(capture core/packet/capture.cpp)
target_link_libraries(capture pcap pthread)

add_executable(pep core/heart/policy-enf-point/pep.cpp)
target_link_libraries(pep pthread)

add_executable(pe core/heart/policy-engine/pe.cpp)
target_link_libraries(pe pthread)

# New: Module Head
add_executable(pehead core/heart/policy-engine/pehead.cpp)
target_link_libraries(pehead crypto ssl pthread)

# New: Controller Body
add_executable(body core/heart/controller/body.cpp)
target_link_libraries(body crypto ssl pthread)

# New: Controller Head
add_executable(head core/heart/controller/head.cpp)
target_link_libraries(head crypto ssl pthread)