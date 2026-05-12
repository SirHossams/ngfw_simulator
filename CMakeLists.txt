cmake_minimum_required(VERSION 3.10)
project(NGFW_Simulator)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/build)

add_compile_options(
    -O2 
    -D_FORTIFY_SOURCE=3
    -fstack-protector-strong
    -fPIE
    -Wformat 
    -Werror=format-security
    -fcf-protection=full
    -fno-strict-aliasing
    -Wall
    -Wextra
)

add_link_options(
    -pie
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
)

add_executable(capture core/packet/capture.cpp)
target_link_libraries(capture pcap pthread)

add_executable(pep core/heart/policy-enf-point/pep.cpp)
target_link_libraries(pep pthread)

add_executable(pe core/heart/policy-engine/pe.cpp)
target_link_libraries(pe pthread)

add_executable(pehead core/heart/policy-engine/pehead.cpp)
target_link_libraries(pehead crypto ssl pthread)

add_executable(body core/heart/controller/body.cpp)
target_link_libraries(body crypto ssl pthread)

add_executable(head core/heart/controller/head.cpp)
target_link_libraries(head crypto ssl pthread)