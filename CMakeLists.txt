cmake_minimum_required(VERSION 3.20)
project(NGFW_Simulator CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE SOURCES core/*.cpp modules/**/*.cpp)

include_directories(
    core
    core/shared-headers
    modules/module1/headers
    modules/module2/headers
)

add_executable(ngfw-simulator ${SOURCES})

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -O2
        -Wall
        -Wextra
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
        -fPIC
        -fno-omit-frame-pointer
        -fvisibility=hidden
        -ffunction-sections
        -fdata-sections
    )

    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-z,relro,-z,now -pie --gc-sections")
endif()