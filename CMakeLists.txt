cmake_minimum_required(VERSION 3.20)
project(NGFW_Simulator C)

file(GLOB_RECURSE SOURCES core/*.c core/packet/*.c core/pipeline/*.c core/modules/**/*.c)

add_executable(ngfw-simulator ${SOURCES})
