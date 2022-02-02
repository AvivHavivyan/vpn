cmake_minimum_required(VERSION 3.20)
project(vpn C)

set(CMAKE_C_STANDARD 99)
link_libraries(ws2_32)

add_executable(vpn main.c)
