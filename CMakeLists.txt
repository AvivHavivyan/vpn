cmake_minimum_required(VERSION 3.20)
project(vpn C)

set(CMAKE_C_STANDARD 99)
link_libraries(ws2_32)
link_libraries(OpenSSL::Crypto)
set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

add_executable(vpn main.c main.h utils.c utils.h)
target_link_libraries(vpn OpenSSL::Crypto)
