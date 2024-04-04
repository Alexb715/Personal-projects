cmake_minimum_required(VERSION 3.27)
project(Login_System)

set(CMAKE_CXX_STANDARD 20)

add_executable(Login_System main.cpp)
find_package(OpenSSL REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(Login_System PRIVATE OpenSSL::SSL OpenSSL::Crypto sqlite3)
