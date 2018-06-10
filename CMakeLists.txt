cmake_minimum_required(VERSION 3.10.3)
project(sigemail)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS "-std=c++17 -Wall -Wextra -Wpedantic -pipe -march=native")
set(CMAKE_CXX_FLAGS_DEBUG "-g -Og")
set(CMAKE_CXX_FLAGS_RELEASE "-s -O3 -DNDEBUG -flto")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-g -O3 -DNDEBUG -flto")
set(CMAKE_CXX_FLAGS_MINSIZEREL "-s -Os -DNDEBUG -flto")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c)

set(SIGEMAIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.h
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
)

add_executable(${PROJECT_NAME} ${SIGEMAIL_SOURCES})

find_package(OpenSSL)

target_link_libraries(${PROJECT_NAME} signal-protocol-c OpenSSL::SSL OpenSSL::Crypto curl)

target_include_directories(${PROJECT_NAME} PRIVATE
    src
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
    #${CMAKE_CURRENT_SOURCE_DIR}/src
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519/ed25519/additions
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519/ed25519/sha512
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519/ed25519
    #${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c/src/curve25519
)

