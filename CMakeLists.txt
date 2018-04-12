cmake_minimum_required(VERSION 3.10.3)
project(sigemail)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS "-std=c11 -Wall -Wextra -pedantic -pipe -march=native")
set(CMAKE_C_FLAGS_DEBUG "-g -Og")
set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG")

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(libsignal-protocol-c)

set(SIGEMAIL_SOURCES
    src/main.c
    src/test.c
    src/test.h
)

add_executable(sigemail ${SIGEMAIL_SOURCES})

target_link_libraries(sigemail signal-protocol-c sodium curl)

target_include_directories(sigemail PRIVATE
    src
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
)
