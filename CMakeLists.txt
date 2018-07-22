cmake_minimum_required(VERSION 3.10.3)
project(sigemail)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -Wall -Wextra -pedantic -pipe -march=native)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -g -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3 -flto)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c)

set(SIGEMAIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
)

add_executable(${PROJECT_NAME} ${SIGEMAIL_SOURCES})

target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")

find_package(OpenSSL)

target_link_libraries(${PROJECT_NAME} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto curl -flto)

target_include_directories(${PROJECT_NAME} PRIVATE
    src
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
)

