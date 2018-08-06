cmake_minimum_required(VERSION 3.9.4)
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
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(SIGEMAIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol.cpp
)

add_executable(${PROJECT_NAME} ${SIGEMAIL_SOURCES})

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    message(STATUS "IPO / LTO enabled")
    set_property(TARGET ${PROJECT_NAME} PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")

find_package(OpenSSL 1.1.0 REQUIRED)
find_package(Boost 1.67 REQUIRED COMPONENTS unit_test_framework)

target_link_libraries(${PROJECT_NAME} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto curl)

target_include_directories(${PROJECT_NAME} PRIVATE
    src
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/protocol.cpp
)

enable_testing()

add_executable(test_binary ${TEST_SOURCES} ${Boost_INCLUDE_DIRS})
add_test(NAME test_binary COMMAND test_binary)

add_custom_command(TARGET test_binary
                   POST_BUILD
                   COMMAND ctest -C $<CONFIGURATION> --output-on-failure)

target_compile_options(test_binary PRIVATE "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(test_binary PRIVATE "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(test_binary PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")

target_link_libraries(test_binary PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto curl ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

target_include_directories(test_binary PRIVATE
    src
    src/test
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
)

