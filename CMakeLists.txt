cmake_minimum_required(VERSION 3.9.4)
project(sigemail)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -Wall -Wextra -Wpedantic -Wformat=2 -Wuninitialized -Wundef -Wfloat-equal -Wshadow -Wcast-align -Wstrict-overflow=2 -Wwrite-strings -pipe -march=native)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -g -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/libsignal-protocol-c)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(Boost 1.67 REQUIRED COMPONENTS unit_test_framework serialization)

set(MAIN_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
)

set(SIGEMAIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/key_pack.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user_record.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device_record.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device.cpp
)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/encrypt_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/sign_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/protocol_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/session_test.cpp
)

set(SOURCE_LIBRARY _${PROJECT_NAME})

add_library(${SOURCE_LIBRARY} ${SIGEMAIL_SOURCES})

target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")

target_link_libraries(${SOURCE_LIBRARY} PUBLIC signal-protocol-c OpenSSL::SSL OpenSSL::Crypto curl ${Boost_SERIALIZATION_LIBRARY})

target_include_directories(${SOURCE_LIBRARY} PUBLIC
    src
    libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    libsignal-protocol-c/src/curve25519/ed25519/additions
    libsignal-protocol-c/src/curve25519/ed25519/sha512
    libsignal-protocol-c/src/curve25519/ed25519
    libsignal-protocol-c/src/curve25519
)

add_executable(${PROJECT_NAME} ${MAIN_SOURCE})
target_link_libraries(${PROJECT_NAME} PRIVATE ${SOURCE_LIBRARY})

enable_testing()

add_executable(test_binary ${TEST_SOURCES} ${Boost_INCLUDE_DIRS})
add_test(NAME encryption_tests COMMAND test_binary -p -t encryption_tests)
add_test(NAME signing_tests COMMAND test_binary -p -t sign_tests)
add_test(NAME protocol_tests COMMAND test_binary -p -t protocol_tests)
add_test(NAME session_tests COMMAND test_binary -p -t session_tests)

target_link_libraries(test_binary PRIVATE ${SOURCE_LIBRARY} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

target_include_directories(test_binary PRIVATE
    src/test
)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    message(STATUS "IPO / LTO enabled")
    set_target_properties(${SOURCE_LIBRARY} ${PROJECT_NAME} test_binary PROPERTIES 
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE 
        POSITION_INDEPENDENT_CODE TRUE
    )
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

