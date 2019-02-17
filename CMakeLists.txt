cmake_minimum_required(VERSION 3.13.0)
project(sigemail)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -pipe -march=native -fcf-protection=full -fstack-protector-strong)
set(WARNINGS -Wall -Wextra -Wpedantic -Wformat=2 -Wuninitialized -Wundef -Wcast-align -Wstrict-overflow=2 -Wwrite-strings -Wno-format-nonliteral)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -g -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${PROJECT_SOURCE_DIR}/.git")
# Update submodules as needed
    option(GIT_SUBMODULE "Check submodules during build" ON)
    if(GIT_SUBMODULE)
        message(STATUS "Submodule update")
        execute_process(COMMAND ${GIT_EXECUTABLE} submodule update --init --recursive
                        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                        RESULT_VARIABLE GIT_SUBMOD_RESULT)
        if(NOT GIT_SUBMOD_RESULT EQUAL "0")
            message(FATAL_ERROR "git submodule update --init failed with ${GIT_SUBMOD_RESULT}, please checkout submodules")
        endif()
    endif()
endif()

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/spdlog/CMakeLists.txt")
    message(FATAL_ERROR "The submodules were not downloaded! GIT_SUBMODULE was turned off or failed. Please update submodules and try again.")
endif()

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/extern/spdlog)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_LINK_WHAT_YOU_USE ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.67 REQUIRED COMPONENTS system unit_test_framework serialization)

find_package(OpenSSL 1.1.1 REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

set(CLIENT_MAIN_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client/main.cpp
)

set(SERVER_MAIN_SOURCE
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/main.cpp
)

set(SIGEMAIL_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dh.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/kdf.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/encrypt.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/sign.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/session.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/message.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/hash.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/db_utils.cpp
)

set(CLIENT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client/client_network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client/client_state.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client/device.cpp
)

set(SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/server_network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/listener.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/server_state.cpp
)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/encrypt_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/sign_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/protocol_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/session_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/hash_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/message_serialize_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/server_db_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/client_db_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/network_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/high_level_test.cpp
)

set(INCLUDE_DIRS
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519/ed25519/additions/generalized
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519/ed25519/additions
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519/ed25519/sha512
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519/ed25519
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/libsignal-protocol-c/src/curve25519
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/spdlog/include
)

set(SOURCE_LIBRARY _${PROJECT_NAME})
set(CLIENT_LIBRARY _${PROJECT_NAME}_client)
set(SERVER_LIBRARY _${PROJECT_NAME}_server)

add_library(sqlite3 OBJECT
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/sqlite3/sqlite3.c
    ${CMAKE_CURRENT_SOURCE_DIR}/extern/sqlite3/sqlite3.h
)
target_compile_options(sqlite3 PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(sqlite3 PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(sqlite3 PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_DEFAULT_FOREIGN_KEYS=1)

add_library(${SOURCE_LIBRARY} OBJECT ${SIGEMAIL_SOURCES})
add_library(${CLIENT_LIBRARY} OBJECT ${CLIENT_SOURCES})
add_library(${SERVER_LIBRARY} OBJECT ${SERVER_SOURCES})

target_compile_options(${SOURCE_LIBRARY}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SOURCE_LIBRARY} PUBLIC ${INCLUDE_DIRS})

target_compile_options(${CLIENT_LIBRARY}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${CLIENT_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${CLIENT_LIBRARY} PUBLIC ${INCLUDE_DIRS})

target_compile_options(${SERVER_LIBRARY}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SERVER_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SERVER_LIBRARY} PUBLIC ${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${CLIENT_MAIN_SOURCE} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${CLIENT_LIBRARY}> $<TARGET_OBJECTS:sqlite3>)
target_compile_options(${PROJECT_NAME}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>" "$<$<CONFIG:DEBUG>:NO_SSL_VERIFY>")
target_include_directories(${PROJECT_NAME} PRIVATE ${INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES} Boost::serialization spdlog)
target_link_options(${PROJECT_NAME} PRIVATE "$<$<CONFIG:RELEASE>:-s>")

set(SERVER ${PROJECT_NAME}_server)
add_executable(${SERVER} ${SERVER_MAIN_SOURCE} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${SERVER_LIBRARY}> $<TARGET_OBJECTS:sqlite3>)
target_compile_options(${SERVER}
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SERVER} PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SERVER} PRIVATE ${INCLUDE_DIRS})
target_link_libraries(${SERVER} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES} Boost::serialization spdlog)
target_link_options(${SERVER} PRIVATE "$<$<CONFIG:RELEASE>:-s>")

enable_testing()

add_executable(test_binary ${TEST_SOURCES} ${Boost_INCLUDE_DIRS} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${CLIENT_LIBRARY}> $<TARGET_OBJECTS:${SERVER_LIBRARY}> $<TARGET_OBJECTS:sqlite3>)
target_compile_options(test_binary
    PRIVATE ${WARNINGS}
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>" "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(test_binary PRIVATE "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(test_binary PRIVATE ${INCLUDE_DIRS})
add_test(NAME encryption_tests COMMAND test_binary -t encryption_tests)
add_test(NAME signing_tests COMMAND test_binary -t sign_tests)
add_test(NAME hash_tests COMMAND test_binary -t hash_tests)
add_test(NAME protocol_tests COMMAND test_binary -t protocol_tests)
add_test(NAME session_tests COMMAND test_binary -t session_tests)
add_test(NAME serialization_tests COMMAND test_binary -t serialization_tests)
add_test(NAME server_db_tests COMMAND test_binary -t server_db_tests)
add_test(NAME client_db_tests COMMAND test_binary -t client_db_tests)
add_test(NAME network_tests COMMAND test_binary -t network_tests)
add_test(NAME high_level_tests COMMAND test_binary -t high_level_tests)

target_link_libraries(test_binary PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES} Boost::unit_test_framework Boost::serialization spdlog)

target_include_directories(test_binary PRIVATE
    src/test
)

