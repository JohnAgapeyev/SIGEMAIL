cmake_minimum_required(VERSION 3.13.0)
project(sigemail)

if("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")
    message(FATAL_ERROR "You cannot build in a source directory (or any directory with a CMakeLists.txt file). Please use the bin subdirectory provided by the project and remove CMakeCache.txt and CMakeFiles.")
endif("${PROJECT_SOURCE_DIR}" STREQUAL "${PROJECT_BINARY_DIR}")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(CMAKE_CXX_FLAGS_DEBUG "")
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "")
set(CMAKE_CXX_FLAGS_MINSIZEREL "")

set(BASE_COMPILE_OPTIONS -Wall -Wextra -Wpedantic -Wformat=2 -Wuninitialized -Wundef -Wcast-align -Wstrict-overflow=2 -Wwrite-strings -Wno-format-nonliteral -pipe -march=native)
set(DEBUG_OPTIONS ${BASE_COMPILE_OPTIONS} -g -O0)
set(RELEASE_OPTIONS ${BASE_COMPILE_OPTIONS} -s -O3)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_LINK_WHAT_YOU_USE ON)

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

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost 1.67 REQUIRED COMPONENTS system unit_test_framework)

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
    ${CMAKE_CURRENT_SOURCE_DIR}/src/key_pack.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/user_record.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device_record.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/device.cpp
)

set(CLIENT_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/client/client_network.cpp
)

set(SERVER_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/server_network.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/server/listener.cpp
)

set(TEST_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/encrypt_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/sign_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/protocol_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/session_test.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/test/hash_test.cpp
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
)

set(SOURCE_LIBRARY _${PROJECT_NAME})
set(CLIENT_LIBRARY _${PROJECT_NAME}_client)
set(SERVER_LIBRARY _${PROJECT_NAME}_server)

add_library(${SOURCE_LIBRARY} OBJECT ${SIGEMAIL_SOURCES})
add_library(${CLIENT_LIBRARY} OBJECT ${CLIENT_SOURCES})
add_library(${SERVER_LIBRARY} OBJECT ${SERVER_SOURCES})

target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SOURCE_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SOURCE_LIBRARY} PUBLIC ${INCLUDE_DIRS})

target_compile_options(${CLIENT_LIBRARY} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${CLIENT_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${CLIENT_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${CLIENT_LIBRARY} PUBLIC ${INCLUDE_DIRS})

target_compile_options(${SERVER_LIBRARY} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${SERVER_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SERVER_LIBRARY} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SERVER_LIBRARY} PUBLIC ${INCLUDE_DIRS})

add_executable(${PROJECT_NAME} ${CLIENT_MAIN_SOURCE} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${CLIENT_LIBRARY}>)
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS})
target_link_libraries(${PROJECT_NAME} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES})
target_link_options(${PROJECT_NAME} PUBLIC "$<$<CONFIG:RELEASE>:-s>")

set(SERVER ${PROJECT_NAME}_server)
add_executable(${SERVER} ${SERVER_MAIN_SOURCE} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${SERVER_LIBRARY}>)
target_compile_options(${SERVER} PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(${SERVER} PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(${SERVER} PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(${SERVER} PUBLIC ${INCLUDE_DIRS})
target_link_libraries(${SERVER} PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES})
target_link_options(${SERVER} PUBLIC "$<$<CONFIG:RELEASE>:-s>")

enable_testing()

add_executable(test_binary ${TEST_SOURCES} ${Boost_INCLUDE_DIRS} $<TARGET_OBJECTS:${SOURCE_LIBRARY}> $<TARGET_OBJECTS:${CLIENT_LIBRARY}> $<TARGET_OBJECTS:${SERVER_LIBRARY}>)
target_compile_options(test_binary PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>")
target_compile_options(test_binary PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")
target_compile_definitions(test_binary PUBLIC "$<$<CONFIG:RELEASE>:NDEBUG>")
target_include_directories(test_binary PUBLIC ${INCLUDE_DIRS})
add_test(NAME encryption_tests COMMAND test_binary -p -t encryption_tests)
add_test(NAME signing_tests COMMAND test_binary -p -t sign_tests)
add_test(NAME hash_tests COMMAND test_binary -p -t hash_tests)
add_test(NAME protocol_tests COMMAND test_binary -p -t protocol_tests)
add_test(NAME session_tests COMMAND test_binary -p -t session_tests)

target_link_libraries(test_binary PRIVATE signal-protocol-c OpenSSL::SSL OpenSSL::Crypto CURL::libcurl Threads::Threads ${Boost_LIBRARIES} Boost::unit_test_framework)

target_include_directories(test_binary PRIVATE
    src/test
)

include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

if(ipo_supported)
    set_target_properties(${SOURCE_LIBRARY} ${CLIENT_LIBRARY} ${SERVER_LIBRARY} ${PROJECT_NAME} ${SERVER} test_binary PROPERTIES
        INTERPROCEDURAL_OPTIMIZATION_RELEASE TRUE
)
else()
    message(STATUS "IPO / LTO not supported: <${error}>")
endif()

