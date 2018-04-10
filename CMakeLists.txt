cmake_minimum_required(VERSION 3.10.3)
project(sigemail)

INCLUDE(CheckSymbolExists)
INCLUDE(CheckCCompilerFlag)

CHECK_SYMBOL_EXISTS(memset_s "string.h" HAVE_MEMSET_S)

IF(CMAKE_SYSTEM_NAME MATCHES "Windows")
	CHECK_SYMBOL_EXISTS(SecureZeroMemory "Windows.h;WinBase.h" HAVE_SECUREZEROMEMORY)
ENDIF(CMAKE_SYSTEM_NAME MATCHES "Windows")

IF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fmessage-length=0 -Wall -Wmissing-field-initializers -Wno-missing-braces -Wparentheses")
ENDIF(CMAKE_COMPILER_IS_GNUCC OR CMAKE_C_COMPILER_ID MATCHES "Clang")

IF(CMAKE_COMPILER_IS_GNUCC)
	CHECK_C_COMPILER_FLAG("-Wsign-conversion" GCC_WARN_SIGN_CONVERSION)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-compare")
	IF(GCC_WARN_SIGN_CONVERSION)
		SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wsign-conversion")
	ENDIF(GCC_WARN_SIGN_CONVERSION)
ENDIF(CMAKE_COMPILER_IS_GNUCC)

IF(CMAKE_C_COMPILER_ID MATCHES "Clang")
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wswitch -Wunused-variable -Wunused-value -Wshadow -Wint-conversion -Wpointer-sign -Wprotocol -Wshorten-64-to-32")
ENDIF(CMAKE_C_COMPILER_ID MATCHES "Clang")

IF(HAVE_MEMSET_S)
	SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DHAVE_MEMSET_S=1")
ENDIF(HAVE_MEMSET_S)

if(BUILD_SHARED_LIBS)
	find_library(M_LIB m)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(
	.
	libsignal-protocol-c/src/curve25519/ed25519/nacl_includes
	libsignal-protocol-c/src/curve25519/ed25519/additions
	libsignal-protocol-c/src/curve25519/ed25519/sha512
	libsignal-protocol-c/src/curve25519/ed25519
	libsignal-protocol-c/src/curve25519
)

add_subdirectory(libsignal-protocol-c/src/curve25519)

set(MAIN
    main.c
    test.c
    test.h
)

add_executable(sigemail ${MAIN})

if(BUILD_SHARED_LIBS)
	target_link_libraries(sigemail ${M_LIB})
endif()

