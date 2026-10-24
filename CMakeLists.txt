cmake_minimum_required(VERSION 3.28.3)

set(PROJECT_NAME "SPRK")
set(PROJECT_VERSION "889.0.0")

set(BIN1 "client")
set(BIN2 "server")
set(BIN3 "user_keygen")

project(${PROJECT_NAME} VERSION ${PROJECT_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

option(USE_CLANG "Clang as compiler instead of g++" ON)

if(USE_CLANG)
    find_program(CXX_COMPILER NAMES clang++-18 clang++-17 clang++-16 clang++ PATHS /usr/bin /usr/local/bin)
else()
    find_program(CXX_COMPILER NAMES g++-15 g++-14 g++-13 g++ PATHS /usr/bin /usr/local/bin)
endif()

if(NOT CXX_COMPILER)
    message(FATAL_ERROR "Compiler not found! Please install Clang >= 16 or GCC >= 13.")
endif()

execute_process(
    COMMAND ${CXX_COMPILER} --version
    OUTPUT_VARIABLE COMPILER_VERSION_OUTPUT
    ERROR_QUIET
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

string(REGEX MATCH "([0-9]+\\.[0-9]+)" COMPILER_VERSION ${COMPILER_VERSION_OUTPUT})

if(USE_CLANG)
    if(COMPILER_VERSION VERSION_LESS "16.0.0")
        message(FATAL_ERROR "Compiler version Clang >= 16.0.0 is required, found version: ${COMPILER_VERSION}")
    endif()
else()
    if(COMPILER_VERSION VERSION_LESS "13.0.0")
        message(FATAL_ERROR "Compiler version GCC >= 13.0.0 is required, found version: ${COMPILER_VERSION}")
    endif()
endif()

execute_process(
    COMMAND ${CXX_COMPILER} -v
    OUTPUT_VARIABLE DETECT_COMPILER
    ERROR_VARIABLE DETECT_COMPILER
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

if(DETECT_COMPILER MATCHES "clang")
    set(CMAKE_CXX_COMPILER_ID "Clang")
elseif(DETECT_COMPILER MATCHES "gcc")
    set(CMAKE_CXX_COMPILER_ID "GNU")
else()
    message(FATAL_ERROR "Unknown compiler detected in: ${DETECT_COMPILER}")
endif()

set(CMAKE_CXX_COMPILER ${CXX_COMPILER})

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING "Build type (Debug, Release, RelWithDebInfo, MinSizeRel)" FORCE)
endif()

set(COMPILER_FLAGS_BASE "-Wall -Wextra -Wpedantic -fPIC -pthread")
set(COMPILER_FLAGS_DEBUG "-O0 -g")
set(COMPILER_FLAGS_RELEASE "-O3")
set(COMPILER_FLAGS_RELWITHDEBINFO "-O2 -g")
set(COMPILER_FLAGS_MINSIZEREL "-Os")

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS_BASE} ${COMPILER_FLAGS_DEBUG}")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -v")
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS_BASE} ${COMPILER_FLAGS_RELEASE}")
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS_BASE} ${COMPILER_FLAGS_RELWITHDEBINFO}")
elseif(CMAKE_BUILD_TYPE STREQUAL "MinSizeRel")
    set(CMAKE_CXX_FLAGS "${COMPILER_FLAGS_BASE} ${COMPILER_FLAGS_MINSIZEREL}")
endif()

option(ENABLE_DEPENDENCY_GENERATION "Enable dependency generation compile flags" OFF)
if(ENABLE_DEPENDENCY_GENERATION)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -MMD -MP")
endif()

option(ENABLE_SANITIZERS "Enable sanitizer compile flags for runtime debugging" ON)
if(ENABLE_SANITIZERS)
    set(COMMON_SANITIZERS
        "undefined" "shift" "shift-exponent" "shift-base"
        "integer-divide-by-zero" "vla-bound" "null" "return"
        "signed-integer-overflow" "bounds" "alignment" "object-size"
        "float-divide-by-zero" "float-cast-overflow" "nonnull-attribute"
        "returns-nonnull-attribute" "bool" "enum" "vptr"
        "pointer-overflow" "builtin" "address" "leak" "pointer-compare"
    )
    set(SANITIZER_FLAGS "")
    foreach(SANITIZER ${COMMON_SANITIZERS})
        list(APPEND SANITIZER_FLAGS "-fsanitize=${SANITIZER}")
    endforeach()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        list(APPEND SANITIZER_FLAGS
            "-fsanitize=shadow-call-stack"
            "-fno-sanitize-address-globals-dead-stripping"
            "-fno-sanitize-address-outline-instrumentation"
            "-fno-sanitize-address-poison-custom-array-cookie"
            "-fno-sanitize-address-use-after-scope"
            "-fno-sanitize-address-use-odr-indicator"
            "-fno-sanitize-cfi-cross-dso"
        )
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        list(APPEND SANITIZER_FLAGS
            "-fno-sanitize-address-use-after-scope"
            "-Wno-maybe-uninitialized"
            "-fsanitize=leak"
            "-fsanitize=bounds-strict"
            "-fsanitize=pointer-compare"
        )
    endif()
    string(REPLACE ";" " " SANITIZER_FLAGS "${SANITIZER_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZER_FLAGS}")
endif()

option(ENABLE_COMPILE_COMMANDS "Enable generation of compile_commands.json" ON)
if(ENABLE_COMPILE_COMMANDS)
    set(CMAKE_EXPORT_COMPILE_COMMANDS YES CACHE BOOL "Export compile commands" FORCE)
endif()

option(ENABLE_VERBOSE_MAKEFILES "Enable verbose makefiles" ON)
if(ENABLE_VERBOSE_MAKEFILES)
    set(CMAKE_VERBOSE_MAKEFILE ON CACHE BOOL "Enable verbose makefile output" FORCE)
endif()

option(ENABLE_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
if(ENABLE_WARNINGS_AS_ERRORS)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
endif()

option(ENABLE_LOGGING "Enable detailed logging" ON)
if(ENABLE_LOGGING)
    add_definitions(-DENABLE_LOGGING)
else()
    add_definitions(-DDISABLE_LOGGING)
endif()

set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(BUILD_DIR ${CMAKE_BINARY_DIR}/build)
set(BIN_DIR ${CMAKE_SOURCE_DIR}/bin)

include_directories(
    ${SRC_DIR}
    ${SRC_DIR}/shared
    ${SRC_DIR}/client
    ${SRC_DIR}/server
    ${SRC_DIR}/user_keygen
)

# OpenSSL 3.5+ -- ML-KEM / ML-DSA / SLH-DSA are native (April 2025). No
# liboqs, no oqs-provider, no patched OpenSSL build required any more.
# Ubuntu 26.04 LTS ships OpenSSL 3.5.5 in its default repositories.
set(OPENSSL_ROOT_DIR "" CACHE PATH
    "Optional custom OpenSSL 3.5+ install prefix; leave empty to use the system OpenSSL")

if(OPENSSL_ROOT_DIR)
    list(APPEND CMAKE_PREFIX_PATH "${OPENSSL_ROOT_DIR}")
    link_directories("${OPENSSL_ROOT_DIR}/lib64" "${OPENSSL_ROOT_DIR}/lib")
endif()

find_package(OpenSSL 3.5 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})
link_libraries(${OPENSSL_LIBRARIES})

set(LIBS_MAIN
ssl
crypto
pthread
PocoData
PocoJSON
PocoXML
PocoNet
PocoUtil
PocoFoundation
)

set(LIBS_${BIN1} )
set(LIBS_${BIN2} )
set(LIBS_${BIN3} )

option(BUILD_${BIN1} "Enable ${BIN1}" ON)
option(BUILD_${BIN2} "Enable ${BIN2}" ON)
option(BUILD_${BIN3} "Enable ${BIN3}" ON)

function(add_feature_executable FEATURE FEATURE_SOURCES)
    set(FEATURE_OPTION "BUILD_${FEATURE}")
    if(${${FEATURE_OPTION}})
        add_executable(${FEATURE} ${FEATURE_SOURCES})
        target_link_libraries(${FEATURE} PRIVATE ${LIBS_MAIN} ${OPENSSL_LIBRARIES})
        target_include_directories(${FEATURE} PRIVATE ${OPENSSL_INCLUDE_DIR})
        set_target_properties(${FEATURE} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR}
        )
        if(OPENSSL_ROOT_DIR)
            set_target_properties(${FEATURE} PROPERTIES
                BUILD_WITH_INSTALL_RPATH TRUE
                INSTALL_RPATH "${OPENSSL_ROOT_DIR}/lib64;${OPENSSL_ROOT_DIR}/lib"
            )
        endif()
    endif()
endfunction()

add_feature_executable(${BIN1} ${SRC_DIR}/${BIN1}/main.cpp)
add_feature_executable(${BIN2} ${SRC_DIR}/${BIN2}/main.cpp)
add_feature_executable(${BIN3} ${SRC_DIR}/${BIN3}/main.cpp)

file(MAKE_DIRECTORY ${BUILD_DIR})
file(MAKE_DIRECTORY ${BIN_DIR})

add_custom_target(my_clean
    COMMAND rm -rf ${BUILD_DIR} ${BIN_DIR}
    COMMENT "Clean build and bin directories"
)

message(STATUS "SPRK ${PROJECT_VERSION} -- OpenSSL: ${OPENSSL_VERSION} (${OPENSSL_INCLUDE_DIR})")
message(STATUS "Build ${BIN1}: ${BUILD_${BIN1}}  Build ${BIN2}: ${BUILD_${BIN2}}  Build ${BIN3}: ${BUILD_${BIN3}}")
