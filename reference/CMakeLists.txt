# SPDX-License-Identifier: AGPL-3.0-only
cmake_minimum_required(VERSION 3.22)
project(WutongCorePoc VERSION 0.1.2 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(wutong_core src/core.cpp)
target_include_directories(wutong_core PUBLIC include)
target_link_libraries(wutong_core PUBLIC SQLite::SQLite3 OpenSSL::Crypto)

add_executable(wutong_core_tests tests/test_core.cpp)
target_link_libraries(wutong_core_tests PRIVATE wutong_core)
enable_testing()
add_test(NAME wutong_core_tests COMMAND wutong_core_tests)

add_executable(wutong_digest tools/digest.cpp)
target_link_libraries(wutong_digest PRIVATE wutong_core)

add_executable(wutong_verify_wire tools/verify_wire.cpp)
target_link_libraries(wutong_verify_wire PRIVATE wutong_core)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(
    NAME wutong_crosslang_digest
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/test_crosslang.py
            $<TARGET_FILE:wutong_digest>
            $<TARGET_FILE:wutong_verify_wire>
  )
  add_test(
    NAME wutong_schema_contract
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/test_schema.py
  )
endif()
