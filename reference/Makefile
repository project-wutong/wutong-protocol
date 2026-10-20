# SPDX-License-Identifier: AGPL-3.0-only
# Portable Makefile for Wutong C++23 Reference Core (works when CMake is unavailable)
CXX ?= g++
CXXFLAGS ?= -std=c++23 -O2 -g -Wall -Wextra -Iinclude
LDFLAGS ?=
SQLITE_LIB := $(shell if [ -f /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 ]; then echo /usr/lib/x86_64-linux-gnu/libsqlite3.so.0; else echo -lsqlite3; fi)
LIBS := $(SQLITE_LIB) -lcrypto
BUILD_DIR ?= build

all: $(BUILD_DIR)/wutong_core_tests $(BUILD_DIR)/wutong_digest $(BUILD_DIR)/wutong_verify_wire

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/core.o: src/core.cpp include/wutong/core.hpp include/wutong/sqlite3_compat.hpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c src/core.cpp -o $(BUILD_DIR)/core.o

$(BUILD_DIR)/wutong_core_tests: tests/test_core.cpp $(BUILD_DIR)/core.o
	$(CXX) $(CXXFLAGS) tests/test_core.cpp $(BUILD_DIR)/core.o -o $(BUILD_DIR)/wutong_core_tests $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/wutong_digest: tools/digest.cpp $(BUILD_DIR)/core.o
	$(CXX) $(CXXFLAGS) tools/digest.cpp $(BUILD_DIR)/core.o -o $(BUILD_DIR)/wutong_digest $(LDFLAGS) $(LIBS)

$(BUILD_DIR)/wutong_verify_wire: tools/verify_wire.cpp $(BUILD_DIR)/core.o
	$(CXX) $(CXXFLAGS) tools/verify_wire.cpp $(BUILD_DIR)/core.o -o $(BUILD_DIR)/wutong_verify_wire $(LDFLAGS) $(LIBS)

test: all
	$(BUILD_DIR)/wutong_core_tests
	python3 tests/test_crosslang.py $(BUILD_DIR)/wutong_digest $(BUILD_DIR)/wutong_verify_wire
	python3 tests/test_schema.py

clean:
	rm -rf $(BUILD_DIR)
