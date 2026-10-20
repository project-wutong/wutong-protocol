#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
set -euo pipefail
cd "$(dirname "$0")/.."

echo "=== [1/3] Running Python + Node.js Wire, Crypto, Policy & FileCoordinator Conformance ==="
if python3 -c "import pytest; assert hasattr(pytest, 'Session')" 2>/dev/null; then
  PYTHONPATH=src python3 -m pytest tests/test_protocol.py -q
else
  PYTHONPATH=src python3 tests/test_protocol.py
fi

echo "=== [2/3] Building & Running C++23 Core, JCS, Ed25519 & Crash-Recovery Conformance ==="
if command -v cmake >/dev/null 2>&1 && [ -f /usr/include/sqlite3.h ]; then
  cmake -S reference -B /tmp/wutong-poc-conformance -DCMAKE_BUILD_TYPE=Debug
  cmake --build /tmp/wutong-poc-conformance -j2
  ctest --test-dir /tmp/wutong-poc-conformance --output-on-failure
else
  make -C reference BUILD_DIR=/tmp/wutong-poc-make clean test
fi

echo "=== [3/3] Building & Running C++23 ASan + UBSan Sanitizer Verification ==="
make -C reference BUILD_DIR=/tmp/wutong-poc-asan \
  CXXFLAGS="-std=c++23 -O1 -g -Wall -Wextra -Iinclude -fsanitize=address,undefined -fno-omit-frame-pointer" \
  LDFLAGS="-fsanitize=address,undefined" \
  clean all
ASAN_OPTIONS=detect_leaks=1 /tmp/wutong-poc-asan/wutong_core_tests
