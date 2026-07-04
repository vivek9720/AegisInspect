#!/bin/bash -eu
ROOT="${SRC:-$(pwd)}"
cd "$ROOT"
: "${OUT:?OUT must be set}"
COMMON_SRC="src/core/types.cpp src/core/exposure_catalog.cpp src/packet/packet.cpp src/ioc/ioc.cpp src/rules/rules.cpp src/policy/policy.cpp"
CXX_BIN="${CXX:-clang++}"
CXX_FLAGS="${CXXFLAGS:-}"
FUZZ_ENGINE="${LIB_FUZZING_ENGINE:-}"
for target in packet_fuzzer ioc_fuzzer rules_fuzzer policy_fuzzer; do
  "$CXX_BIN" $CXX_FLAGS -std=c++17 -Iinclude fuzz/${target}.cc $COMMON_SRC $FUZZ_ENGINE -o "$OUT/${target}"
done
