#!/bin/bash -eu

# Install additional dependencies if needed (ClusterFuzzLite base has most, but ensure)
apt-get update && apt-get install -y meson ninja-build python3 clang llvm

# Do NOT override CFLAGS/CXXFLAGS/LDFLAGS here, as ClusterFuzzLite already sets appropriate flags
# like -fsanitize=address,undefined,fuzzer-no-link for compilation.
# Overriding causes conflicts (e.g., duplicate/mismatched sanitizer flags) that break Meson's compiler check.

# Set CC and CXX to clang if not already (ClusterFuzzLite usually does this)
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"

# Build dependencies if not subprojects (assuming wrap files handle them)
cd $SRC/libcss
meson subprojects update || true  # If using subprojects/wraps for libwapcaplet, libparserutils

# Clean and setup Meson with fuzzing enabled
rm -rf build || true
meson setup build \
  --default-library=static \
  --buildtype=plain \
  -Db_sanitize=none \
  -Db_lundef=false \
  -Dfuzzing=true

# Build
ninja -C build -j$(nproc)

# Install if needed (but for fuzzing, probably not necessary since static)
ninja -C build install || true

# Copy the fuzzer binary to $OUT
cp build/css_parse_fuzzer $OUT/

# Optional: Build seed corpus (zip test data or examples)
mkdir -p css_parse_fuzzer_seed_corpus
# Add some seed files, e.g., from test data
cp -r test/data/* css_parse_fuzzer_seed_corpus/ || true  # Adjust path to your test CSS files
zip -r $OUT/css_parse_fuzzer_seed_corpus.zip css_parse_fuzzer_seed_corpus || true

# If you have multiple fuzzers, repeat cp and seed steps