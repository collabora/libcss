#!/bin/bash -eu

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
cp -r test/data/css/* css_parse_fuzzer_seed_corpus/ || true  # Adjust path to your test CSS files
zip -r $OUT/css_parse_fuzzer_seed_corpus.zip css_parse_fuzzer_seed_corpus || true