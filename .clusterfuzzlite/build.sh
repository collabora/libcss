#!/bin/bash -eu

# Build libcss and dependencies
cd $SRC/libcss
rm -rf build || true  # Wipe old build dir if it exists, ignore if not
mkdir -p build
cd build
meson setup .. --default-library=static
ninja -j$(nproc)
ninja install
cd ../..


# Set executable permissions for fuzzer build scripts
chmod +x $SRC/libcss/test/fuzzers/build_google_oss_fuzzers.sh
chmod +x $SRC/libcss/test/fuzzers/build_seed_corpus.sh

# Build fuzzers and seed corpus
$SRC/libcss/test/fuzzers/build_google_oss_fuzzers.sh
$SRC/libcss/test/fuzzers/build_seed_corpus.sh