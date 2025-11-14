#!/bin/bash

set -e

if [ "$OUT" == "" ]; then
    echo "OUT env var not defined"
    exit 1
fi

# Assuming a directory with CSS seed files (create manually or source from test data)
SEED_DIR=$SRC/libcss/test/data/css

rm -f $OUT/css_parse_fuzzer_seed_corpus.zip
zip $OUT/css_parse_fuzzer_seed_corpus.zip $SEED_DIR/*.vtt $SEED_DIR/*.css
