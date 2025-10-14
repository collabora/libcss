#!/bin/bash

set -e

if [ "$SRC" == "" ]; then
    echo "SRC env var not defined"
    exit 1
fi

if [ "$OUT" == "" ]; then
    echo "OUT env var not defined"
    exit 1
fi

if [ "$CXX" == "" ]; then
    echo "CXX env var not defined"
    exit 1
fi

build_fuzzer()
{
    fuzzerName=$1
    sourceFilename=$2
    shift
    shift
    echo "Building fuzzer $fuzzerName"
    $CXX $CXXFLAGS -std=c++11 -I$SRC/libcss/include \
        $sourceFilename $* -o $OUT/$fuzzerName \
        $LIB_FUZZING_ENGINE $SRC/libcss/build/liblibcss.a \
        $SRC/libcss/build/subprojects/libparserutils/libparserutils.a \
        $SRC/libcss/build/subprojects/libwapcaplet/libwapcaplet.a
}

fuzzerFiles=$(dirname $0)/*.cc
for F in $fuzzerFiles; do
    fuzzerName=$(basename $F .cc)
    build_fuzzer $fuzzerName $F
done
