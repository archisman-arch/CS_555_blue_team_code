#!/usr/bin/env bash

mkdir -p ./build/
# clean
rm -f ./build/*.teal

set -e # die on error

python ./compile.py "$1" ./build/approval.teal ./build/clear.teal
#python3 ./compile.py contracts.counter.step_01 ./build/approval.teal ./build/clear.teal
