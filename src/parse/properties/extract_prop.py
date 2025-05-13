#!/usr/bin/env python3

import sys

# Check for correct number of arguments
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_file> <property_name>", file=sys.stderr)
    sys.exit(1)

input_file = sys.argv[1]
prop_name = sys.argv[2]

try:
    with open(input_file, 'r') as fh:
        for line in fh:
            line = line.rstrip('\n')  # Remove trailing newline
            if line.startswith('#') or not line.strip():
                continue  # Skip comments and empty lines
            if line.startswith(prop_name + ':'):
                print(line.rstrip(), end='')  # Print without trailing whitespace or newline
                sys.exit(0)
except FileNotFoundError:
    print(f"Cannot open {input_file}: No such file or directory", file=sys.stderr)
    sys.exit(1)