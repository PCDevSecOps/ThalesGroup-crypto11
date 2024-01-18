#!/usr/bin/env bash


echo "Testing with $(go version)"
echo "Testing Go file '$1'"

set -x

dep=$(find . -type f \( -iname "*.go" ! -iname "$1" \))
echo "DEBUG dep : '$dep'"
go test "$1" "$dep"

echo "Done"
exit 0
