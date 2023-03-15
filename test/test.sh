#!/bin/sh

set -e

origin=$(realpath $(dirname $0))

cd $origin/../build

fc=./fcrypt

rm -f test.txt.decrypted test.txt.fc

echo "to be encrypted" > test.txt

$fc -p test test.txt

if [ ! -f test.txt.fc ]; then
	echo "encrypted file not found"
	exit 1
fi

$fc -p test -o test.txt.decrypted test.txt.fc

if [ ! -f test.txt.decrypted ]; then
	echo "decrypted file not found"
	exit 1
fi

s1=$(cat test.txt)
s2=$(cat test.txt.decrypted)

#echo $s1
#echo $s2

if [ "$s1" != "$s2" ]; then
	echo "test failed"
	exit 1
fi

# cleanup
rm -f test.txt test.txt.fc test.txt.decrypted

echo "test successful"

