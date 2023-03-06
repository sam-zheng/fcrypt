#!/bin/sh

set -e

origin=$(realpath $(dirname $0))

cd $origin/../build

fc=./fc

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




##include <time.h>
##include <stdlib.h>
##include <assert.h>
##include <string.h>
##include <stdio.h>
##include <sys/stat.h>
#
##include "../src/fc.h"
#
##define HEX(c) (c) < 10 ? '0' + (c) : 'a' + (c) - 10
##define HEX_H(c) HEX(((unsigned char)(c)) >> 4)
##define HEX_L(c) HEX(((unsigned char)(c)) & 0xf)
#
#static char* read_file(char *file) {
#	struct stat st;
#	fstat(file, &st);
#	st.st_size;
#	char * s = malloc(st.st_size + 1);
#	FILE *fp = fopen(file, "r");
#	fread(s, 1, st.st_size, fp);
#	fclose(fp);
#	s[st.st_size] = '\0';
#	return s;
#}
#
#int main(void) {
#	struct ctx c;
#
#	char *rd = "/dev/urandom";
#	FILE *fp = fopen(rd, "r");
#	if (!fp) {
#		fprintf(stderr, "error opening %s\n", rd);
#		fflush(stderr);
#		exit(ENOFILE);
#	}
#	char b[12];
#	int r = fread(b, 1, sizeof(b), fp);
#	assert(r == sizeof(b));
#	fclose(fp);
#
#	char *tfn = tmpnam(NULL);
#	FILE *tf = fopen(tfn, "w+");
#	char s[2 * sizeof(b)];
#	for (int i = 0; i < sizeof(b); i++) {
#		s[i * 2] = HEX_H(b[i]);
#		s[i * 2 + 1] = HEX_L(b[i]);
#	}
#	fwrite(s, 1,  sizeof(s), tf);
#	fclose(tf);
#	strcpy(c.password, "test");
#
#	tf = fopen(tfn, "r");
#	c.f = tf;
#	c.enc = 1; # encrypt
#	c.name = tfn;
#
#	fcrypt(&c);
#
#	fclose(tf);
#
#	remove(tf);
#
#	struct ctx new = c;
#	new.enc = 0; // decrypt
#	int tfnl = strlen(tfn);
#	char *encname = malloc(tfnl + 4);
#	memcpy(encname, tfn, tfnl);
#	memcpy(encname + tfnl, ".fc\0", 4);
#
#	new.name = encname;
#	new.f = fopen(encname, "r");
#	fcrypt(&new);
#	fclose(new.f);
#	free(encname);
#
#	char *decrypted = read_file(tfn);
#
#	assert(!strncmp(s, decrypted, sizeof(s)));
#
#}
#
#
