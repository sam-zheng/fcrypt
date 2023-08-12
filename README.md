# Simple file encryption utility

fcrypt is a simple file encryption utility using openssl crypto lib or [tiny-AES-c](https://github.com/kokke/tiny-AES-c)

### Usage

to build:

	$ make

to use:

	$ fcrypt -h
	
to run test:

	$ make test
	
### Example

encrypt all files in the current directory:

	$ fcrypt .
	password:
	./work.o: 100%
	./output.o: 100%
	./fcrypt.o: 100%
	./crc.o: 100%
	./aes.o: 100%
	./fcrypt: 100%

### TODO

tidy up.

