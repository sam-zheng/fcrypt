cc = gcc
ld = gcc
cflags = -g -Wall
objects := $(patsubst %.c,%.o,$(wildcard *.c))
fc: $(objects)
	$(ld) -o $@ $(objects) -lcrypt

$(objects): %.o: %.c
	$(cc) -c $(cflags) $< -o $@

clean:
	rm *.o fc
	
.PHONY: clean

