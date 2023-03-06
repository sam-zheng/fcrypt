cc = gcc
ld = gcc
cflags = -g -Wall
srcdir = src
builddir = build
objects := $(patsubst $(srcdir)/%.c,$(builddir)/%.o,$(wildcard $(srcdir)/*.c))

all: $(builddir)/fc

$(builddir)/fc: $(objects)
	$(ld) -o $@ $(objects) -lcrypt

$(objects): $(builddir)/%.o: $(srcdir)/%.c
	mkdir -p $(builddir)
	$(cc) -c $(cflags) $< -o $@

clean:
	rm -rf $(builddir)

test: $(builddir)/fc
	chmod +x test/fc_test.sh
	test/fc_test.sh
	
.PHONY: all clean test

