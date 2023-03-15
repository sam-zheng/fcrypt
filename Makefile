cc = gcc
ld = gcc
cflags = -g -Wall
srcdir = src
builddir = build
exe = fcrypt
objects := $(patsubst $(srcdir)/%.c,$(builddir)/%.o,$(wildcard $(srcdir)/*.c))

all: $(builddir)/$(exe)

$(builddir)/$(exe): $(objects)
	$(ld) -o $@ $(objects) -lcrypt

$(objects): $(builddir)/%.o: $(srcdir)/%.c
	mkdir -p $(builddir)
	$(cc) -c $(cflags) $< -o $@

clean:
	rm -rf $(builddir)

test: $(builddir)/$(exe)
	chmod +x test/test.sh
	test/test.sh
	
.PHONY: all clean test

