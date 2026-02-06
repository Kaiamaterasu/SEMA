PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin

.PHONY: all
all:
	zig build -Doptimize=ReleaseSafe

.PHONY: clean
clean:
	zig build clean

.PHONY: install
install: all
	install -d $(BINDIR)
	install -m 0755 zig-out/bin/sema $(BINDIR)/sema

.PHONY: uninstall
uninstall:
	rm -f $(BINDIR)/sema
