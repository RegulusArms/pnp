# pnp: build, test, install, package. Needs only build-essential (gcc, make, binutils) and, for `make deb`, dpkg-dev.
#   make                  build/pnp
#   make test             build the test binary and run tests/run.sh
#   sudo make install     /usr/local/bin/pnp and its manual (PREFIX, DESTDIR)
#   sudo make install-udev  the udev rule and the pnp group, so the group can read /dev/hwrng
#   make deb              build/pnp_<version>_<arch>.deb
#   make WERROR=1 ...     warnings are errors (CI)

VERSION := $(shell cat VERSION)
DEB_VERSION := $(subst -,~,$(VERSION))
ARCH := $(shell dpkg --print-architecture 2>/dev/null || uname -m)

CC ?= cc
CFLAGS ?= -O2 -g
PREFIX ?= /usr/local
DESTDIR ?=
UDEV_RULES_DIR ?= /etc/udev/rules.d

WARN := -std=c11 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wconversion -Wno-sign-conversion
ifeq ($(WERROR),1)
WARN += -Werror
endif
HARDEN := -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -fPIE
HARDEN_LD := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
ALL_CFLAGS := $(WARN) $(HARDEN) $(CFLAGS) -DPNP_VERSION='"$(VERSION)"'
ALL_LDFLAGS := $(HARDEN_LD) $(LDFLAGS)

SRC := src/main.c src/rng.c src/fileio.c src/mac.c src/protect.c src/kdf.c src/blake2b.c src/chacha20.c
HDR := src/rng.h src/fileio.h src/mac.h src/protect.h src/kdf.h src/blake2b.h src/chacha20.h build/wordlist.h
KDF_SRC := src/kdf.c src/blake2b.c src/chacha20.c

.PHONY: all test install install-udev uninstall deb clean

all: build/pnp

build:
	mkdir -p build

# --gen-passphrase's words: each "NNNNN<tab>word" line of the EFF list becomes "word",. A line in any other shape
# is left as it is, so it breaks the build instead of slipping in.
build/wordlist.h: data/eff_large_wordlist.txt | build
	sed -E 's/^[1-6]{5}\t([a-z-]+)$$/"\1",/' $< > $@

build/pnp: $(SRC) $(HDR) VERSION | build
	$(CC) $(ALL_CFLAGS) -Ibuild -o $@ $(SRC) $(ALL_LDFLAGS)

# the same program with the test hooks (PNP_TEST_* in src/rng.c); never installed or packaged
build/pnp-test: $(SRC) $(HDR) VERSION | build
	$(CC) $(ALL_CFLAGS) -Ibuild -DPNP_TEST -o $@ $(SRC) $(ALL_LDFLAGS)

build/test_health: tests/test_health.c src/rng.c src/rng.h | build
	$(CC) $(ALL_CFLAGS) -DPNP_TEST -Isrc -o $@ tests/test_health.c src/rng.c $(ALL_LDFLAGS)

build/test_mac: tests/test_mac.c src/mac.c src/mac.h | build
	$(CC) $(ALL_CFLAGS) -Isrc -o $@ tests/test_mac.c src/mac.c $(ALL_LDFLAGS)

build/test_kdf: tests/test_kdf.c $(KDF_SRC) src/protect.c src/kdf.h src/blake2b.h src/chacha20.h src/protect.h | build
	$(CC) $(ALL_CFLAGS) -Isrc -o $@ tests/test_kdf.c $(KDF_SRC) src/protect.c $(ALL_LDFLAGS)

build/xorcheck: tests/xorcheck.c | build
	$(CC) $(ALL_CFLAGS) -o $@ tests/xorcheck.c $(ALL_LDFLAGS)

test: build/pnp build/pnp-test build/test_health build/test_mac build/test_kdf build/xorcheck
	tests/run.sh

install: build/pnp
	install -D -m 755 build/pnp $(DESTDIR)$(PREFIX)/bin/pnp
	install -d $(DESTDIR)$(PREFIX)/share/man/man1
	sed 's/@VERSION@/$(VERSION)/' man/pnp.1 | gzip -9n > $(DESTDIR)$(PREFIX)/share/man/man1/pnp.1.gz

install-udev:
	install -D -m 644 data/60-pnp-hwrng.rules $(DESTDIR)$(UDEV_RULES_DIR)/60-pnp-hwrng.rules
	@if [ -z "$(DESTDIR)" ]; then \
		getent group pnp >/dev/null || groupadd --system pnp; \
		udevadm control --reload-rules && udevadm trigger --subsystem-match=misc --sysname-match=hw_random; \
		echo "Now join the pnp group: sudo usermod -aG pnp \$$USER, then log out and back in."; \
	fi

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/pnp $(DESTDIR)$(PREFIX)/share/man/man1/pnp.1.gz
	rm -f $(DESTDIR)$(UDEV_RULES_DIR)/60-pnp-hwrng.rules

# The .deb, built with dpkg-deb from a staging folder. Depends on the newest glibc symbol version the binary
# actually uses, so a package built on an old release installs on every newer one.
DEB := build/pnp_$(DEB_VERSION)_$(ARCH).deb
deb: $(DEB)

$(DEB): build/pnp man/pnp.1 data/60-pnp-hwrng.rules debian/control.in debian/postinst debian/postrm debian/copyright CHANGELOG.md README.md
	rm -rf build/deb && mkdir -p build/deb/DEBIAN
	$(MAKE) --no-print-directory install DESTDIR=$(CURDIR)/build/deb PREFIX=/usr
	strip --strip-unneeded build/deb/usr/bin/pnp
	install -D -m 644 data/60-pnp-hwrng.rules build/deb/usr/lib/udev/rules.d/60-pnp-hwrng.rules
	install -D -m 644 debian/copyright build/deb/usr/share/doc/pnp/copyright
	gzip -9n < CHANGELOG.md > build/deb/usr/share/doc/pnp/CHANGELOG.md.gz
	printf 'pnp (%s) unstable; urgency=medium\n\n  * See CHANGELOG.md.gz.\n\n -- RegulusArms <ross@regulusarms.com>  %s\n' \
		'$(DEB_VERSION)' "$$(date -R -u -d @$${SOURCE_DATE_EPOCH:-$$(date +%s)})" | gzip -9n > build/deb/usr/share/doc/pnp/changelog.gz
	install -m 644 README.md build/deb/usr/share/doc/pnp/README.md
	install -m 755 debian/postinst debian/postrm build/deb/DEBIAN/
	chmod -R u=rwX,go=rX build/deb
	glibc=$$(objdump -T build/pnp | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1); \
	size=$$(du -sk --exclude=DEBIAN build/deb | cut -f1); \
	sed -e 's/@DEB_VERSION@/$(DEB_VERSION)/' -e 's/@ARCH@/$(ARCH)/' -e "s/@GLIBC@/$$glibc/" -e "s/@SIZE@/$$size/" \
		debian/control.in > build/deb/DEBIAN/control
	cd build/deb && find usr -type f -exec md5sum {} + > DEBIAN/md5sums
	dpkg-deb --root-owner-group -Zxz --build build/deb $@

clean:
	rm -rf build
