# pnp: build, test, install, package. Needs only build-essential (gcc, make, binutils) and, for `make deb`, dpkg-dev.
#   make                  build/pnp
#   make test             build the test binaries and run tests/run.sh (needs script(1), from bsdutils)
#   sudo make install     /usr/local/bin/pnp and its manual (PREFIX, DESTDIR)
#   sudo make install-udev  the udev rule and the pnp group, so the group can read /dev/hwrng
#   make sanitize         the tests again, built with AddressSanitizer and UndefinedBehaviorSanitizer
#   make analyze          static analysis: gcc -fanalyzer, cppcheck, clang's scan-build
#   make deb              build/pnp_<version>_<arch>.deb
#   make fuzz-run         fuzz every untrusted-input parser for FUZZ_SECONDS each (needs clang)
#   make WERROR=1 ...     warnings are errors (CI)

VERSION := $(shell cat VERSION)
DEB_VERSION := $(subst -,~,$(VERSION))
# Reproducible builds (docs/reproducible.md): every timestamp in the package is this one, the last commit's time
# unless given, so the same source built with the same tools gives the same .deb, bit for bit.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || stat -c %Y VERSION)
export SOURCE_DATE_EPOCH
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
# Hardening: each flag is used where the compiler has it, so the same Makefile builds on the oldest release
# (ubuntu:22.04, gcc 11) and the newest.
#   _FORTIFY_SOURCE=3: buffer checks that also know sizes only computed at run time; needs
#     __builtin_dynamic_object_size (gcc 12+, clang 9+), else level 2
#   -fcf-protection (x86-64: CET's indirect-branch tracking and shadow stack, where the CPU and kernel use them),
#     -mbranch-protection=standard (arm64: PAC and BTI)
#   -ftrivial-auto-var-init=zero (gcc 12+, clang 16+): local variables start zeroed, so a missed initialisation
#     can't leak an earlier call's stack contents (pad or key bytes among them)
cc_has = $(shell $(CC) -Werror $(1) -c -x c /dev/null -o /dev/null 2>/dev/null && echo $(1))
FORTIFY := $(or $(shell echo 'int f(char *p) { return (int)__builtin_dynamic_object_size(p, 0); }' | \
	$(CC) -Werror -c -x c - -o /dev/null 2>/dev/null && echo 3),2)
HARDEN := -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=$(FORTIFY) -fstack-protector-strong -fstack-clash-protection -fPIE \
	$(call cc_has,-fcf-protection) $(call cc_has,-mbranch-protection=standard) $(call cc_has,-ftrivial-auto-var-init=zero)
HARDEN_LD := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
# -pthread: Argon2id's lanes run in threads (src/kdf.c); pthreads are part of glibc, so still libc only
# the source folder's path is left out of the binary, so where it's built doesn't change it
REPRO := -ffile-prefix-map=$(CURDIR)=.
ALL_CFLAGS := $(WARN) $(HARDEN) $(REPRO) -pthread $(CFLAGS) -DPNP_VERSION='"$(VERSION)"'
ALL_LDFLAGS := $(HARDEN_LD) -pthread $(LDFLAGS)

SRC := src/main.c src/tui.c src/keys.c src/format.c src/sandbox.c src/progress.c src/rng.c src/fileio.c src/mac.c src/protect.c src/kdf.c src/blake2b.c src/chacha20.c
HDR := src/pnp.h src/sandbox.h src/keys.h src/progress.h src/format.h src/rng.h src/fileio.h src/mac.h src/protect.h src/kdf.h src/blake2b.h src/chacha20.h build/wordlist.h
KDF_SRC := src/kdf.c src/blake2b.c src/chacha20.c

.PHONY: all test sanitize analyze install install-udev uninstall deb clean fuzz fuzz-run

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

# Fuzzing (tests/fuzz/): one harness per kind of untrusted input. `make test` runs each on its seeds through
# tests/fuzz/replay.c with the normal compiler; `make fuzz` builds them for libFuzzer (clang), and
# `make fuzz-run FUZZ_SECONDS=60` fuzzes each for that long from its seeds (tests/fuzz/seeds.sh), keeping what it
# finds in build/fuzz/corpus. A crash leaves a crash-* file: replay it with build/fuzz/replay_NAME FILE.
FUZZ := header keys passfile verify
FUZZ_SRC_header := src/format.c src/protect.c src/rng.c $(KDF_SRC)
FUZZ_SRC_keys := src/keys.c
FUZZ_SRC_passfile := src/protect.c $(KDF_SRC)
FUZZ_SRC_verify := $(SRC)
FUZZ_FLAGS := -DPNP_FUZZ -DPNP_TEST -Dmain=pnp_cli_main -Isrc -Ibuild
FUZZ_SECONDS ?= 60
CLANG ?= clang
.SECONDEXPANSION:
build/fuzz/replay_%: tests/fuzz/fuzz_%.c tests/fuzz/replay.c $$(FUZZ_SRC_$$*) $(HDR) | build
	mkdir -p build/fuzz
	$(CC) $(ALL_CFLAGS) $(FUZZ_FLAGS) -o $@ $< tests/fuzz/replay.c $(FUZZ_SRC_$*) $(ALL_LDFLAGS)

build/fuzz/fuzz_%: tests/fuzz/fuzz_%.c $$(FUZZ_SRC_$$*) $(HDR) | build
	mkdir -p build/fuzz
	$(CLANG) -std=c11 -O1 -g -pthread -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
		$(FUZZ_FLAGS) -DPNP_VERSION='"$(VERSION)"' -o $@ $< $(FUZZ_SRC_$*)

build/fuzz/seeds: build/pnp-test tests/fuzz/seeds.sh
	tests/fuzz/seeds.sh build/pnp-test $@

fuzz: $(FUZZ:%=build/fuzz/fuzz_%)

fuzz-run: fuzz build/fuzz/seeds
	for f in $(FUZZ); do \
		mkdir -p build/fuzz/corpus/$$f && \
		build/fuzz/fuzz_$$f -max_total_time=$(FUZZ_SECONDS) -max_len=8192 -timeout=10 -rss_limit_mb=4096 \
			-artifact_prefix=build/fuzz/crash-$$f- build/fuzz/corpus/$$f build/fuzz/seeds/$$f || exit 1; \
	done

test: build/pnp build/pnp-test build/test_health build/test_mac build/test_kdf build/xorcheck $(FUZZ:%=build/fuzz/replay_%)
	tests/run.sh

# Memory errors and undefined behaviour (out-of-bounds, use-after-free, overflow...) stop the run. build/ is wiped
# before and after, so a sanitized binary never ends up installed or packaged.
SAN := -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
sanitize:
	rm -rf build
	PNP_SANITIZE=1 $(MAKE) --no-print-directory test CFLAGS="-O1 -g $(SAN)" LDFLAGS="$(SAN)"
	rm -rf build

# Static analysis (CI runs it on the newest compilers): gcc's -fanalyzer on each source file, in both builds;
# cppcheck's warning, portability and performance checks (its style notes are taste, not findings); and clang's
# scan-build over the whole build. Any finding fails it: each is fixed, or the code is changed until the tool can
# see it's sound (see the comment in blake2b.c's compress). Needs gcc 12+, cppcheck and clang-tools.
analyze: build/wordlist.h
	for f in $(SRC); do \
		$(CC) -std=c11 -fanalyzer -Werror -O1 -pthread -Ibuild -c $$f -o /dev/null || exit 1; \
		$(CC) -std=c11 -fanalyzer -Werror -O1 -pthread -Ibuild -DPNP_TEST -c $$f -o /dev/null || exit 1; \
	done
	cppcheck -q --std=c11 --enable=warning,performance,portability --error-exitcode=1 --inline-suppr \
		-Isrc -Ibuild -D__x86_64__ -DPNP_TEST src tests
	scan-build --status-bugs -o build/scan $(MAKE) --no-print-directory -B build/pnp build/pnp-test CC=clang

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
		'$(DEB_VERSION)' "$$(LC_ALL=C date -R -u -d @$(SOURCE_DATE_EPOCH))" | gzip -9n > build/deb/usr/share/doc/pnp/changelog.gz
	install -m 644 README.md build/deb/usr/share/doc/pnp/README.md
	install -m 755 debian/postinst debian/postrm build/deb/DEBIAN/
	chmod -R u=rwX,go=rX build/deb
	glibc=$$(objdump -T build/pnp | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -V | tail -1); \
	size=$$(find build/deb/usr -type f -printf '%s\n' | awk '{ k += int(($$1 + 1023) / 1024) } END { print k }'); \
	sed -e 's/@DEB_VERSION@/$(DEB_VERSION)/' -e 's/@ARCH@/$(ARCH)/' -e "s/@GLIBC@/$$glibc/" -e "s/@SIZE@/$$size/" \
		debian/control.in > build/deb/DEBIAN/control
	cd build/deb && find usr -type f | LC_ALL=C sort | xargs md5sum > DEBIAN/md5sums
	find build/deb -exec touch -h -d @$(SOURCE_DATE_EPOCH) {} +
	dpkg-deb --root-owner-group -Zxz --build build/deb $@

clean:
	rm -rf build
