#!/usr/bin/env bash
# The .deb, installed on a clean system: it installs, pnp runs, its files and the pnp group are in place, a file
# round-trips when the machine has a hardware source, and removing then purging it leaves nothing behind.
# Needs root and a throwaway system (CI runs it in fresh containers). Locally:
#   docker run --rm -v "$PWD":/src:ro mirror.gcr.io/library/debian:13 /src/tests/check_package.sh /src/build/pnp_….deb
set -uo pipefail
PKG="$(realpath "${1:?usage: check_package.sh pnp_VERSION_ARCH.deb}")"
fails=0
check() { if eval "$1"; then echo "PASS $2"; else echo "FAIL $2"; fails=$((fails + 1)); fi; }
export DEBIAN_FRONTEND=noninteractive
apt-get update >/tmp/update.log 2>&1

check 'apt-get install -y -qq "$PKG" >/tmp/install.log 2>&1 || { tail -20 /tmp/install.log; false; }' \
    "the package installs, with its dependencies"
check '[[ "$(pnp --version)" == "pnp "* ]]' "pnp runs and reports its version"
check '[[ -f /usr/lib/udev/rules.d/60-pnp-hwrng.rules ]] && grep -q "KERNEL==\"hw_random\", GROUP=\"pnp\", MODE=\"0640\"" \
       /usr/lib/udev/rules.d/60-pnp-hwrng.rules' "the udev rule is installed"
check 'getent group pnp >/dev/null' "the pnp group exists"
# from the package's file list: Ubuntu's container images are set up not to install manuals and docs (dpkg path-exclude)
check 'dpkg -L pnp | grep -qx /usr/share/man/man1/pnp.1.gz && dpkg -L pnp | grep -qx /usr/share/doc/pnp/copyright' \
    "the package has the manual and copyright file"

# encrypting needs a hardware source: containers see the host's CPU, so RDSEED usually works here
useradd -m pnp-pkg-test 2>/dev/null
D=/home/pnp-pkg-test
if su pnp-pkg-test -c "pnp --sources" >/tmp/sources.txt 2>&1; then
    su pnp-pkg-test -c "head -c 1000000 /dev/urandom > $D/f && cp $D/f $D/orig && pnp -q $D/f && rm $D/f && pnp -q -d $D/f.pnp"
    check 'cmp -s "$D/f" "$D/orig" && [[ $(stat -c %a "$D/f.pnp.key") == 600 ]]' \
        "as a normal user, a file encrypts and decrypts with the installed pnp (key mode 600)"
else
    cat /tmp/sources.txt
    check '! su pnp-pkg-test -c "echo x > $D/f && pnp $D/f" 2>/dev/null && [[ ! -e $D/f.pnp ]]' \
        "without a hardware source, the installed pnp refuses to encrypt"
fi

check 'apt-get remove -y -qq pnp >/dev/null 2>&1 && [[ ! -e /usr/bin/pnp && ! -e /usr/lib/udev/rules.d/60-pnp-hwrng.rules ]]' \
    "removing the package removes pnp and the udev rule"
check 'apt-get purge -y -qq pnp >/dev/null 2>&1 && ! getent group pnp >/dev/null && ! dpkg -l pnp 2>/dev/null | grep -q "^[ir]"' \
    "purging it removes the pnp group and leaves nothing behind"

echo
if ((fails)); then echo "$fails check(s) failed"; exit 1; fi
echo "All checks passed"
