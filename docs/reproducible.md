# Reproducible builds: checking a package against your own build

The same pnp source, built with the same tools and the same timestamp, gives a bit-identical .deb. So you don't
have to trust that the package in the apt repository or on a GitHub release was built from the source you can
read: you can build it yourself and compare.

This strengthens the README's "Disclaimer: if P = NP, build from source". The apt repository's signature only says
the package came from whoever holds the signing key, and if P = NP that signature could be forged. A matching
rebuild says the package *is* the reviewed source, whoever signed it. (It still trusts your own compiler and
system, as building from source always does.)

## Check a published package

You need Docker (or an Ubuntu 22.04 machine) and the package you want to check.

1. **Get the build info.** Every GitHub release has a `.buildinfo` file beside the .deb (and dev builds on the
   `dev-latest` pre-release). It names the commit, the timestamp (`SOURCE_DATE_EPOCH`), the package version
   (`DEB_VERSION`) and the versions of the tools that built it:
   ```
   Package: pnp_0.1.0~alpha.13_amd64.deb
   Source: https://github.com/RegulusArms/pnp commit 1a2b3c4...
   SOURCE_DATE_EPOCH: 1764100000
   DEB_VERSION: 0.1.0~alpha.13
   ...
   ```
2. **Get the source at that commit**, and read it (that's the point):
   ```
   git clone https://github.com/RegulusArms/pnp && cd pnp && git checkout <commit>
   ```
3. **Build it as CI does**, in a clean Ubuntu 22.04 with gcc-12:
   ```
   docker run --rm -v "$PWD":/src -w /src ubuntu:22.04 bash -c '
     apt-get update && apt-get install -y build-essential gcc-12 &&
     make clean && make CC=gcc-12 deb DEB_VERSION=<DEB_VERSION> SOURCE_DATE_EPOCH=<SOURCE_DATE_EPOCH>'
   ```
4. **Compare:**
   ```
   sha256sum build/pnp_*.deb /path/to/downloaded/pnp_*.deb
   ```
   The same hash means the published package is exactly what this source builds. For a package installed through
   apt, compare with the one in `/var/cache/apt/archives/`, or download it again with `apt download pnp`.

## If the hashes differ

The most likely reason is a different tool version: Ubuntu 22.04 still gets updates to gcc-12, binutils or
dpkg, and a newer compiler can produce different (equally correct) code. The `.buildinfo` file lists the versions
CI used; compare them with yours (`dpkg-query -W gcc-12 binutils dpkg xz-utils`). To see *what* differs,
`diffoscope` (`apt install diffoscope`) compares two .debs file by file. A difference only in the binary, with the
same tool versions, is worth reporting (SECURITY.md).

## What makes it reproducible

- Every timestamp in the package (file times, the ar archive, the Debian changelog's date) is
  `SOURCE_DATE_EPOCH`: the last commit's time by default (the Makefile), passed explicitly by CI.
- The build folder's path is mapped out of the binary (`-ffile-prefix-map`), so where you build doesn't matter.
- The file lists (md5sums) are sorted; `Installed-Size` is computed from file sizes, not from the disk's block
  size; owners are root, modes are normalised, compression is deterministic (`gzip -n`, xz).
- CI builds every package twice, the second time in another folder with another umask, and fails if the two
  differ.

## Signed checksums

Each GitHub release also has `SHA256SUMS` and `SHA256SUMS.asc`, signed with the apt repository's key
(`pnp.asc`, fingerprint `B605C24B0B68BEF13104D1048A29173719C44365`), for downloading the .deb directly:

```
curl -fsSLO https://pnp.regulusarms.com/pnp.asc && gpg --import pnp.asc
gpg --verify SHA256SUMS.asc SHA256SUMS && sha256sum -c --ignore-missing SHA256SUMS
```

The signature has the same limits as the apt repository's (RSA: computationally secure only). A matching
rebuild doesn't.
