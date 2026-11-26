# Security policy

pnp exists to keep files secret. If you've found a way to break that, or anything below, please tell us
privately first, so it can be fixed before it's public.

## Reporting a vulnerability

Report it privately, by either:

- **GitHub's private reporting**: the repository's **Security** tab → **Report a vulnerability**. Only you and
  the maintainers see it.
- **Email**: ross@regulusarms.com, subject starting with `pnp security`.

Please don't open a public issue, pull request or discussion for it.

Useful to include: the pnp version (`pnp --version`), the release you run it on, what you did, what happened and
what you expected, and a file or script that shows it if you have one. Don't send real secrets: a pad or key you
made for the report is fine.

## What happens next

1. **Within 7 days**: a reply saying it has been received, and a first view on whether it's in scope.
2. **Within 30 days**: an assessment, and a fix or a plan with a date. You'll hear how it's going at least every
   two weeks until it's settled.
3. **Release**: the fix goes out as a new version through the apt repo and GitHub releases, with a GitHub
   security advisory describing the problem, what it affects and what to do (for example, re-encrypt files made
   with an affected version).
4. **Disclosure**: coordinated with you. The default is to publish once the fix is out, and at most 90 days
   after your report, sooner if it's already being exploited. You're credited in the advisory and
   CHANGELOG.md, unless you'd rather not be.

There's no bug bounty: pnp is a small free project.

## What's in scope

Anything that undoes what pnp promises, in particular:

- **The one-time pad**: pad bytes that aren't from the hardware sources as documented, a pad used twice or
  shorter than the file, pad or plaintext bytes reaching the ciphertext's disk, swap, a core dump or another
  file.
- **The randomness**: a way for pnp to encrypt without a healthy hardware source, health tests that pass a broken
  source, or the summary line misreporting which sources made the pad.
- **The integrity check**: a change to a ciphertext or key that decrypts without the check failing.
- **Files**: a lost key or plaintext, a half-written output under a real name, an existing file replaced
  without `-f`, a key readable by other users.
- **Parsing**: a crash, hang or memory error from a crafted ciphertext, key, share, passphrase file, file name
  or terminal input.
- **`--protect`**: a way past the passphrase cheaper than guessing it (it's only computationally secure by
  design, and that's documented).
- **The sandbox**: a way for pnp, once its files are open, to reach the network, run a program or touch other
  files.
- **Packaging**: the .deb, its maintainer scripts and udev rule, the apt repo or its signing.

Not in scope, because pnp says it can't protect against them ([docs/threat-model.md](docs/threat-model.md)):
malware or another user with root on the machine that encrypts or decrypts, a virtual machine's host, someone
who holds the key (and the passphrase, with `--protect`), and the apt repo's RSA signature failing if P = NP
(the README's disclaimer). Reports that one of these is worse than documented are welcome.

## Supported versions

pnp is in alpha: only the newest release (and the `dev` suite) gets fixes. Upgrade with
`sudo apt update && sudo apt upgrade`.
