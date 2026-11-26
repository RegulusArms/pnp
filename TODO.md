# To do

Planned work for pnp, roughly in priority order.

## Keys

- [ ] **Write the key to a separate place (`--key-out DIR` or `--key-out FILE`).** Today the key always goes beside
  the ciphertext, so it lands on the computer's own disk first even when it's meant for a USB stick. On an SSD a
  deleted key may stay recoverable (the drive moves data around internally). With `--key-out`, the key is written
  straight to removable media and never touches the internal disk. Decrypting finds it with `-k` as now.
- [ ] **Split a key into shares.** An option to write the key as two (or more) shares, each one useless alone and
  all of them needed to decrypt, for keeping in different places. XOR splitting: share 1 is a fresh hardware-random
  pad, share 2 is key XOR share 1. Like the pad itself, this is information-theoretically secure. Needs a header
  format for shares (a new magic, the shared ID, share number and count) and refusal of an incomplete set.
- [ ] **"Keeping your keys" section in the README.** Guard keys physically, not with more encryption (an
  AES-encrypted drive, password manager or cloud account is only as strong as what P = NP would break). Keep the
  ciphertext anywhere and the key offline. Keep two or more copies in different places, on more than one kind of
  storage for long-term archives, with a checksum list to catch corruption. Avoid the ciphertext's location, cloud
  storage, email, and the computer's SSD. Destroying every copy of a key makes the file unreadable for good.

## Later

- [ ] An information-theoretic integrity check (a one-time MAC keyed from the pad), so a modified ciphertext is
  detected instead of decrypting to modified data. HMAC or a plain hash wouldn't keep the P = NP claim.
- [ ] TPM 2.0 (`/dev/tpmrm0`) as an extra hardware source, for machines whose TPM isn't already behind
  `/dev/hwrng`.
- [ ] A progress display for large files when the hardware source is slow.
- [ ] arm64 packages (no RDSEED there: `/dev/hwrng` only).
