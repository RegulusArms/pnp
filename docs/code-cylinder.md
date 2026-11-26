# Your code cylinder: a key drive you carry

pnp's encryption can't be broken by any amount of computing power, even if P = NP. That strength has a price:
**everything depends on who can physically get hold of your keys.** This guide shows how to set up a dedicated key
drive (your "code cylinder"), how to carry it, and how to destroy keys when you need to.

## Why pnp comes down to physical security

Most encryption protects a file with a short password or a small key, and relies on it being too hard to compute
the way back. pnp uses a one-time pad instead: the key is as long as the file, truly random, and the ciphertext
tells an attacker nothing at all without it.

That moves the whole secret into the key file:

- **Anyone who has the key file and the ciphertext can read your file.** By default there's no password on the
  key and no second barrier. `--protect` can add a passphrase, but that layer is only computationally secure
  (the kind of security P = NP could break): it slows down a thief, it doesn't make a stolen key safe. Treat
  every key as if anyone who picks it up can use it.
- **Nobody without the key can read your file, ever.** Not with a supercomputer, a new algorithm, or a proof that
  P = NP.
- **Losing the key loses the file.** There's no recovery.

So the question "is my file safe?" becomes "where are all the copies of its key, and who can reach them?" A drive
you control physically answers that far better than any cloud account, password manager or encrypted volume, all
of which rely on ciphers that P = NP would break.

## Why an external hard disk

Keys need a drive you can **really erase**, so that deleting a key actually destroys it.

| Drive | Can a deleted key be erased for sure? | Notes |
|---|---|---|
| **External hard disk (HDD, spinning platters)** | **Yes.** Data is overwritten where it lies | Best choice for a key drive. Large, so big keys fit |
| USB stick, SD card, external SSD | **No.** Wear levelling moves data around internally, and old copies can stay in cells you can't reach | Fine for a backup copy you never need to erase. Destroy it physically at end of life |
| The computer's internal SSD | **No**, for the same reason | Never let keys land here. Use `--key-out` |

A hard disk writes data back to the same place on the platter, so overwriting a file really does replace its old
contents. A flash drive's controller writes new data somewhere else and keeps the old blocks until it decides to
reuse them, so you can never be sure a key on flash is gone.

Choose a **2.5-inch portable USB hard disk** (bus-powered, no separate power supply). Avoid:

- Drives sold as "SSD", "flash" or "hybrid (SSHD)": they have flash inside.
- Relying on a drive's built-in "hardware encryption" or password lock. It uses AES, which is only computationally
  secure. It does no harm, but don't count on it.

Keys are as big as the files they encrypt, so size the drive for the files you'll protect, with room to spare.

## Setting it up

This erases everything on the drive. **Check the device name twice:** choosing the wrong one wipes the wrong disk.

1. Plug in the drive and find it:

   ```
   lsblk -o NAME,SIZE,MODEL,ROTA,TRAN
   ```

   Look for your drive's size and model with `TRAN` = `usb`. `ROTA` = `1` confirms it's a spinning disk; `0` means
   flash inside, so don't use it as a key drive. Below it's called `/dev/sdX`: replace that with the real name,
   such as `/dev/sdb`.

2. Check its health (optional but worth it; `sudo apt install smartmontools`):

   ```
   sudo smartctl -H -A /dev/sdX
   ```

   It should say `PASSED`, and `Reallocated_Sector_Ct` should be 0. Some USB enclosures hide this information; then
   try `sudo smartctl -d sat -H -A /dev/sdX`.

3. Unmount it if your desktop mounted it, then make one partition with an ext4 filesystem called `KEYS`:

   ```
   sudo umount /dev/sdX?* 2>/dev/null
   sudo wipefs -a /dev/sdX
   sudo parted -s /dev/sdX mklabel gpt mkpart keys ext4 0% 100%
   sudo mkfs.ext4 -L KEYS /dev/sdX1
   ```

   Use **ext4**. It overwrites file data in place, so `shred` works on it (see below). Don't use btrfs or ZFS:
   they're copy-on-write and keep old copies of overwritten data.

4. Unplug it and plug it back in. Your desktop mounts it at `/media/$USER/KEYS`. Make it yours, readable by you
   only:

   ```
   sudo chown $USER: /media/$USER/KEYS
   chmod 700 /media/$USER/KEYS
   ```

5. Write a test key to it and decrypt with it:

   ```
   echo hello > test.txt
   pnp --key-out /media/$USER/KEYS test.txt
   pnp -d -f -k /media/$USER/KEYS/test.txt.pnp.key test.txt.pnp
   ```

## Using it

The easiest way is pnp's interactive mode: type `pnp` in the folder with your files. It finds the drive by its
`KEYS` label, writes new keys straight to it, and shows which key on it each `.pnp` file will be decrypted with.

A label is easy to copy, though: anyone could format a stick and call it `KEYS`, and if it were plugged in instead
of yours, your next keys would go to their drive. So the interactive mode remembers each drive it has written keys
to by its filesystem UUID (set when the drive was formatted, kept in `~/.local/state/pnp/drives`), and says
**"NOT the KEYS drive pnp wrote keys to before"** in red when a drive with that name shows up with another UUID.
Stop and check which drive is plugged in. If it's a new drive of yours (a replacement or a backup), writing keys
to it adds it to the list, and the warning goes away. A careful attacker could copy the UUID too, so this catches
a swap, it doesn't prove the drive is yours: keeping the drive with you does that.

- **Always write keys straight to the drive** with `--key-out /media/$USER/KEYS`. Without it, the key is written
  beside the ciphertext, on the computer's own disk, and a deleted file there may stay recoverable.
- **Plug it in only while you encrypt or decrypt**, then unmount and unplug it (eject it in your file manager, or
  `udisksctl unmount -b /dev/sdX1 && udisksctl power-off -b /dev/sdX`). While it's mounted, any program on the
  computer can read your keys.
- **Only plug it into a computer you trust.** pnp's math can't protect against malware on the machine itself,
  which could copy every key on the drive while it's connected.
- **Keep the ciphertext elsewhere.** The `.pnp` files can go anywhere: the computer, a backup, the cloud. The drive
  holding the keys should hold no ciphertexts, so losing it alone gives nothing away.
- **If you lock keys with `--protect`, never keep the passphrase on the drive** (or on a note in the drive's
  case). Keep it in your head, or written down somewhere else entirely.
- **Keep a checksum list on the drive** to catch corruption early:

  ```
  cd /media/$USER/KEYS && sha256sum *.key > SHA256SUMS      # after adding keys
  cd /media/$USER/KEYS && sha256sum -c SHA256SUMS           # now and then
  ```

  Or check each archived file against its key directly, which also runs the integrity check over every byte:
  `pnp --verify -k /media/$USER/KEYS/FILE.pnp.key FILE.pnp`.

## Keeping the code cylinder with you

A drive in your pocket is a key you can see. A drive left in a desk is a key you have to trust others with.

- **Carry it on you**, in a padded case, a zipped inner pocket or a belt pouch. Hard disks dislike shocks,
  especially while running: never move or drop it while it's spinning, and let it spin down before unplugging.
- **Don't leave it plugged in** or lying in a bag, a car or a hotel room.
- **Make tampering visible.** Someone with a few minutes alone with the drive can copy every key without leaving a
  trace. A tamper-evident sticker, or a dab of glitter nail polish over a seam photographed close up, at least
  shows you that the case was opened. A copy made over USB leaves no sign, so the real protection is not letting
  the drive out of your sight.
- **If it's lost or stolen,** assume every key on it is known to whoever has it. Any file whose ciphertext they can
  also get is exposed. Move or delete those ciphertexts if you can. Keys locked with a strong `--protect`
  passphrase buy you time, but treat them as exposed too: that lock is only computationally secure.

## Backups, and carrying only half a key

A key drive can fail, and a failed key drive means lost files. Keep at least one copy elsewhere:

- **A second copy at home** in a safe, or with someone you trust, on a second drive. For long-term archives, use
  more than one kind of storage (a second hard disk plus a USB stick or optical disc), since every kind fails
  eventually. Keep the checksum list with every copy.

Or use **shares**, so that no single drive holds a usable key:

```
pnp --shares 2 --key-out /media/$USER/KEYS --key-out /media/$USER/HOMEKEYS photo.jpg
```

Share 1 goes on the drive you carry, share 2 on a drive that stays at home. Each share alone is pure random noise:
if your carried drive is stolen, the thief learns nothing, however much computing power they have. To decrypt,
bring both together:

```
pnp -d -k /media/$USER/KEYS/photo.jpg.pnp.key.1 -k /media/$USER/HOMEKEYS/photo.jpg.pnp.key.2 photo.jpg.pnp
```

The cost: losing either share loses the file. Back up each share as you would a whole key.

## Destroying keys

Destroying every copy of a key makes its file unreadable for good, which is sometimes exactly what you want.

**One key**, on the ext4 hard disk set up above:

```
shred -u /media/$USER/KEYS/photo.jpg.pnp.key
```

One overwrite is enough on a modern hard disk. Plain `rm` is not: it only frees the space, and the key stays on
the platter until something else is written there. `shred` is reliable here because the drive is a hard disk and
the filesystem is ext4. It isn't reliable on flash or SSDs, or on btrfs/ZFS.

Remember the other copies: backups, the second drive, any share. A key is destroyed only when every copy is.

**The whole drive** (when retiring or giving it away):

```
sudo dd if=/dev/zero of=/dev/sdX bs=4M status=progress
```

This overwrites every sector, including free space and old deleted keys. Check the device name first. The one
place it can't reach is a sector the drive has retired as faulty (`Reallocated_Sector_Ct` above 0). If that
matters to you, or the drive is dead, destroy it physically: open it and drill or smash through the platters.

**Flash drives and SSDs** that ever held keys can't be reliably erased by software. Destroy them physically when
you're done with them.

## Summary

- pnp's keys are its only secret, so how you store them is pnp's weakest link. Whoever has a key and its
  ciphertext can read the file. Nobody else can, ever.
- Keep keys on a dedicated external hard disk with ext4, written straight there with `--key-out`.
- Carry it, plug it in only to use it, only into a computer you trust, and keep ciphertexts elsewhere.
- Back it up, or split keys into shares across a drive you carry and one you don't.
- Destroy a key with `shred -u` on that drive, and a whole drive with `dd` or a drill.
