# Your code cylinder: a key drive you carry

Without its key, a pnp ciphertext reveals nothing about the file but its length, however much computing power is
used, even if P = NP (as long as the key is truly random, used once and kept secret). That strength has a price:
**everything depends on who can physically get hold of your keys.** This guide shows how to set up a dedicated key
drive (your "code cylinder"), encrypt it, carry it, and destroy keys when you need to.

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
you control physically answers that far better than any cloud account or password manager, which rely on ciphers
that P = NP would break. Encrypting the drive itself (below) is still worth doing, as a second lock on top of
physical custody, never instead of it.

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

## Why encrypt the drive too

An unencrypted key drive needs no clever attack: whoever picks it up plugs it in and copies the keys in a minute.
Encrypting the whole drive with **LUKS** (Linux's standard disk encryption) changes that:

- **A lost or stolen drive gives no usable keys** without its passphrase.
- **A few minutes alone with it isn't enough.** Everything on the drive is encrypted, file names included (and
  names like `tax-return.pdf.pnp.key` say what you've encrypted). To get at a key, an attacker has to copy the
  whole drive, which takes hours for a large disk, and then guess the passphrase, with every guess costing about
  1 GiB of memory and several seconds of computing (the settings below). With a strong passphrase that's not worth
  it to anyone short of a state.
- **You can make it unreadable in seconds** in an emergency (`cryptsetup luksErase`, below).

What it doesn't do:

- **It's computationally secure only.** LUKS uses AES and Argon2id, the kind of protection a practical P = NP
  algorithm, or a state's resources, could get through. Like `--protect`, it makes stealing keys expensive; it
  isn't part of pnp's P = NP guarantee, and physical custody still comes first.
- **It protects nothing while the drive is unlocked.** Once unlocked and mounted, any program on the computer can
  read the keys, exactly as before. Lock it again as soon as you're done.
- **It adds a way to lose everything.** Forget the passphrase, or damage the LUKS header (the first 16 MiB of the
  partition), and every key on the drive is gone, and with them every file they decrypt. Back up the header
  (step 5 below) and keep backups of the keys.

**LUKS or VeraCrypt?** Use LUKS2: `cryptsetup` is in every Debian, Ubuntu and Mint archive, and the desktop asks
for the passphrase when you plug the drive in. A VeraCrypt volume works as well, if the drive has to open on
Windows or macOS too; it isn't in the Debian archives (download it from veracrypt.fr and check its signature), and
it's one more program to trust. The steps below use LUKS. Either way, don't count on a drive's built-in
"hardware encryption" (see above).

**LUKS and `--protect` together:** LUKS protects the whole drive at rest, names included; `--protect` protects
each key file wherever it goes, including while the drive is unlocked or if a key is copied off it. You can use
both. Give them different passphrases.

**Who the two locks stop: common criminals, not the Galactic Federation.** Someone who steals or finds the drive
has to crack the drive's passphrase, and then each key's, at about a gigabyte of memory and seconds per guess
for both. With generated passphrases that's far beyond any attacker known today, states included: an estimate
from today's hardware and algorithms, not a proof. If P = NP comes with a practical
algorithm, though, both locks fall to whoever can afford enough computing for it: neither LUKS's AES key nor
`--protect`'s ChaCha20 key needs the passphrase to be found, and checking a guessed key is a tiny job. A thief
with a rack of GPUs is still kept out unless the algorithm is very good; a state with thousands of racks isn't
([how long would it take?](https://pnp.regulusarms.com/p-np.html)). So the locks are for the drive that's lost,
stolen or copied by an ordinary criminal. Against a state, what counts is that the drive never leaves your
custody, and that keys you must keep from a state are split into shares on drives in different places (below):
a set missing one share tells any attacker nothing, however much computing they have (the shares' bytes being
truly random).

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

3. Choose the drive's passphrase. It's what stands between a thief and your keys, so make it strong: pnp can
   make one (`pnp --gen-passphrase`, 7 random words, about 90 bits). Write it down and keep that apart from the
   drive, never in its case. If it's lost, the keys are lost.

4. Unmount the drive if your desktop mounted it, then make one partition, encrypt it with LUKS2, and put an ext4
   filesystem called `KEYS` inside:

   ```
   sudo umount /dev/sdX?* 2>/dev/null
   sudo wipefs -a /dev/sdX
   sudo parted -s /dev/sdX mklabel gpt mkpart keys 0% 100%
   sudo cryptsetup luksFormat --type luks2 --pbkdf argon2id --pbkdf-memory 1048576 --iter-time 4000 /dev/sdX1
   sudo cryptsetup open /dev/sdX1 keys
   sudo mkfs.ext4 -L KEYS /dev/mapper/keys
   sudo cryptsetup close keys
   ```

   `luksFormat` asks you to type `YES` and then the passphrase twice. `--pbkdf-memory 1048576` (KiB, so 1 GiB)
   and `--iter-time 4000` (milliseconds) make each passphrase guess cost 1 GiB of memory and about 4 seconds on
   your computer, so unlocking takes a few seconds too. That's the point.

   Use **ext4**. It overwrites file data in place, so `shred` works on it (see below), and LUKS keeps each sector
   in the same place on the disk, so that stays true underneath. Don't use btrfs or ZFS: they're copy-on-write
   and keep old copies of overwritten data.

5. Back up the LUKS header. If those first 16 MiB are ever damaged, the drive can't be opened even with the
   right passphrase. Write the backup straight to your backup drive (see "Backups" below), not to the computer:

   ```
   sudo cryptsetup luksHeaderBackup /dev/sdX1 --header-backup-file /media/$USER/HOMEKEYS/KEYS-luks-header.img
   ```

   It's restored with `sudo cryptsetup luksHeaderRestore /dev/sdX1 --header-backup-file ...`. Guard it like the
   drive: it opens with the passphrase the drive had when it was made, even after you change it with
   `cryptsetup luksChangeKey`. After a passphrase change, make a new backup and destroy the old one.

6. Unplug the drive and plug it back in. Your desktop asks for the passphrase, then mounts it at
   `/media/$USER/KEYS`. (From a terminal: `udisksctl unlock -b /dev/sdX1` says which device it unlocked as, such
   as `/dev/dm-0`; then `udisksctl mount -b /dev/dm-0`.) Make it yours, readable by you only:

   ```
   sudo chown $USER: /media/$USER/KEYS
   chmod 700 /media/$USER/KEYS
   ```

7. Write a test key to it and decrypt with it:

   ```
   echo hello > test.txt
   pnp --key-out /media/$USER/KEYS test.txt
   pnp -d -f -k /media/$USER/KEYS/test.txt.pnp.key test.txt.pnp
   ```

## Using it

The easiest way is pnp's interactive mode: type `pnp` in the folder with your files. Once the drive is unlocked
and mounted, it finds it by its `KEYS` label, writes new keys straight to it, and shows which key on it each `.pnp` file will be decrypted with.

A label is easy to copy, though: anyone could format a stick and call it `KEYS`, and if it were plugged in instead
of yours, your next keys would go to their drive. So the interactive mode remembers each drive it has written keys
to by its filesystem UUID (set when the drive was formatted, kept in `~/.local/state/pnp/drives`), and says
**"NOT the KEYS drive pnp wrote keys to before"** in red when a drive with that name shows up with another UUID.
Stop and check which drive is plugged in. If it's a new drive of yours (a replacement or a backup), writing keys
to it adds it to the list, and the warning goes away. A careful attacker could copy the UUID too, so this catches
a swap, it doesn't prove the drive is yours: keeping the drive with you does that.

- **Always write keys straight to the drive** with `--key-out /media/$USER/KEYS`. Without it, the key is written
  beside the ciphertext, on the computer's own disk, and a deleted file there may stay recoverable.
- **Unlock it only while you encrypt or decrypt**, then unmount, lock and unplug it. Ejecting it in your file
  manager does all three; from a terminal:
  `udisksctl unmount -b /dev/dm-0 && udisksctl lock -b /dev/sdX1 && udisksctl power-off -b /dev/sdX`. While it's
  unlocked, any program on the computer can read your keys.
- **Only plug it into a computer you trust.** pnp's math can't protect against malware on the machine itself,
  which could copy every key on the drive while it's unlocked, or record the drive's passphrase as you type it.
- **Keep the ciphertext elsewhere.** The `.pnp` files can go anywhere: the computer, a backup, the cloud. The drive
  holding the keys should hold no ciphertexts, so losing it alone gives nothing away.
- **Never keep a passphrase with the drive**, neither the drive's own nor a `--protect` one: not on it, not on a
  note in its case. Keep them in your head, or written down somewhere else entirely, and make them different.
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
- **Make tampering visible.** Someone with time alone with the drive can copy all of it without leaving a trace.
  Encrypted, that copy is useless to them without the passphrase; but if they can also get at the computer you
  type it on, they may get that too. A tamper-evident sticker, or a dab of glitter nail polish over a seam photographed close up, at least
  shows you that the case was opened. A copy made over USB leaves no sign, so the real protection is not letting
  the drive out of your sight.
- **If it's lost or stolen,** assume every key on it will become known to whoever has it. Any file whose
  ciphertext they can also get is exposed. Move or delete those ciphertexts if you can. The drive's encryption,
  and a strong `--protect` passphrase on top, buy you time, but treat the keys as exposed anyway: both locks are
  only computationally secure.

## Backups, and carrying only half a key

A key drive can fail, and a failed key drive means lost files. Keep at least one copy elsewhere:

- **A second copy at home** in a safe, or with someone you trust, on a second drive. For long-term archives, use
  more than one kind of storage (a second hard disk plus a USB stick or optical disc), since every kind fails
  eventually. Keep the checksum list with every copy. Encrypt each backup drive the same way, keep the LUKS
  header backups of your other drives on it, and keep its own header backup somewhere else.

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

**The whole drive, in a hurry:**

```
sudo cryptsetup luksErase /dev/sdX1
```

This destroys the LUKS key slots in seconds: after it, not even the right passphrase opens the drive. It isn't
final on its own: a header backup still opens it (destroy every copy of that too), and the keys are still on the
platter under AES, which only computational hardness protects. Overwrite the drive as below as soon as you can.

**The whole drive** (when retiring or giving it away):

```
sudo dd if=/dev/zero of=/dev/sdX bs=4M status=progress
```

This overwrites every sector, including free space and old deleted keys. Check the device name first. The one
place it can't reach is a sector the drive has retired as faulty (`Reallocated_Sector_Ct` above 0). If that
matters to you, or the drive is dead, destroy it physically: open it and drill or smash through the platters.

**Flash drives and SSDs** that ever held keys can't be reliably erased by software. Destroy them physically when
you're done with them.

## Groups on a code cylinder

If you're in a pair or group ([group.md](group.md)), your cylinder also holds its folder, `pnp-group-<ID>`. It
follows different rules from ordinary keys:

- **Never back it up, and never restore it.** A group's keys are used up as you go: every seal, signature and
  message burns a slot or a run of pad. A restored copy would bring used ones back, and using one twice breaks the
  guarantee. If the cylinder dies, report it with a kill notice and meet again.
- **The cylinder never goes to a meeting.** Meetings use courier sticks, and the import happens at home, alone.
- **Several cylinders by trust level:**
  - a daily one with the current period;
  - a vault with future periods (`pnp --move KEYSET --to VAULT`) and your kill card;
  - one per high-trust group.
- **If it's lost or stolen,** use your kill card, or ask two members, to kill the keys that were on it.

## Summary

- pnp's keys are its only secret, so how you store them is pnp's weakest link. Whoever has a key and its
  ciphertext can read the file. Without the key, the ciphertext reveals nothing but its length.
- Keep keys on a dedicated external hard disk, encrypted with LUKS2 and ext4 inside, written straight there with
  `--key-out`. The encryption makes a lost or stolen drive expensive to use, never safe: physical custody comes
  first.
- Carry it, plug it in only to use it, only into a computer you trust, and keep ciphertexts elsewhere.
- Back it up, or split keys into shares across a drive you carry and one you don't.
- Destroy a key with `shred -u` on that drive, and a whole drive with `dd` or a drill.
