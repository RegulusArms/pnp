# Recovering after an interrupted run

pnp writes every output under a hidden name first and renames it into place only when it's complete
(src/fileio.c). It's designed so that a run that's killed, crashes or loses power partway never leaves a
half-written file under a real name, and never loses an old key. Kills and crashes are tested (below); a power
cut is covered by design only, until real power-loss testing is done. It can leave hidden files behind, though, and the next pnp run that
writes into (or reads from) that folder points them out:

```
pnp: note: /home/you/docs holds files left by a pnp run that was interrupted (a crash, a kill or a power cut):
  .report.pdf.pnp.Xk3d9A.pnp-part: an unfinished report.pdf.pnp (it may hold pad or plaintext bytes). Delete it, ...
  .report.pdf.pnp.key.Qm2pL7.pnp-old: the old report.pdf.pnp.key, moved aside by pnp -f to be replaced. ...
```

pnp never deletes or renames these itself: only you can tell which copy you want. `ls -a` shows them.

## The two kinds

| Hidden name | What it is | What to do |
|---|---|---|
| `.NAME.XXXXXX.pnp-part` | An output that was never finished, or finished but not yet renamed to `NAME` | Delete it, then run pnp again if `NAME` is missing. It may hold pad bytes (a key's part) or plaintext (a decryption's part), so delete it as you would the real thing. |
| `.NAME.XXXXXX.pnp-old` | An old `NAME` that `pnp -f` moved aside so it could be replaced, and that the interrupted run never got to delete or put back | See below: it belongs with the other `.pnp-old` files of the same run. |

## After an interrupted encryption

The file you were encrypting is never touched, so the simplest fix is always: delete the leftovers and the
outputs of the interrupted run, and encrypt again.

- **Without `-f`:** pnp saves the key (or every share) first and the ciphertext last. So you may find a key with
  no ciphertext (harmless: delete it), but never a ciphertext without its key. A `NAME.pnp` under its real name
  always has its whole key.
- **With `-f` (replacing an old ciphertext and key):** the old files are moved aside to `.pnp-old` names first,
  the new ones take their places, and only then are the old ones deleted. If the run stopped in between, either:
  - **undo it:** put back *every* `.pnp-old` file of that run, ciphertext and key (or shares) together, replacing
    whatever is under the real names now, and delete the `.pnp-part` files. That's exactly the state before the
    run. With `--key-out`, look in the key's folder too: the note lists each folder.
    ```
    mv -f '.report.pdf.pnp.key.Qm2pL7.pnp-old' report.pdf.pnp.key      # in the key's folder
    mv -f '.report.pdf.pnp.Ab9xYz.pnp-old' report.pdf.pnp              # in the ciphertext's folder
    rm .report.pdf.pnp.*.pnp-part                                      # in each folder
    ```
  - **or keep the new ones:** if `pnp --verify report.pdf.pnp` says the ciphertext and key under the real names
    are whole, the run had finished saving them; delete the `.pnp-old` files.

  Don't mix the two: an old ciphertext with a new key (or the other way round) don't belong together, and pnp
  refuses them ("isn't the key for ... (they're from different encryptions)").

## After an interrupted decryption

The ciphertext and key are only read, never changed. The decrypted file takes its name only after the integrity
check passes, so a `NAME` under its real name is always complete and checked. Delete any `.pnp-part` (it holds
plaintext that may not have been checked yet) and decrypt again. With `-f`, the old `NAME` is replaced in one
atomic rename: you'll find either the old file or the new one, never a mix.

## Checking long-term archives

`pnp --verify FILE.pnp` checks a ciphertext against its key or shares (that they belong together, their sizes,
and the integrity check over every byte) without writing anything. Run it now and then on archived files, and
before relying on a key drive.

## How this is tested

tests/run.sh kills pnp (SIGKILL, no clean-up) at every step of writing and saving, one step per run: each write,
fsync, rename, link and unlink, for encrypting with the key on another filesystem, `-f` replacing a ciphertext and
key, `-f` with three shares, and decrypting over an existing file. After each kill it checks that the plaintext is
untouched, that a ciphertext under its real name has its whole key, and that the state is either finished or is
put back exactly by the "undo" above. A kill leaves the file names in every state they can be in; that each state
also survives a power cut is a design objective, resting on pnp's fsyncs (of each file before its rename, and of
the folder after) and on the filesystem honouring them. It hasn't been tested with a simulated power cut yet
(dm-log-writes or dm-flakey; TODO.md).
