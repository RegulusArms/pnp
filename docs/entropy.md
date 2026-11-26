# Measuring the hardware random sources

pnp's health tests (src/rng.h) assume each hardware source gives at least **4 bits of min-entropy per byte**, and
their cutoffs are computed from that. This page checks the assumption against real hardware with NIST's
SP 800-90B entropy assessment, and says how to measure your own machine.

## Results

Measured with NIST's `ea_non_iid` (SP800-90B_EntropyAssessment, commit 87c104d, 2026-05-26), 1,000,000 bytes per
source, 8 bits per sample, dumped with the test build's `PNP_TEST_DUMP` hook (raw source output: nothing else
mixed in).

| Machine | Source | H_original | 8 × H_bitstring | **Min-entropy** (bits/byte) | vs. the 4 assumed |
|---|---|---|---|---|---|
| AMD Ryzen Threadripper 2950X, Linux 7.0, 2026-11-26 | `/dev/hwrng` (AMD CCP, `ccp-1-rng`) | 7.72 | 7.16 | **7.16** | 1.8× margin |
| same | RDSEED | 7.35 | 7.23 | **7.23** | 1.8× margin |

The lowest estimators were the LRS test (hwrng, 7.72) and the t-tuple test (RDSEED, 7.35) on the bytes, and the
bit-string estimators overall (about 0.90 bits per bit). Every predictor estimate was above 7.9 bits per byte.

**Reading this honestly.** Both sources deliver *conditioned* output: the AMD CCP and RDSEED each run their noise
source through a cryptographic conditioner before software sees a byte. The assessment measures what pnp actually
receives, and near 8 bits per byte is what a working conditioner gives. It can't see the raw noise underneath,
which only the vendors can measure (and which no software can reach on these parts). So these numbers:

- **do** show the output pnp uses has no detectable structure, that the 4 bits per byte the health tests assume is
  conservative for it, and that the cutoffs aren't so tight that a healthy source trips them;
- **don't** prove the noise source behind the conditioner is as unpredictable as claimed: a backdoored or failing
  noise source under a good conditioner still looks like 8 bits per byte. That's why pnp XORs every source
  together with `getrandom()` instead of trusting one ([threat-model.md](threat-model.md), assumption 1).

More machines are welcome: run the steps below and send the `.txt` results (with `machine.txt`) as an issue or
pull request.

## Measure your own

```
make build/pnp-test
tests/entropy/assess.sh build/pnp-test /tmp/entropy
```

The script dumps 1,000,000 raw bytes from each usable source (reading `/dev/hwrng` needs the `pnp` group) and, if
NIST's `ea_non_iid` is installed, assesses them. It explains at the top how to build `ea_non_iid` (C++, kept apart
from pnp, which stays libc only). The number to read is the last line, `min(H_original, 8 X H_bitstring)`, in
bits per byte: well above 4 means pnp's assumption is conservative on your machine.

The dump hook exists only in the test build (`build/pnp-test`, `-DPNP_TEST`); the installed pnp can't dump raw
source bytes (`make test` checks).
