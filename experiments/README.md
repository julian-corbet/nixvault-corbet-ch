# Experiments

Runnable experiments with recorded results. Each experiment gets its own
directory with a README stating hypothesis, method, and outcome.
Cross-linked from [`studies/`](../studies/README.md) where a study motivated
it.

One experiment settled; two candidates remain open.

## 001 — a `pkgs.testers.nixosTest` covering the full lifecycle end to end — SETTLED

**Hypothesis:** the create → assemble → commit split (and the
`nixvault-verify` compare/alert step it depends on) is real, working
behavior, not just what the module's comments claim it does — provable only
by driving the actual tools against a real LUKS container, never by eval
alone.

**Method:** `checks/lifecycle-vm-test.nix`, a `pkgs.testers.nixosTest` against
a plain pre-sized regular file as the vault's LUKS container (never a real or
emulated block device — proving `nixvault.device`'s own claim that cryptsetup
treats a file and a block device identically). Drives `nixvault-create`
(random master key → operator passphrase → reformat-refusal), `nixvault-assemble`
(including a real `luksHeaderBackup` against a second, genuinely-formatted
dummy volume — the "generated" category pipeline, not just static sources),
`nixvault-verify` before and after a commit, `nixvault-update`, a cold
reopen-and-mount to read real staged content back, both failing directions
(a wrong passphrase against both a raw `cryptsetup open` and
`nixvault-update` itself; a backdated timestamp with unchanged content), and
a content-drift round trip (edit the source, re-assemble, confirm
`nixvault-verify` detects the mismatch and alerts, confirm committing clears
it). Same house pattern as
[nixram](https://github.com/julian-corbet/nixram-corbet-ch)'s
`checks/swappiness-relief-vm-test.nix` and
[nixrescue](https://github.com/julian-corbet/nixrescue-corbet-ch)'s
`checks/rescue-vm-test.nix`.

**Outcome:** all thirteen subtests pass. The design correction in the
sealed record this module implements — `luksOpen` needs its passphrase every
time, so a vault refresh cannot be unattended — was already built correctly
before that record caught up; what this experiment actually found missing
was the **compare** step: `nixvault-verify` tracked staleness by age alone
and had no way to detect that the manifest had moved on since the last
commit. Fixed by having `nixvault-assemble` and `nixvault-update` each stamp
a plaintext sha256 fingerprint (staged vs. committed) that `nixvault-verify`
diffs — no passphrase needed to compare, only to act on what the compare
finds.

## Open candidates

- A real-hardware trial of `nixvault-export-offsite` against an actual
  low-entropy human passphrase, confirming the re-wrap genuinely removes that
  keyslot (`cryptsetup luksDump` before/after) rather than merely appearing
  to from the command's own output.
- A timing measurement of `mksquashfs -Xcompression-level 22` against the
  `medium` tier's real 4 GiB budget once a real manifest exists, to confirm
  the packing pipeline stays fast enough to run on every `nixvault-assemble`
  timer firing rather than only being acceptable as a one-off.
