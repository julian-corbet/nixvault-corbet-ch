# Experiments

Runnable experiments with recorded results. Each experiment gets its own
directory with a README stating hypothesis, method, and outcome.
Cross-linked from [`studies/`](../studies/README.md) where a study motivated
it.

Two experiments settled; one candidate remains open.

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

**Outcome:** all fourteen subtests pass. The design correction in the
sealed record this module implements — `luksOpen` needs its passphrase every
time, so a vault refresh cannot be unattended — was already built correctly
before that record caught up; what this experiment actually found missing
was the **compare** step: `nixvault-verify` tracked staleness by age alone
and had no way to detect that the manifest had moved on since the last
commit. Fixed by having `nixvault-assemble` and `nixvault-update` each stamp
a plaintext content fingerprint (staged vs. committed) that `nixvault-verify`
diffs — no passphrase needed to compare, only to act on what the compare
finds. (Originally run against a squashfs image; the container has since
moved to a mounted f2fs filesystem — see experiment 002 — and this test was
updated in place rather than superseded, since the lifecycle it proves did
not change.)

## 002 — incremental f2fs commits write only what changed, measured — SETTLED

**Hypothesis:** replacing the whole-volume squashfs rewrite with an
incremental `rsync` into a mounted f2fs filesystem actually reduces bytes
written on a commit that only changes a small file, not merely in theory —
provable only by measuring real write volume, never by asserting the design
should work.

**Method:** extended `checks/lifecycle-vm-test.nix` with a large,
incompressible "bulk" file that sits in the manifest throughout and is never
touched after its first commit. The vault's LUKS container backing file's
allocated-block count (`stat -c%b`, the kernel's own real-usage accounting)
is measured immediately either side of two commits: the first, of the whole
manifest including the bulk file; the second, changing only a few bytes of
the runbook. `nodiscard` (part of the shared recipe in nixfs's
`lib/catalogue.nix`, `filesystems.f2fs.compression`) keeps freed
blocks from being punched back to sparse holes, which is what makes an
allocated-block delta a faithful proxy for real bytes written to the block
layer for that specific commit.

**Outcome:** the first commit's delta comfortably exceeds the 8 MiB bulk
file's size; the second commit's delta is a small fraction of the first's
and stays under an absolute few-MiB ceiling, even though nothing in either
commit's assertions or command sequence changed except which files actually
differed since the last commit. Confirms the incremental-commit design
change delivers what it was built for, not merely that it was implemented.

## Open candidates

- A real-hardware trial of `nixvault-export-offsite` against an actual
  low-entropy human passphrase, confirming the re-wrap genuinely removes that
  keyslot (`cryptsetup luksDump` before/after) rather than merely appearing
  to from the command's own output.
