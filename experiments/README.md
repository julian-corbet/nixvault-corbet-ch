# Experiments

Runnable experiments with recorded results. Each experiment gets its own
directory with a README stating hypothesis, method, and outcome.
Cross-linked from [`studies/`](../studies/README.md) where a study motivated
it.

No experiments have been run yet. Candidates, in the order they would
actually close real risk:

- A `pkgs.testers.nixosTest` covering the full lifecycle end to end against a
  loopback-file "device": `nixvault-create` against a scripted (non-interactive)
  passphrase, `nixvault-assemble` staging a synthetic manifest, `nixvault-update`
  writing it in, then mounting the result read-only and asserting every
  declared category actually landed. This is the harness the sibling
  [nixrescue](../modules/nixvault.nix) design record argues should come
  *before* the rest of a domain is built, not after -- same posture as the
  disposable-VM tests in [nixram](https://github.com/julian-corbet/nixram-corbet-ch)
  (`nixram/checks/swappiness-relief-vm-test.nix`).
- A real-hardware trial of `nixvault-export-offsite` against an actual
  low-entropy human passphrase, confirming the re-wrap genuinely removes that
  keyslot (`cryptsetup luksDump` before/after) rather than merely appearing
  to from the command's own output.
- A timing measurement of `mksquashfs -Xcompression-level 22` against the
  `medium` tier's real 4 GiB budget once a real manifest exists, to confirm
  the packing pipeline stays fast enough to run on every `nixvault-assemble`
  timer firing rather than only being acceptable as a one-off.
