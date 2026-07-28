# Studies

Written investigations that motivate design decisions — comparisons, failed
approaches, upstream research. Cross-linked from
[`experiments/`](../experiments/README.md) where a study led to a runnable
experiment.

No studies have been written yet. The material that would seed the first one
already exists as evidence inside the module itself rather than as a separate
document — see the header of [`modules/nixvault.nix`](../modules/nixvault.nix)
for why the container is passphrase-only with no TPM and no machine binding,
why `nixvault-create` and `nixvault-update` are two different tools instead of
one idempotent one, and why an offsite copy needs its own re-wrap step. A
written study belongs here once that reasoning needs to be argued from prior
art (other disaster-recovery-vault designs, other LUKS-header-backup
conventions) rather than restated from the module's own comments — for
example, a comparison of the `nixvault-export-offsite` re-wrap approach
against Shamir's Secret Sharing or a hardware security key as alternative
offsite-safe mechanisms, which was considered but not pursued here for
complexity reasons that deserve a fuller writeup than a code comment.
