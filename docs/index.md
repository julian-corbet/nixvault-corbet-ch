# nixvault — design walkthrough

## What a vault is for

A vault is not a convenience copy of notes. It is how an operator gets back
into their own encrypted storage on the day a machine's normal unlock path no
longer exists — a dead mainboard takes its TPM with it, a firmware update
invalidates a PCR-sealed keyslot, and the only recovery has to happen on
whatever machine is actually at hand. Its payload is prioritized accordingly:
LUKS header backups first (a damaged header makes the data behind it
unrecoverable regardless of the passphrase), then the sops age keys that
decrypt everything else, then a device-role map, the Secure Boot PKI, a
plain-text runbook, and only then — space permitting — a curated slice of the
operator's own knowledge tree. See [`lib/manifest.nix`](../lib/manifest.nix)
for the exact category list and which tier packs which.

## Why passphrase-only, no TPM, no machine binding

Two independent, real failure modes rule out sealing:

- **PCR fragility.** TPM sealing binds to firmware measurements. A routine
  firmware update can silently invalidate a sealed keyslot, and the failure
  is invisible until the day the vault is actually needed — the worst
  possible moment to discover it.
- **Machine binding defeats the point.** A sealed vault opens only on the
  machine that sealed it. The one scenario a vault exists for — a dead
  mainboard, a blown firmware — is exactly the scenario in which a sealed
  vault would refuse to open. Passphrase-only means it opens anywhere: a
  replacement board, a borrowed machine, wherever the recovery is actually
  happening.

This is availability chosen over confidentiality-at-rest, which is the right
trade for an artifact whose failure mode is "did not open when needed," not
"was read by someone with no business reading it." The [OFFSITE
COPIES](#offsite-copies-are-different) section below is the one place that
trade does not survive contact.

## The lifecycle

**CREATE ONCE**, per host, per device (`nixvault-create`):

1. The container is formatted with a random, disposable master key. LUKS
   separates the master key from its keyslots, so a container can be created
   with no passphrase at all.
2. Immediately, one `luksAddKey` adds the operator's own passphrase — typed
   locally, at that console. Its entire path is: the operator's head → that
   machine's LUKS header. Never the network, never a build host, never sops.
3. The passphrase slot is verified, then the temporary random-key slot is
   removed. The passphrase is now the *only* way in.

**UPDATE MANY** times after that, and this is where ASSEMBLE and COMMIT
genuinely split — not two names for the same idempotent action:

1. `nixvault-assemble` stages the manifest into a plain directory tree
   without touching the LUKS container at all — no passphrase involved,
   safe to run on a timer, unattended.
2. `nixvault-update` is the *only* tool that ever writes into the container.
   It opens the container — the operator types the *same* passphrase they
   already know, an ordinary unlock, not a new secret being generated or
   managed — mounts the f2fs filesystem already inside it, `rsync`s the
   staged tree in so only files that actually changed are written, releases
   the compression blocks that write reserved, and closes it again. Neither
   the container nor its filesystem is ever reformatted; only the files that
   changed are rewritten.

`luksOpen` needs its passphrase every single time — there is no such thing
as an unattended one — so committing is, and must stay, a deliberate human
act, never a timer. (An earlier draft of this design claimed updates need
"no secret at all: `luksOpen` → `dd` → `luksClose`". That is false, and
was caught and corrected while this module was actually being built — see
this family's own `nixrescue.md` §7.3 for the record of that correction.)

This is why they are two different tools instead of one idempotent one: they
have a fundamentally different relationship to the passphrase. Create mints
one; update merely uses one that already exists.

## Why f2fs, not squashfs

The vault typically lives on a really slow USB stick. An earlier version of
this module formatted the container as an immutable squashfs image, rebuilt
whole and `dd`'d in whole on every commit — several GiB rewritten over slow
flash for a change of a few kilobytes. The container is a compressed,
read-write f2fs filesystem instead: formatted once, at `nixvault-create`
time, then synced into incrementally by `rsync` on every `nixvault-update`
after that, so a commit only ever writes the files that actually changed.

f2fs's own compression mount recipe is vendored, not invented, from a sibling
project's field-proven store recipe (`lib/f2fs-vault-opts.nix`). f2fs is the
right choice here even though that sibling's own rescue image deliberately
rejected it for its own store: f2fs's fs-mode compression reserves
*uncompressed* blocks until an explicit release pass runs, which is a real
problem when ingesting a whole closure in one shot into a tight partition —
but this vault is the opposite shape of write, a small payload landing on a
device with roughly ten times the headroom, written incrementally with a
release pass after every commit. Compression here is a write-speed win
against slow flash, never a capacity one — CPU time is nearly free by
comparison, so it must never be "optimised away" in the name of simplicity.

f2fs's release/reserve block accounting only becomes correct on kernel
≥ 6.12. A sibling project gets that floor for free from an unrelated
dependency; nixvault has no such freebie, so it checks the running kernel
explicitly, by name, immediately before it ever formats or mounts the
filesystem — a runtime check rather than a Nix `assertions` entry, because
this module is exported unchanged to both NixOS and system-manager, and
system-manager owns no `boot.kernelPackages` to assert against at eval time.

## Staleness is not cosmetic, and neither is drift

A header backup or a key that predates a passphrase change looks exactly
like a working recovery path and is not one. `nixvault-verify` is the
unattended **compare-and-alert** step this lifecycle actually needs: it
tracks two plain timestamps that need no passphrase to read — when content
was last staged, and when it was last actually committed — warning once
either drifts past `nixvault.staleness.maxAgeDays`, *and* it compares a
content fingerprint of the manifest tree `nixvault-assemble` just staged
against what `nixvault-update` last actually wrote into the container.

That second check cannot literally open the container to look — that would
need the passphrase, defeating the entire point of running it from a timer.
Instead, `nixvault-assemble` leaves a plaintext content fingerprint (every
file's path and content hash, folded into one digest) of the tree it just
staged, and `nixvault-update` computes the same kind of fingerprint fresh
from what is actually now inside the mounted container and stamps that as
"committed" the moment it finishes. As long as `nixvault-update` is the only
path that ever writes the container (which `nixvault-create`'s refusal to
reformat an existing one guarantees), staged == committed is an exact,
secret-free proxy for "the container already holds the current manifest". A
mismatch means the manifest moved on since the last commit — content drift,
not merely age — and `nixvault-verify` says exactly what to do about it: run
`nixvault-update`.

The alert channel itself (`staleness.alertCommand`) is a deliberate escape
hatch: a public module cannot know which host's paging system to call, so
it only logs by default and leaves the real channel to the consuming host's
own config.

## Offsite copies are different

Because `nixvault.luksVolumes` and the sops keys put an operator's own
cross-host recovery material inside the vault, a copy that leaves the
machine while still carrying the reused passphrase keyslot hands whoever has
it an **offline-attackable copy of that entire recovery material** — offline
meaning at leisure, forever, with no lockout and no rate limit. The only
thing standing in the way at that point is the entropy of a passphrase
chosen to be memorable, which is a much weaker bar than this operator's own
encryption was ever meant to rely on.

`nixvault-export-offsite` exists for exactly this boundary: it re-wraps a
**copy** of the vault with a fresh, high-entropy key (meant to be moved into
sops immediately) and removes the reused passphrase keyslot from that copy
only. The original device the vault actually lives on is never touched by
it.

**A vault is also a derived artifact** — every byte in it is rebuildable from
its declared sources (`nixvault.sources.*`, `nixvault.luksVolumes`) — so an
offsite copy of it is a *cache*, not a backup of record. Treating it as a
backup of record is how a project drifts into being the file-level backup
system this house has otherwise deliberately ruled out; the thing actually
worth protecting durably is the *sources*, not this derived snapshot of them.

## Tiers

| Tier | Budget | Adds over the tier below |
|---|---|---|
| `small` | 500 MiB | The recovery core: LUKS header backups, the device-role map, sops age keys, standalone recovery keys, the Secure Boot PKI, and a plain-text runbook. |
| `medium` | 4096 MiB | Everything `small` has, plus a curated knowledge tree, the operator's own repo sources, and rendered docs — worth the space only once the recovery core is already covered. |

There is no default tier, and there never will be an eval-time guess — see
the option description on `nixvault.tier` in
[`modules/nixvault.nix`](../modules/nixvault.nix).
