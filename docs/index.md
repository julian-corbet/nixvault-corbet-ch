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

**UPDATE MANY** times after that (`nixvault-assemble` then
`nixvault-update`), and this needs no *new* secret:

1. `nixvault-assemble` stages the manifest and builds a squashfs image
   without touching the LUKS container at all — no passphrase involved,
   safe to run on a timer, unattended.
2. `nixvault-update` opens the container — the operator types the *same*
   passphrase they already know, an ordinary unlock, not a new secret being
   generated or managed — writes the fresh image straight into the mapper
   device, and closes it again. The container is never reformatted; only its
   contents change.

This is why they are two different tools instead of one idempotent one: they
have a fundamentally different relationship to the passphrase. Create mints
one; update merely uses one that already exists.

## Staleness is not cosmetic

A header backup or a key that predates a passphrase change looks exactly
like a working recovery path and is not one. `nixvault-verify` tracks two
plain timestamps that need no passphrase to read — when content was last
staged, and when it was last actually written into the container — and warns
once either drifts past `nixvault.staleness.maxAgeDays`. The alert channel
itself (`staleness.alertCommand`) is a deliberate escape hatch: a public
module cannot know which fleet's paging system to call, so it only logs by
default and leaves the real channel to the consuming host's own config.

## Offsite copies are different

Because `nixvault.luksVolumes` and the sops keys put an operator's own
fleet-wide recovery material inside the vault, a copy that leaves the
machine while still carrying the reused passphrase keyslot hands whoever has
it an **offline-attackable copy of that entire recovery material** — offline
meaning at leisure, forever, with no lockout and no rate limit. The only
thing standing in the way at that point is the entropy of a passphrase
chosen to be memorable, which is a much weaker bar than the fleet's own
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
