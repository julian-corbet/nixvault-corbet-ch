# nixvault

**A passphrase-only, per-host disaster-recovery vault — LUKS → a compressed,
read-write f2fs filesystem, built on the host it protects, with no TPM, no
keyfile, and no machine binding.**

## What nixvault is

A vault is not a convenience copy of notes. It is how an operator gets back
into their own encrypted storage on the day a machine's normal unlock path no
longer exists: a dead mainboard takes its TPM with it, a firmware update
invalidates a PCR-sealed keyslot, and the only recovery has to happen on
whatever machine is actually at hand. So the container is opened with
nothing but a passphrase the operator already knows — no TPM seal, no
keyfile, no binding to the machine that created it — because the one
scenario it exists for is exactly the scenario in which a sealed vault would
refuse to open.

Its payload is prioritized as disaster recovery, not as a grab-bag of files:
LUKS header backups for every encrypted volume it exists to help recover (a
damaged header makes the data behind it unrecoverable regardless of the
passphrase), the sops age keys that decrypt everything else, a device-role
map, the Secure Boot PKI needed to re-sign after a board swap, a plain-text
runbook readable with nothing but `cat`, and — only once all of that is
covered — a curated slice of the operator's own knowledge tree. See
[`lib/manifest.nix`](lib/manifest.nix) for the full category list and which
tier packs which, and [`docs/index.md`](docs/index.md) for the full design
walkthrough.

**The lifecycle has two genuinely different halves**, and the module ships a
different tool for each because they have a different relationship to the
passphrase:

- **`nixvault-create`** — run exactly once, per host, per device. Formats
  the container with a random, disposable master key, then immediately runs
  one `luksAddKey` where the operator types their own passphrase, locally.
  That passphrase never touches the network, a build host, or sops.
- **`nixvault-assemble`** — stages the manifest into a plain directory tree.
  Touches no LUKS container at all, needs no passphrase, and is safe to run
  on a timer, unattended.
- **`nixvault-update`** — the ONLY tool that ever writes into the container.
  Opens it with the operator's existing passphrase (an ordinary unlock, not
  a new secret) — `luksOpen` needs its passphrase every time, so this step
  can never be unattended, on purpose — mounts the vault's own f2fs
  filesystem and `rsync`s the staged tree in, so only files that actually
  changed are ever written, then releases the compression blocks that write
  reserved and closes the container again. Neither the container nor its
  filesystem is ever reformatted; only the files that changed are rewritten.
- **`nixvault-verify`** — the unattended compare-and-alert step: warns if
  either the staged image or the on-disk vault contents have gone stale
  (`staleness.maxAgeDays`), *and* compares a plaintext fingerprint of what
  was just staged against what `nixvault-update` last actually committed —
  detecting that the manifest has moved on since the last commit without
  ever needing to open the container to check. A header backup that
  predates a passphrase change looks like a recovery path and is not one.
- **`nixvault-export-offsite`** — re-wraps a *copy* of the vault with a
  fresh, high-entropy key and drops the reused passphrase keyslot from that
  copy before it leaves the machine. See [`docs/index.md`](docs/index.md#offsite-copies-are-different)
  for why an offsite copy cannot carry the same keyslot the local container
  does.

## Why f2fs, not squashfs

The vault typically lives on a really slow USB stick. An earlier version of
this module formatted the container as an immutable squashfs image, rebuilt
whole and `dd`'d in whole on every commit — several GiB rewritten over slow
flash for a change of a few kilobytes of runbook text. The container is now
a compressed, read-write f2fs filesystem instead: formatted once at
`nixvault-create` time, then synced into incrementally by `rsync` on every
`nixvault-update` after that, so a commit only ever writes the files that
actually changed.

f2fs's compression mount recipe is consumed directly from
[nixfs](https://github.com/julian-corbet/nixfs-corbet-ch)
(`lib.catalogue.filesystems.f2fs.compression`) — the one canonical copy of
the same field-proven recipe the sibling
[nixnas](https://github.com/julian-corbet/nixnas-corbet-ch) project's own
store uses, never a second, independently-vendored copy. f2fs is the right
choice here even though nixnas's own rescue SLOT deliberately rejected it:
f2fs's fs-mode compression reserves *uncompressed* blocks until an explicit
release pass runs, which is a real problem when ingesting a whole closure in
one shot into a tight partition — but this vault is the opposite shape of
write, a small payload landing on a device with roughly ten times the
headroom, written incrementally with a release pass after every commit.
Compression here is a write-speed win against slow flash, never a capacity
one — CPU time is nearly free by comparison. See `modules/nixvault.nix`'s own
header for the full reasoning, including the kernel floor (≥ 6.12) f2fs's
release/reserve block accounting needs.

## Status

The module, manifest, and lifecycle tools are complete, exported for both
NixOS and system-manager (see "Two backends" below), and covered by both
eval-time tests and a real `pkgs.testers.nixosTest` runtime harness
(`checks/lifecycle-vm-test.nix`) that exercises the whole
create → assemble → commit → drift-detect round trip against a real LUKS
container on a loopback file, including both failing directions (a wrong
passphrase, a stale/drifted vault) and a measured proof that a second commit
touching one small file writes materially less than the first commit of the
whole manifest — see "Why f2fs, not squashfs" below.

## Two backends, one file

`nixosModules.default` and `systemManagerModules.default` are the same file,
unchanged. That is possible, not a shortcut: nixvault only ever touches
option surface system-manager supports identically to NixOS —
`environment.systemPackages`, `systemd.services`/`systemd.timers`,
`assertions`, `warnings` — confirmed by reading system-manager's own module
source rather than assumed. It never needed `users.users`, `boot.*`, or any
NixOS-only systemd-generator integration in the first place, so there was
nothing to design around. See `modules/nixvault.nix`'s own "ONE FILE, BOTH
BACKENDS" header for the full accounting, and `checks/default.nix`'s
backend-parity tests for the CI proof that both backends actually agree.

```nix
# On a foreign (non-NixOS) host applying its config via system-manager:
imports = [ inputs.nixvault.systemManagerModules.default ];
```

## Usage

```nix
{
  inputs.nixvault.url = "github:julian-corbet/nixvault-corbet-ch";

  outputs = { self, nixpkgs, nixvault, ... }: {
    nixosConfigurations.myhost = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        nixvault.nixosModules.default

        {
          nixvault = {
            enable = true;
            tier = "small"; # or "medium" -- no default, see lib/manifest.nix
            device = "/dev/disk/by-id/..."; # this host's own vault partition or file

            # Every LUKS volume this vault should carry a header backup for --
            # across all hosts, not just this host's own.
            luksVolumes = [
              { name = "myhost-root"; device = "/dev/disk/by-id/..."; }
            ];

            sources.sopsAgeKeys = [ "/var/lib/sops/keys.txt" ];
            sources.runbook = [ "/etc/nixvault/runbook.md" ];
          };
        }
      ];
    };
  };
}
```

Then, on that host:

```console
# once, ever, per device:
$ sudo nixvault-create

# routinely, as often as the manifest changes:
$ sudo nixvault-assemble
$ sudo nixvault-update
```

`nixvault-assemble` also runs automatically on a timer
(`nixvault.schedule.onCalendar`, default `daily`) so the staged manifest never
drifts far behind `nixvault.sources.*`; `nixvault-update` is never automated,
on purpose, because it needs the operator's passphrase.

## Repository layout

| Path | Purpose |
|---|---|
| `flake.nix` | Flake entry point: `nixosModules.default` / `systemManagerModules.default` (the same file, both backends), and `lib.manifest`. |
| `modules/nixvault.nix` | The module: options, assertions, and the five lifecycle tools. |
| `lib/manifest.nix` | Pure data: the tiers, their size budgets, and the manifest categories each one packs. |
| *(no local `lib/facts.nix`)* | `lib.probeFact`/`lib.collectProbes` are consumed from [nixhost](https://github.com/julian-corbet/nixhost-corbet-ch)'s own `lib/facts.nix` via this repo's `nixhost` flake input (see `flake.nix`), not reinvented or vendored here. Distinguishes "nixstorage not composed" from "nixstorage composed but `layout.images`/`disks` renamed" for `nixvault.deviceFromLayout`/`luksVolumes[].fromDisk`'s own reads -- see nixhost's own header. |
| `checks/` | Eval-time tests (including NixOS/system-manager backend parity) plus the real `pkgs.testers.nixosTest` lifecycle harness, all wired into `nix flake check`. |
| `docs/index.md` | The design walkthrough: why passphrase-only, the create/update split, staleness, and the offsite-copy boundary. |
| `experiments/` | Runnable trials with recorded results — see [`experiments/README.md`](experiments/README.md). |
| `studies/` | Written investigations that motivate design decisions — see [`studies/README.md`](studies/README.md). |

## Related projects

Part of the same small, independently-usable NixOS module family:
[nixram](https://github.com/julian-corbet/nixram-corbet-ch) (the VM-test
pattern this project's own `checks/lifecycle-vm-test.nix` copies),
[nixboot](https://github.com/julian-corbet/nixboot-corbet-ch) (the
prose-option, one-knob-one-owner house style), and
[nixnas](https://github.com/julian-corbet/nixnas-corbet-ch) (the sibling
project whose USB store field-validated the same f2fs compression recipe
this vault's own container uses — see "Why f2fs, not squashfs" above).
nixvault has no dependency on nixram, nixboot, or nixnas — it is built to sit
in front of any host, independent of whatever rescue layer or boot stance
that host uses. The one real exception is
[nixfs](https://github.com/julian-corbet/nixfs-corbet-ch) itself, a genuine
flake input for exactly one thing: `lib.catalogue`, the data/module split
this project's own `lib/manifest.nix` follows, and (since that recipe moved
there) the one canonical copy of the f2fs mkfs/mount facts above — a
lower-layer lib dependency, never nixfs's own NixOS module, which this
project has no reason to install.

## License

[MIT License](LICENSE) &copy; 2026 Julian Corbet
