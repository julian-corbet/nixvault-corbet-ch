# nixvault

**A passphrase-only, per-host disaster-recovery vault — LUKS → squashfs,
built on the host it protects, with no TPM, no keyfile, and no machine
binding.**

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
- **`nixvault-assemble`** — stages the manifest and builds the squashfs
  image. Touches no LUKS container at all, needs no passphrase, and is safe
  to run on a timer, unattended.
- **`nixvault-update`** — opens the container with the operator's existing
  passphrase (an ordinary unlock, not a new secret), writes the fresh image
  in, and closes it. The container is never reformatted; only its contents
  change.
- **`nixvault-verify`** — warns if either the staged image or the on-disk
  vault contents have gone stale, because a header backup that predates a
  passphrase change looks like a recovery path and is not one.
- **`nixvault-export-offsite`** — re-wraps a *copy* of the vault with a
  fresh, high-entropy key and drops the reused passphrase keyslot from that
  copy before it leaves the machine. See [`docs/index.md`](docs/index.md#offsite-copies-are-different)
  for why an offsite copy cannot carry the same keyslot the local container
  does.

## Status

Fresh project. The module, manifest, and lifecycle tools are complete and
covered by eval-time tests (`checks/`); no `pkgs.testers.nixosTest` runtime
harness exists yet — see [`experiments/README.md`](experiments/README.md) for
where that work would land, and the sibling
[nixram](https://github.com/julian-corbet/nixram-corbet-ch) project for the
pattern it would copy.

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
            # fleet-wide, not just this host's own.
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
(`nixvault.schedule.onCalendar`, default `daily`) so the staged image never
drifts far behind `nixvault.sources.*`; `nixvault-update` is never automated,
on purpose, because it needs the operator's passphrase.

## Repository layout

| Path | Purpose |
|---|---|
| `flake.nix` | Flake entry point: `nixosModules.nixvault` / `nixosModules.default`, and `lib.manifest`. |
| `modules/nixvault.nix` | The module: options, assertions, and the five lifecycle tools. |
| `lib/manifest.nix` | Pure data: the tiers, their size budgets, and the manifest categories each one packs. |
| `checks/` | Eval-time tests wired into `nix flake check`. |
| `docs/index.md` | The design walkthrough: why passphrase-only, the create/update split, staleness, and the offsite-copy boundary. |
| `experiments/` | Runnable trials with recorded results — see [`experiments/README.md`](experiments/README.md). |
| `studies/` | Written investigations that motivate design decisions — see [`studies/README.md`](studies/README.md). |

## Related projects

Part of the same small, independently-usable NixOS module family:
[nixram](https://github.com/julian-corbet/nixram-corbet-ch) (the VM-test
pattern this project's own future runtime tests would copy),
[nixfs](https://github.com/julian-corbet/nixfs-corbet-ch) (the data/module
split this project's `lib/manifest.nix` follows), and
[nixboot](https://github.com/julian-corbet/nixboot-corbet-ch) (the
prose-option, one-knob-one-owner house style). nixvault has no dependency on
any of them — it is built to sit in front of any host, independent of
whatever rescue layer or boot stance that host uses.

## License

[MIT License](LICENSE) &copy; 2026 Julian Corbet
