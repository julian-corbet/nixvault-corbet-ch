#
# modules/nixvault.nix -- a small, passphrase-only recovery vault, built on the host it protects.
#
# THE GAP THIS CLOSES. Every other piece of encrypted storage on a fleet has an unlock path that
# depends on the machine it lives on: a TPM that seals to firmware measurements, a keyfile that
# sits on the same disk, an initrd that only exists on that one box. All of that is exactly backwards
# for the one artifact whose entire job is surviving the day a machine's own unlock path is gone --
# a dead mainboard takes its TPM with it; a firmware update invalidates a PCR-sealed keyslot; the
# laptop you actually have with you is not the one that sealed the container. A vault is the answer:
# LUKS -> f2fs, built on the host that will carry it, opened with nothing but a passphrase the
# operator already knows, so it opens anywhere -- a replacement board, a borrowed machine, wherever
# the recovery is actually happening.
#
# ITS PAYLOAD IS DISASTER RECOVERY, NOT A CONVENIENCE COPY OF NOTES. In priority order: LUKS header
# backups for every encrypted volume this vault exists to help recover (a damaged header makes the
# data behind it unrecoverable regardless of the passphrase); the sops age keys that decrypt
# everything else the operator has encrypted (without these the rest of the vault is inert
# ciphertext); a device-to-role map; the Secure Boot PKI needed to re-sign after a board swap; a
# plain-text runbook readable with nothing but `cat`; and, only once all of that is covered, a
# curated slice of the operator's own knowledge tree. See lib/manifest.nix for the full category
# list and which tier packs which.
#
# WHY F2FS, NOT SQUASHFS -- an earlier version of this module formatted the container as an
# immutable squashfs image, rebuilt whole and `dd`'d in whole on every commit. That was wrong for
# the one fact that actually matters about this vault's hardware: it lives on a REALLY slow USB
# stick. Rewriting several GiB of squashfs over slow flash for a change of a few kilobytes of
# runbook text is exactly backwards. The container is now a compressed, read-write f2fs
# filesystem instead, formatted ONCE at `nixvault-create` time (the same one-time act as the LUKS
# format it rides alongside) and synced into incrementally by every `nixvault-update` after that --
# see THE LIFECYCLE below for what "synced into incrementally" actually means.
#
# f2fs's mount recipe (`lib/f2fs-vault-opts.nix`) is VENDORED, not invented, from the sibling
# nixnas project's own field-proven store recipe (its `modules/lib/f2fs-store-mount-opts.nix` +
# `modules/boot/disk.nix`'s mkfs invocation, `docs/STORAGE.md` §§4-6) -- and f2fs is the RIGHT
# choice here even though that sibling's own rescue SLOT deliberately rejected it. The reason it
# was wrong there is that f2fs's fs-mode compression reserves UNCOMPRESSED blocks until an
# explicit `release_cblocks` pass runs, which bites hard when ingesting a whole closure in one
# shot into a partition with almost no headroom to spare. This vault is the opposite shape of
# write entirely: a small payload (the tier budgets are 500 MiB / 4096 MiB) landing on a device
# sized with roughly TEN TIMES that headroom, written incrementally -- one changed file at a time
# -- with a release pass run after every commit, not deferred to some later maintenance window.
# The accounting gate f2fs's reservation-until-release behavior creates never gets anywhere near
# full on this container. Do not "fix" this by arguing back to squashfs; the slow-flash problem
# squashfs actually had (whole-volume rewrites) is the one f2fs solves, and the tight-partition
# problem f2fs actually had (in the rescue SLOT) simply does not exist here.
#
# COMPRESSION HERE IS A WRITE-SPEED WIN, NOT A CAPACITY ONE -- say so here so nobody later
# "optimises" it away by pointing at the tier budgets and asking why a vault this small needs
# compression at all. The point was never fitting more into the budget: CPU time spent compressing
# is nearly free set against how slow the underlying USB flash is, so every byte compression keeps
# off that flash is a real, measurable time saved on every commit. Do not remove `compress_*` mount
# options in the name of "simplifying" this module -- that would trade a free win for none.
#
# THE KERNEL FLOOR THIS RELIES ON: f2fs's release/reserve `i_blocks` accounting only becomes
# correct on kernel >= 6.12 (see `docs/STORAGE.md` §5's own citation trail on the sibling project).
# That project gets this floor for free from an unrelated dependency -- its ZFS pools force a
# recent-enough kernel regardless of f2fs. nixvault has no such freebie: it is not tied to any
# other subsystem's kernel cap, so it checks the running kernel explicitly, by name, at the one
# moment it matters (immediately before `nixvault-create` formats the filesystem, and immediately
# before `nixvault-update` mounts it) rather than assuming whatever kernel happens to be running
# is new enough. See the `kernelFloorGuard` script fragment below for why this is a RUNTIME check
# rather than a Nix `assertions` entry -- the short version: this module owns no `boot.*` surface
# on either backend it exports to, and system-manager in particular has no `boot.kernelPackages` to
# assert against at eval time in the first place.
#
# PASSPHRASE ONLY. NO TPM. NO KEYFILE. NO MACHINE BINDING. This is decided, not an oversight:
# TPM-sealed keyslots are bound to firmware measurements that change under routine updates, and a
# sealed vault opens only on the machine that sealed it -- which is exactly the machine that is
# gone in the one scenario this vault exists for. Passphrase-only trades confidentiality-at-rest
# for availability, which is the correct trade for an artifact whose failure mode is "did not open
# when needed", not "was read by someone with no business reading it". See the OFFSITE COPIES note
# below for the one place that trade does not survive contact.
#
# THE LIFECYCLE -- read this before touching nixvault-create or nixvault-update.
#
#   CREATE ONCE, per host, per device. `nixvault-create` formats the target with a random,
#   disposable master key (a container can be created with no passphrase at all -- LUKS separates
#   the master key from its keyslots), then immediately runs ONE `luksAddKey` where the operator
#   types their own passphrase, locally, at the console. That passphrase's entire path is: the
#   operator's head -> that machine's LUKS header. It is never generated by, sent to, or stored on
#   anything else -- never the network, never a build host, never sops. Then, still with that same
#   passphrase, `nixvault-create` opens the container ONE more time and runs `mkfs.f2fs` on it --
#   the filesystem is formatted exactly once here, the same one-time posture as the LUKS format
#   itself, never repeated by any later tool. Finally the temporary random key is shredded and its
#   keyslot removed, so the passphrase becomes the ONLY way into the container.
#
#   UPDATE MANY times after that, and this is where ASSEMBLE and COMMIT genuinely split, not two
#   names for one idempotent action. `nixvault-assemble` stages the manifest into a plain directory
#   tree entirely without touching the LUKS container -- no passphrase involved at all, so it is
#   the one part of this lifecycle safe to run unattended, off `schedule.onCalendar`.
#   `nixvault-update` is the ONLY thing that ever writes into the container: it opens it (the
#   operator types the SAME passphrase they already know -- a normal unlock, not a new secret being
#   created or managed), mounts the f2fs filesystem already sitting inside it, `rsync`s the staged
#   tree in -- so only files that actually changed since the last commit are written at all, not
#   the whole manifest -- runs f2fs's compression release pass so those writes' reserved-but-unused
#   blocks are freed back to the filesystem, then unmounts and closes it again. Opening a LUKS
#   container needs its passphrase full stop -- there is no such thing as an unattended `luksOpen`
#   -- so committing is, and must stay, a deliberate human act, never a timer. The container itself
#   is never reformatted, and its filesystem is never rebuilt from scratch either; only the files
#   that changed are ever rewritten. This is the whole reason nixvault-create and nixvault-update
#   are two different tools instead of one idempotent one -- they have completely different
#   relationships to the passphrase.
#
#   (CORRECTED HERE having once been stated wrong: an earlier draft of the design record this
#   module implements claimed updates need "no secret at all: luksOpen -> dd -> luksClose". That
#   is false -- `luksOpen` needs the passphrase every time -- and the record itself now says so;
#   see nixrescue.md §7.3's own correction. This module was already built the right way round
#   before that record caught up: assemble unattended, commit attended, never the reverse. That
#   correction is exactly as true of the f2fs-based commit above as it was of the old dd-a-squashfs
#   one -- swapping the payload format never touched which half of the lifecycle needs the secret.)
#
#   STALENESS IS NOT COSMETIC HERE, and neither is DRIFT. A header backup or key that predates a
#   passphrase change looks exactly like a working recovery path and is not one. `nixvault-verify`
#   is the unattended COMPARE + ALERT step the timer actually runs: it re-checks two on-disk
#   timestamps that need no passphrase to read -- when content was last staged, and when it was
#   last actually committed -- against `staleness.maxAgeDays`, AND it compares a plaintext content
#   fingerprint of the manifest tree `nixvault-assemble` just staged against what `nixvault-update`
#   last actually wrote into the container. That second check cannot literally open the container
#   to look (that would need the passphrase, defeating the point of running it from a timer) --
#   instead `nixvault-assemble` fingerprints every file path and its content hash in the tree it
#   just staged, folded into one digest, and `nixvault-update` computes the SAME kind of digest
#   fresh from what is actually now sitting inside the mounted container and stamps that as
#   "committed" the moment the commit finishes -- computed from the container's own contents, not
#   copied from nixvault-assemble's own value, so a bug or a race in staging can't quietly pass
#   this check. As long as nixvault-update is the only write path into the container (nixvault-create
#   refuses to reformat an existing one, so it is), staged == committed is an exact, secret-free
#   proxy for "the container already holds this". A mismatch means the manifest has moved on since
#   the last commit -- content drift, not merely age -- and `nixvault-verify` says so in as many
#   words: run nixvault-update. `staleness.alertCommand` is a deliberate escape hatch rather than a
#   hardcoded channel: a public module cannot know which fleet's paging system to call.
#
# THE PACKING PIPELINE (nixvault-assemble): rm -rf the staging directory, re-populate it (generated
# categories from `cryptsetup luksHeaderBackup` against `nixvault.luksVolumes`; static categories
# from whatever paths `nixvault.sources.<category>` names). Unlike the old squashfs pipeline,
# nothing is built here -- the staged directory tree IS the thing `nixvault-update` later `rsync`s
# into the container, verbatim. The staged tree sits in plaintext in `stateDirectory` until
# `nixvault-update` syncs it in; that is a live-host-local duplicate of material this host already
# holds in plaintext somewhere (the sources it was copied from), not a new exposure, and
# `stateDirectory` is created 0700 accordingly. It is exactly the reason the staging directory must
# never itself be copied anywhere -- only the LUKS container is meant to travel.
#
# OFFSITE COPIES ARE THE ONE PLACE THE PASSPHRASE-ONLY TRADE DOES NOT SURVIVE CONTACT. Because
# `nixvault.luksVolumes` and the sops keys put the fleet's OWN recovery material inside the vault,
# a copy that leaves this machine still carrying the reused passphrase keyslot hands whoever has it
# an offline-attackable copy of that recovery material -- offline meaning at leisure, forever, no
# lockout, no rate limit. `nixvault-export-offsite` exists for exactly this: it re-wraps a COPY with
# a fresh high-entropy key (meant to be moved into sops) and removes the passphrase keyslot from
# that copy only. The original device this vault lives on is never touched by it. A vault is also a
# DERIVED artifact -- rebuildable from its sources -- so an offsite copy is a cache, not a backup of
# record; see docs/index.md.
#
# SCOPE -- what this module owns, so no knob has two managers:
#   OWNED : the tier (`nixvault.tier`, no default -- a per-host capacity fact, the same shape as
#           nixram's level), the manifest selection and its packing (`nixvault-assemble`), the
#           create/update/verify/export lifecycle tools, and the timers that keep the staged image
#           fresh.
#   NOT   : partitioning, formatting, or sizing the target device -- `nixvault.device` is a fact
#           this module asserts and builds against, never something it creates. Provisioning that
#           device is a disk-layout tool's job, same boundary nixboot draws around the ESP.
#   NOT   : the boot path, the ESP, or anything that runs before switch-root -- that is nixboot's
#           domain. A vault has no boot-time role at all; it is opened by an operator, on demand,
#           after the system it belongs to is already up.
#   NOT   : which rescue image boots in front of a main, or how that rescue reaches this vault --
#           that is nixrescue's domain. This module has no opinion on how it is invoked.
#
# ONE FILE, BOTH BACKENDS -- exported unchanged as both `nixosModules.default` and
# `systemManagerModules.default` (see flake.nix), the same "one backend, both platforms" shape as
# nixfs's modules/install.nix, and for the identical reason: everything below resolves to option
# surface system-manager supports IDENTICALLY to NixOS, confirmed by reading its actual module
# source (numtide/system-manager, nix/modules/*.nix), not assumed:
#
#   - `environment.systemPackages` -- a real system-manager option (nix/modules/environment.nix),
#     rendered into the exact same `pkgs.buildEnv` install every one of nixvault's tools reaches
#     the host through.
#   - `systemd.services.*` / `systemd.timers.*` -- real, fully-supported options
#     (nix/modules/systemd.nix) built from the identical nixpkgs `systemdUtils` code NixOS itself
#     uses; `wantedBy = [ "multi-user.target" ]` / `[ "timers.target" ]` are silently rewritten to
#     `system-manager.target` internally, but nixvault only ever names them, never depends on which
#     target actually owns them.
#   - `assertions` / `warnings` -- real options, and (confirmed in nix/lib.nix's
#     `returnIfNoAssertions`) actually enforced at build time exactly like NixOS: a failed
#     assertion throws before `system-manager switch` can run, a warning surfaces the same way.
#
# What this module deliberately never touches is exactly what system-manager CANNOT do:
# `users.users` (no user/group option surface at all -- every nixvault tool runs as whatever user
# invokes it, never a dedicated service account), `boot.*` (no bootloader or kernel-parameter
# surface -- irrelevant anyway, a vault has no boot-time role, see SCOPE above), and no dependency
# on `services.zram-generator` or any other NixOS-only systemd-generator integration. Nothing in
# nixvault's actual job -- packing a manifest, writing it into a LUKS container an operator opens
# by hand -- ever needed any of those, so there was nothing to design around, unlike nixram's
# zswap/oomd surface (which genuinely does need a NixOS-only escape hatch on one backend -- see
# that project's own system-manager/ split for the case where "one file" is NOT the honest answer).
#
{ config, lib, pkgs, ... }:

let
  cfg = config.nixvault;
  manifest = import ../lib/manifest.nix { };
  inherit (manifest) tiers tierNames categoryNames staticCategories generatedCategories;

  # The f2fs recipe, vendored unchanged from the sibling nixnas project -- see
  # lib/f2fs-vault-opts.nix's own header for exactly what each flag does and why.
  f2fsOpts = import ../lib/f2fs-vault-opts.nix;
  f2fsMountOptionsStr = lib.concatStringsSep "," f2fsOpts.mountOptions;

  # THE KERNEL FLOOR release_cblocks needs -- see this module's own "THE KERNEL FLOOR" header
  # section for why this is a runtime check, not a Nix `assertions` entry: this module owns no
  # `boot.*` surface on either backend it exports to, and system-manager in particular has no
  # `boot.kernelPackages` to force at eval time. `uname -r` is exactly as meaningful on a foreign
  # system-manager host as on NixOS -- it names the kernel the script is ACTUALLY about to run
  # f2fs operations under, which is the only thing that matters here.
  requiredKernel = "6.12";
  kernelFloorGuard = ''
    running_kernel="$(uname -r)"
    oldest="$(printf '%s\n%s\n' "${requiredKernel}" "$running_kernel" | sort -V | head -n1)"
    if [ "$oldest" != "${requiredKernel}" ]; then
      echo "nixvault: running kernel $running_kernel is older than the ${requiredKernel} floor f2fs's compression release/reserve block accounting needs (see this module's own header) -- refusing to format or write into the vault. Boot a ${requiredKernel}+ kernel first." >&2
      exit 1
    fi
  '';

  # EVAL SAFETY, same shape as nixram's own `activeLevel`: `nixvault.tier` and `nixvault.device`
  # have no default and can legitimately be null while NixOS forces most of `config` in one pass to
  # build `system.build.toplevel` -- independent of, and possibly before, whichever order
  # `assertions` gets checked in. Never index `tiers` with `cfg.tier` directly, and never
  # interpolate `cfg.device` directly into a script's text: go through the fallbacks below, so that
  # forcing an unrelated attribute can never itself throw a raw Nix error before the friendly
  # assertion gets to speak. Neither fallback is ever seen by a real user -- `nixvault.enable`
  # gates every service and package below, and the matching assertion fails the build whenever
  # enable is true and the real value is still null.
  activeTierName = if cfg.tier != null then cfg.tier else builtins.head tierNames;
  activeTier = tiers.${activeTierName};
  deviceOrPlaceholder = if cfg.device != null then cfg.device else "/nixvault-device-not-set";

  activeStaticCategories = builtins.filter (c: builtins.elem c staticCategories) activeTier.categories;
  activeGeneratedCategories = builtins.filter (c: builtins.elem c generatedCategories) activeTier.categories;

  mkSourceOption = category: lib.mkOption {
    type = lib.types.listOf lib.types.str;
    default = [ ];
    description = ''
      ${manifest.categories.${category}.summary}.

      ${manifest.categories.${category}.detail}
      Paths that already exist on this host, copied in verbatim by nixvault-assemble. Only actually
      packed when the selected tier's category list includes "${category}" -- see nixvault.tier and
      lib/manifest.nix. Sources given for a category the active tier does not include produce a
      warning rather than being silently dropped.
    '';
  };

  sourceCategoryOutsideTierWarnings =
    lib.concatMap
      (cat:
        lib.optional (cfg.sources.${cat} != [ ] && !(builtins.elem cat activeTier.categories))
          "nixvault: sources given for category '${cat}' but tier '${activeTierName}' does not include it -- they will NOT be packed. Either switch to a tier that includes '${cat}' or remove these sources."
      )
      staticCategories;

  luksVolumeNames = map (v: v.name) cfg.luksVolumes;

  # A content fingerprint of an entire directory tree -- every file's path AND its content hash,
  # folded into one digest -- needs no LUKS access and no image built first to compute. Shared,
  # verbatim, between nixvault-assemble (fingerprints the staging directory right after populating
  # it) and nixvault-update (fingerprints the mounted container right after committing into it):
  # using the identical function on both sides is what makes staged-hash == committed-hash a
  # meaningful drift proxy at all, rather than two different notions of "the same" by coincidence.
  treeHashFn = ''
    nixvault_tree_hash() {
      ( cd "$1" && find . -type f -exec sha256sum {} + | sort -k2 | sha256sum | cut -d' ' -f1 )
    }
  '';

  # ── The scripts ──────────────────────────────────────────────────────────────────────────────
  assembleScript = pkgs.writeShellApplication {
    name = "nixvault-assemble";
    runtimeInputs = [ pkgs.cryptsetup pkgs.coreutils pkgs.findutils ];
    text = ''
      set -euo pipefail

      ${treeHashFn}

      staging="${cfg.stateDirectory}/stage"

      install -d -m 0700 "${cfg.stateDirectory}"
      rm -rf "$staging"
      install -d -m 0700 "$staging"

      ${lib.optionalString (activeGeneratedCategories != [ ]) ''
        echo "nixvault-assemble: generating LUKS header backups and the device-role map..."
        install -d -m 0700 "$staging/luksHeaderBackups"
        install -d -m 0700 "$staging/deviceRoleMap"
        : > "$staging/deviceRoleMap/device-role-map.txt"
        ${lib.concatMapStringsSep "\n" (v: ''
          echo "  ${v.name} <- ${v.device}"
          cryptsetup luksHeaderBackup "${v.device}" --header-backup-file "$staging/luksHeaderBackups/${v.name}.img"
          printf '%s\t%s\n' "${v.name}" "${v.device}" >> "$staging/deviceRoleMap/device-role-map.txt"
        '') cfg.luksVolumes}
      ''}

      ${lib.concatMapStringsSep "\n" (cat: ''
        echo "nixvault-assemble: staging category '${cat}'..."
        install -d -m 0700 "$staging/${cat}"
        ${lib.concatMapStringsSep "\n" (src: ''cp -a --no-preserve=ownership "${src}" "$staging/${cat}/"'') cfg.sources.${cat}}
      '') activeStaticCategories}

      date -u +%s > "${cfg.stateDirectory}/last-assembled-timestamp"

      # A plaintext content fingerprint of the manifest tree just staged -- needs no passphrase to
      # write or to read. This is the other half of nixvault-verify's drift check: nixvault-update
      # computes the SAME kind of fingerprint fresh from what actually landed inside the container
      # and stamps THAT as "committed" the moment a commit finishes, so comparing the two lets an
      # unattended timer notice the manifest has moved on since the last commit without ever
      # opening the container to look.
      nixvault_tree_hash "$staging" > "${cfg.stateDirectory}/staged-hash"

      budget_bytes=$(( ${toString activeTier.budgetMiB} * 1024 * 1024 ))
      actual_bytes=$(du -sb "$staging" | cut -f1)
      if [ "$actual_bytes" -gt "$budget_bytes" ]; then
        echo "nixvault-assemble: WARNING -- staged manifest is $actual_bytes bytes, over the '${activeTierName}' tier's own ${toString activeTier.budgetMiB} MiB budget ($budget_bytes bytes). It will still be written if the underlying device is large enough, but the tier no longer describes what this host actually carries. This is a RAW byte count -- compression on the vault's f2fs filesystem is a write-speed win, never counted on for capacity here (see this module's own header)." >&2
      fi

      echo "nixvault-assemble: staged $staging ($actual_bytes raw bytes). Run nixvault-update to sync it into the vault."
    '';
  };

  createScript = pkgs.writeShellApplication {
    name = "nixvault-create";
    runtimeInputs = [ pkgs.cryptsetup pkgs.coreutils pkgs.f2fs-tools ];
    text = ''
      set -euo pipefail

      device="${deviceOrPlaceholder}"
      mapper="${cfg.mapperName}-create"

      if cryptsetup isLuks "$device" 2>/dev/null; then
        echo "nixvault-create: $device is already a LUKS container. Refusing to reformat -- this would destroy an existing vault. Use nixvault-update for routine content changes." >&2
        exit 1
      fi

      ${kernelFloorGuard}

      tmpkey="$(mktemp)"
      cleanup() {
        cryptsetup close "$mapper" 2>/dev/null || true
        shred -u "$tmpkey" 2>/dev/null || rm -f "$tmpkey"
      }
      trap cleanup EXIT
      head -c 64 /dev/urandom > "$tmpkey"

      echo "nixvault-create: formatting $device with a random, disposable master key."
      echo "This key never leaves this machine and is shredded before this command exits."
      cryptsetup luksFormat --type luks2 --batch-mode --key-file "$tmpkey" "$device"

      echo
      echo "nixvault-create: now add YOUR OWN passphrase -- typed here, at this console, never anywhere else."
      echo "This will be the ONLY credential this vault keeps once this command finishes:"
      cryptsetup luksAddKey --key-file "$tmpkey" "$device"

      echo
      echo "nixvault-create: opening with the passphrase you just typed -- this both confirms it actually works and lays down the vault's filesystem, which (like the LUKS format itself) only ever happens once:"
      cryptsetup open "$device" "$mapper"

      echo "nixvault-create: formatting the opened container as f2fs, with compression enabled (a WRITE-SPEED win against slow flash on every future commit, never a capacity one -- see this module's own header for why that must never be \"optimised\" away)..."
      mkfs.f2fs -f -O ${f2fsOpts.mkfsFeatures} "/dev/mapper/$mapper"

      cryptsetup close "$mapper"

      echo "nixvault-create: confirmed. Removing the temporary random-key slot -- the passphrase is now the only way in."
      cryptsetup luksRemoveKey --key-file "$tmpkey" "$device"

      echo
      echo "nixvault-create: done. $device now holds an empty, compressed f2fs filesystem inside a LUKS2 container, unlockable ONLY with the passphrase you just typed -- no TPM, no keyfile, no machine binding, by design (it must open on a replacement mainboard, which is the exact scenario it exists for)."
      echo "Next: nixvault-assemble to stage content, then nixvault-update to write it in."
    '';
  };

  updateScript = pkgs.writeShellApplication {
    name = "nixvault-update";
    runtimeInputs = [ pkgs.cryptsetup pkgs.coreutils pkgs.util-linux pkgs.rsync pkgs.f2fs-tools pkgs.findutils ];
    text = ''
      set -euo pipefail

      ${treeHashFn}

      device="${deviceOrPlaceholder}"
      mapper="${cfg.mapperName}"
      staging="${cfg.stateDirectory}/stage"

      if [ ! -d "$staging" ] || [ ! -e "${cfg.stateDirectory}/staged-hash" ]; then
        echo "nixvault-update: no staged manifest at $staging -- run nixvault-assemble first." >&2
        exit 1
      fi

      ${kernelFloorGuard}

      echo "nixvault-update: opening $device as /dev/mapper/$mapper -- you will be asked for the passphrase."
      cryptsetup open "$device" "$mapper"

      mnt="$(mktemp -d)"
      cleanup() {
        umount "$mnt" 2>/dev/null || true
        rmdir "$mnt" 2>/dev/null || true
        cryptsetup close "$mapper" 2>/dev/null || true
      }
      trap cleanup EXIT

      echo "nixvault-update: mounting the vault's f2fs filesystem..."
      mount -t f2fs -o "${f2fsMountOptionsStr}" "/dev/mapper/$mapper" "$mnt"

      # THE INCREMENTAL COMMIT -- the whole reason this module dropped squashfs (see this file's
      # own header). Plain rsync (never --inplace: a changed file is written to a NEW temp file
      # and renamed over the old one, so an already-released compressed file is never rewritten
      # IN PLACE -- the one write pattern f2fs's release_cblocks leaves EIO/EPERM-blocked, see
      # lib/f2fs-vault-opts.nix). --checksum, not mtime/size, because a GENERATED category (a
      # fresh `cryptsetup luksHeaderBackup` run) gets a brand-new mtime on every nixvault-assemble
      # even when its content has not actually changed -- mtime-based comparison would wrongly
      # treat that as a change and rewrite it every single commit, defeating the entire point.
      echo "nixvault-update: syncing the staged manifest in -- only files that actually changed are written..."
      rsync -a --delete --checksum "$staging"/ "$mnt"/

      echo "nixvault-update: releasing this commit's reserved-but-unused compressed blocks back to the filesystem (idempotent -- already-released files are a harmless no-op; see lib/f2fs-vault-opts.nix)..."
      sync
      find "$mnt" -xdev -type f -print0 | xargs -0 -r -n1 f2fs_io release_cblocks >/dev/null 2>&1 || true
      sync

      # Stamp what was ACTUALLY committed, in plaintext, computed fresh from the mounted
      # container's own contents -- not copied from nixvault-assemble's own staged-hash value, so
      # this is correct even if something else touched $mnt. This is the other half of
      # nixvault-verify's drift check (see nixvault-assemble): as long as this tool is the only
      # thing that ever writes the container -- which nixvault-create's reformat refusal
      # guarantees -- staged-hash == committed-hash is an exact, secret-free proxy for "the
      # container already holds this manifest".
      committed_hash="$(nixvault_tree_hash "$mnt")"

      umount "$mnt"
      rmdir "$mnt"
      cryptsetup close "$mapper"
      trap - EXIT

      date -u +%s > "${cfg.stateDirectory}/last-written-timestamp"
      echo "$committed_hash" > "${cfg.stateDirectory}/committed-hash"

      echo "nixvault-update: done. $device now carries the freshly synced vault contents. Neither the LUKS container nor its f2fs filesystem was reformatted -- only the files that changed were ever rewritten."
    '';
  };

  verifyScript = pkgs.writeShellApplication {
    name = "nixvault-verify";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      set -uo pipefail
      warn=0

      check_age() {
        file="$1"; label="$2"; max_days="$3"
        if [ ! -e "$file" ]; then
          echo "WARN: $label has never run ($file does not exist)"
          warn=$((warn + 1))
          return
        fi
        now=$(date +%s)
        mtime=$(stat -c %Y "$file")
        age_days=$(( (now - mtime) / 86400 ))
        if [ "$age_days" -gt "$max_days" ]; then
          echo "WARN: $label is $age_days day(s) old, over the $max_days-day limit ($file)"
          warn=$((warn + 1))
        else
          echo "PASS: $label is $age_days day(s) old (limit $max_days)"
        fi
      }

      check_age "${cfg.stateDirectory}/last-assembled-timestamp" "staged vault manifest (nixvault-assemble)" "${toString cfg.staleness.maxAgeDays}"
      check_age "${cfg.stateDirectory}/last-written-timestamp" "on-disk vault contents (nixvault-update)" "${toString cfg.staleness.maxAgeDays}"

      # CONTENT DRIFT -- the compare step this lifecycle actually needs (see the module's own
      # "THE LIFECYCLE" header). nixvault-verify cannot open the LUKS container to see what it
      # holds -- that needs the passphrase, and this runs unattended off a timer -- so it compares
      # plaintext content fingerprints instead: nixvault-assemble fingerprints the manifest tree it
      # just staged, and nixvault-update stamps the SAME kind of fingerprint -- computed fresh from
      # what is actually now inside the container -- as "committed" the instant a commit finishes.
      # Staged == committed is therefore an exact, secret-free proxy for "the container already
      # holds the current manifest", true as long as nixvault-update is the only path that ever
      # writes it (nixvault-create refuses to reformat an existing container, so it is).
      staged_hash_file="${cfg.stateDirectory}/staged-hash"
      committed_hash_file="${cfg.stateDirectory}/committed-hash"
      if [ ! -e "$staged_hash_file" ]; then
        echo "WARN: no staged manifest yet ($staged_hash_file does not exist) -- run nixvault-assemble first"
        warn=$((warn + 1))
      elif [ ! -e "$committed_hash_file" ]; then
        echo "WARN: this vault's content has never been committed ($committed_hash_file does not exist)"
        echo "ACTION REQUIRED: run nixvault-update to sync the staged manifest into the vault -- you will be asked for the passphrase."
        warn=$((warn + 1))
      else
        staged_hash=$(cat "$staged_hash_file")
        committed_hash=$(cat "$committed_hash_file")
        if [ "$staged_hash" != "$committed_hash" ]; then
          echo "WARN: the assembled manifest has DRIFTED from what the LUKS container holds (staged $staged_hash, committed $committed_hash)"
          echo "ACTION REQUIRED: run nixvault-update to commit the new content -- you will be asked for the passphrase."
          warn=$((warn + 1))
        else
          echo "PASS: assembled content matches what nixvault-update last committed ($staged_hash)"
        fi
      fi

      if [ "$warn" -gt 0 ]; then
        echo "nixvault-verify: $warn staleness/drift warning(s). A header backup or key that predates a passphrase change looks exactly like a recovery path and is not one -- treat this as an alarm, not decoration."
        ${lib.optionalString (cfg.staleness.alertCommand != null) ''
          ${cfg.staleness.alertCommand} "nixvault: $warn staleness/drift warning(s) on this host -- action required, see nixvault-verify's own output" || true
        ''}
      else
        echo "nixvault-verify: no staleness or drift warnings."
      fi

      exit 0
    '';
  };

  exportScript = pkgs.writeShellApplication {
    name = "nixvault-export-offsite";
    runtimeInputs = [ pkgs.cryptsetup pkgs.coreutils ];
    text = ''
      set -euo pipefail

      usage() {
        echo "usage: nixvault-export-offsite <source-device-or-image> <destination-path>" >&2
        echo "  Copies a vault container and re-wraps the copy so it does NOT carry the reused" >&2
        echo "  passphrase keyslot -- see the OFFSITE COPIES note in modules/nixvault.nix." >&2
        exit 1
      }

      [ $# -eq 2 ] || usage
      src="$1"
      dest="$2"

      if [ -e "$dest" ]; then
        echo "nixvault-export-offsite: $dest already exists -- refusing to overwrite." >&2
        exit 1
      fi

      echo "nixvault-export-offsite: copying $src to $dest..."
      cp --sparse=always "$src" "$dest"

      keyfile="$(mktemp)"
      trap 'shred -u "$keyfile" 2>/dev/null || rm -f "$keyfile"' EXIT
      head -c 64 /dev/urandom > "$keyfile"

      echo
      echo "nixvault-export-offsite: adding a fresh, high-entropy keyslot to the COPY only."
      echo "You will be asked for the vault's EXISTING passphrase once, to authorize the change:"
      cryptsetup luksAddKey "$dest" "$keyfile"

      keyout="$dest.key"
      cp "$keyfile" "$keyout"
      chmod 0600 "$keyout"

      echo
      echo "nixvault-export-offsite: removing the reused passphrase keyslot from the COPY (the original device is untouched -- only $dest changes)."
      echo "You will be asked for that SAME existing passphrase once more, to identify which slot to remove:"
      cryptsetup luksRemoveKey "$dest"

      echo
      echo "nixvault-export-offsite: done. $dest now opens ONLY with the key at $keyout."
      echo "Move $keyout into sops and shred the local copy -- it is the only way into this exported copy now."
      echo "The original device this vault lives on still opens with the normal operator passphrase, unchanged."
    '';
  };
in
{
  options.nixvault = {
    enable = lib.mkEnableOption "a passphrase-only, per-host disaster-recovery vault (LUKS -> f2fs), assembled from a curated manifest and written into a container built on this host";

    tier = lib.mkOption {
      type = lib.types.nullOr (lib.types.enum tierNames);
      default = null;
      example = "small";
      description = ''
        Which of the two manifest tiers this host carries: ${lib.concatStringsSep ", " tierNames}.

        There is NO default. How much a given host can spare for a vault -- and therefore how much
        of the manifest it can carry -- is a per-host capacity fact, the same shape as nixram's
        `level`: Nix evaluation cannot see a target device's real size, and guessing wrong here
        means either a build that silently fails to fit, or a vault quietly missing part of what it
        promises to carry. Leaving this unset is a hard evaluation error, not a fallback.

        See lib/manifest.nix for exactly which categories each tier includes and why.
      '';
    };

    device = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/dev/disk/by-id/example-vault-partition";
      description = ''
        The block device -- or a pre-sized regular file, cryptsetup treats both identically -- this
        vault's LUKS container lives in, or will be created in by nixvault-create.

        There is NO default: this is exactly as host-specific as nixboot's ESP location, and a
        real device path here would be exactly the kind of fleet detail a public module must never
        guess or invent. nixvault only ever asserts this is set and builds its tools against it; it
        never partitions or sizes anything itself.
      '';
    };

    mapperName = lib.mkOption {
      type = lib.types.str;
      default = "vault";
      description = "The /dev/mapper/<name> this vault is opened as while nixvault-update mounts and syncs into it (nixvault-create uses '<name>-create' for its own one-time mkfs pass, so the two never collide). Only matters while a script in this module is actively running -- the container is closed again before either tool exits.";
    };

    stateDirectory = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/nixvault";
      description = ''
        Where the staged manifest tree, the two staleness timestamps, and the two plaintext content
        fingerprints (staged-hash, committed-hash -- see nixvault-verify's own drift check) live on
        this host. Created 0700: the staging directory holds a plaintext duplicate of everything the
        vault will eventually carry, including the sops age keys and the Secure Boot PKI, before
        nixvault-update `rsync`s it into the container. That duplicate adds no new exposure beyond
        normal root-on-this-host scope -- the same material already sits in plaintext wherever
        nixvault.sources.* points at -- but it must never itself be the thing that leaves this
        machine. Only the LUKS container is meant to travel. The two sha256-derived fingerprints
        carry no secret material at all -- they identify content, not open it.
      '';
    };

    luksVolumes = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          name = lib.mkOption {
            type = lib.types.str;
            description = "A short, filesystem-safe label for what this volume holds -- becomes the header-backup filename and its row in the device-role map. Must be unique across the whole list.";
          };
          device = lib.mkOption {
            type = lib.types.str;
            description = "The block device (or by-id path) a header backup is taken from. Read-only as far as nixvault is concerned: it only ever runs `cryptsetup luksHeaderBackup` against this, never luksFormat or anything that writes to it.";
          };
        };
      });
      default = [ ];
      example = [{ name = "example-root"; device = "/dev/disk/by-id/example-encrypted-root"; }];
      description = ''
        Every LUKS-encrypted volume this vault should carry a header backup for -- fleet-wide, not
        just whatever this particular host happens to own. A damaged header makes the data behind
        it unrecoverable regardless of the passphrase, so this list is the vault's single
        highest-value payload; both tiers pack it unconditionally. No realistic example is given
        beyond the placeholder shape above, because a real device path here would be exactly the
        fleet detail this repository must never carry.
      '';
    };

    sources = lib.genAttrs staticCategories mkSourceOption;

    schedule.onCalendar = lib.mkOption {
      type = lib.types.str;
      default = "daily";
      description = "systemd OnCalendar= cadence for both the nixvault-assemble and nixvault-verify timers -- how often the staged image is rebuilt and staleness is checked. Neither timer ever touches the LUKS container itself, so this needs no passphrase and can run unattended.";
    };

    assemble.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Run nixvault-assemble automatically on a timer (and once at boot), so the staged manifest never drifts far from nixvault.sources.* and nixvault.luksVolumes. Turn off on a host that stages the manifest by some other means, or that wants full manual control over when assembly happens. Never affects nixvault-update, which always requires the operator to run it, on purpose.";
    };

    staleness.maxAgeDays = lib.mkOption {
      type = lib.types.ints.positive;
      default = 30;
      description = "How many days nixvault-verify tolerates before warning that the staged image or the on-disk vault contents are stale. A header backup or key that predates a passphrase change looks like a recovery path and is not one, which is why this exists at all rather than being purely cosmetic.";
    };

    staleness.alertCommand = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "curl -fsS -d";
      description = ''
        Escape hatch: a command nixvault-verify invokes (with one argument, the warning message)
        whenever a staleness check OR a content-drift check fails -- see nixvault-verify's own
        compare step (staged content vs. what nixvault-update last actually committed). Left unset
        by default and only ever logged to the journal, because a public module cannot know which
        fleet's paging or notification channel to call -- point this at whatever the consuming host
        already uses.
      '';
    };

    exportTool.enable = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Install nixvault-export-offsite, the tool that re-wraps a COPY of this vault with a fresh high-entropy key and drops the reused passphrase keyslot from that copy before it leaves this machine. Turn off on a host that never makes offsite copies of its vault.";
    };

    # ── Computed, read-only ──────────────────────────────────────────────────────────────────
    manifestCategories = lib.mkOption {
      type = lib.types.listOf (lib.types.enum categoryNames);
      readOnly = true;
      description = "The categories the selected tier actually packs, resolved from lib/manifest.nix. What nixvault-assemble stages, in the order it stages them.";
    };

    budgetMiB = lib.mkOption {
      type = lib.types.ints.positive;
      readOnly = true;
      description = "The selected tier's size budget in MiB, resolved from lib/manifest.nix. Informational, and used by nixvault-assemble's own post-staging size warning -- never enforced at eval time, since the manifest's real size isn't knowable until the content actually exists. A raw byte count, not a compressed one -- see this module's own header for why compression is a write-speed win here, never counted on for capacity.";
    };
  };

  config = lib.mkIf cfg.enable {
    nixvault.manifestCategories = activeTier.categories;
    nixvault.budgetMiB = activeTier.budgetMiB;

    assertions = [
      {
        assertion = cfg.tier != null;
        message = ''
          nixvault.enable is true but nixvault.tier is unset. There is no default and there never
          will be an eval-time guess -- how much this host can spare for a vault is a per-host
          capacity fact, the same shape as nixram.level. Pick one of: ${lib.concatStringsSep ", " tierNames}.
        '';
      }
      {
        assertion = cfg.device != null;
        message = ''
          nixvault.enable is true but nixvault.device is unset. This is genuinely host-specific --
          the block device or pre-sized file this vault's LUKS container lives in or will be
          created in -- and nixvault will not guess it.
        '';
      }
      {
        assertion = (lib.length (lib.unique luksVolumeNames)) == (lib.length luksVolumeNames);
        message = "nixvault.luksVolumes has duplicate 'name' entries -- each name becomes a header-backup filename and a device-role-map row, so it must be unique. Got: ${lib.concatStringsSep ", " luksVolumeNames}.";
      }
    ];

    warnings = sourceCategoryOutsideTierWarnings;

    environment.systemPackages = [
      assembleScript
      createScript
      updateScript
      verifyScript
    ] ++ lib.optional cfg.exportTool.enable exportScript;

    # nixvault-create and nixvault-update are deliberately absent from systemd entirely, the same
    # posture as nixboot-enroll-sb: both need a human-known passphrase (a brand-new one for create,
    # an existing one for update), and neither should ever be reachable from a timer, a oneshot, or
    # anything else that could run unattended.

    systemd.services.nixvault-assemble = lib.mkIf cfg.assemble.enable {
      description = "nixvault: stage the manifest into a plain directory tree (no LUKS container touched)";
      wantedBy = [ "multi-user.target" ];
      after = [ "local-fs.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${assembleScript}/bin/nixvault-assemble";
      };
    };

    systemd.timers.nixvault-assemble = lib.mkIf cfg.assemble.enable {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule.onCalendar;
        Persistent = true;
      };
    };

    systemd.services.nixvault-verify = {
      description = "nixvault: warn if the staged manifest or the on-disk vault contents are stale, or if the manifest has drifted from what is committed";
      wantedBy = [ "multi-user.target" ];
      after = [ "nixvault-assemble.service" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${verifyScript}/bin/nixvault-verify";
      };
    };

    systemd.timers.nixvault-verify = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.schedule.onCalendar;
        Persistent = true;
      };
    };
  };
}
