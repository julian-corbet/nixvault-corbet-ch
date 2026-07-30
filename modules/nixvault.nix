#
# modules/nixvault.nix -- a small, passphrase-only recovery vault, built on the host it protects.
#
# THE GAP THIS CLOSES. Every other piece of encrypted storage has an unlock path that
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
# f2fs's mount recipe is consumed from nixfs (`nixfsCatalogue.filesystems.f2fs.compression` --
# see nixfs's lib/catalogue.nix for the per-flag rationale), the SAME field-proven recipe
# nixnas's own USB store uses (its `modules/boot/disk.nix` mkfs invocation, `docs/STORAGE.md`
# §§4-6) -- and f2fs is the RIGHT choice here even though nixnas's own rescue SLOT deliberately
# rejected it. The reason it was wrong there is that f2fs's fs-mode compression reserves
# UNCOMPRESSED blocks until an explicit `release_cblocks` pass runs, which bites hard when
# ingesting a whole closure in one shot into a partition with almost no headroom to spare. This
# vault is the opposite shape of write entirely: a small payload (the tier budgets are 500 MiB /
# 4096 MiB) landing on a device sized with roughly TEN TIMES that headroom, written incrementally
# -- one changed file at a time -- with a release pass run after every commit, not deferred to
# some later maintenance window. The accounting gate f2fs's reservation-until-release behavior
# creates never gets anywhere near full on this container. Do not "fix" this by arguing back to
# squashfs; the slow-flash problem squashfs actually had (whole-volume rewrites) is the one f2fs
# solves, and the tight-partition problem f2fs actually had (in the rescue SLOT) simply does not
# exist here. THIS RECIPE IS ONE, SHARED FACT, NOT A SECOND COPY: it used to be vendored here
# (`lib/f2fs-vault-opts.nix`, a byte-for-byte copy of nixnas's own list) specifically so it
# "cannot quietly drift" -- true, but the fix for a copy drifting is not a second copy, it is no
# copy; nixfs is the one place this now lives, and if this vault's own write pattern ever needed
# a genuinely different flag, that would be a parameter passed at THIS call site, never a second
# variant sitting inside nixfs's own data.
#
# COMPRESSION HERE IS A WRITE-SPEED WIN, NOT A CAPACITY ONE -- say so here so nobody later
# "optimises" it away by pointing at the tier budgets and asking why a vault this small needs
# compression at all. The point was never fitting more into the budget: CPU time spent compressing
# is nearly free set against how slow the underlying USB flash is, so every byte compression keeps
# off that flash is a real, measurable time saved on every commit. Do not remove `compress_*` mount
# options in the name of "simplifying" this module -- that would trade a free win for none.
#
# THE KERNEL FLOOR THIS RELIES ON: f2fs's release/reserve `i_blocks` accounting only becomes
# correct on kernel >= 6.12 -- `requiredKernel`, read from the SAME nixfs recipe as the mkfs/mount
# facts above (`nixfsCatalogue.filesystems.f2fs.compression.requiredKernel`; see nixfs's own
# lib/catalogue.nix for the citation trail: release-cblocks decoupled from the VFS immutable bit
# since 5.14, a compressed-block SPOR fix ~6.7, this accounting fix ~6.12). nixnas's sibling
# project gets this floor for free from an unrelated dependency -- its ZFS pools force a
# recent-enough kernel regardless of f2fs, and it now asserts as much at eval time
# (`modules/boot/kernel.nix`). nixvault has no such freebie: it is not tied to any
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
#   for a container NOTHING ELSE HAS OPENED. That qualifier matters, and an earlier draft of this
#   header missed it: on a host whose initrd already unlocks every declared LUKS member from ONE
#   operator passphrase (the kernel keyring caches it across the set), the vault can be declared
#   as one more member and is open before userspace exists. `nixvault-update` adopts such a mapper
#   instead of re-prompting, and closes only what it opened itself. The human act is then the ONE
#   passphrase entry at boot -- which is the point; re-prompting for an already-open container is
#   not extra security, it is a second tax on the same decision, and it is exactly what would
#   block an unattended assemble->commit lifecycle on such a host. Committing remains a deliberate
#   act either way. The container itself
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
#   hardcoded channel: a public module cannot know which operator's paging system to call.
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
# `nixvault.luksVolumes` and the sops keys put the operator's OWN recovery material inside the vault,
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
#           fresh. ALSO OWNED: the TRANSPORT that gets a remote host's already-published LUKS
#           header backups onto local disk for a second vault to import
#           (`nixvault.headerBackupPull` -- a signed rsync/ssh pull, never NFS or any other
#           unauthenticated channel). Generating those backups in the first place is NOT this
#           module's job (see the next NOT below); this module owns only fetching what some other
#           host already produced.
#   NOT   : producing a LUKS header backup at all -- that is the publishing host's own domain
#           (e.g. nixluks's `headerBackup.destination`/`.schedule`). `nixvault.luksVolumes` is the
#           one exception, and only on the host that physically owns those disks.
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
# `nixfsCatalogue` is a plain closure argument, partially applied by flake.nix at import time
# (`import ./modules/nixvault.nix { nixfsCatalogue = nixfs.lib.catalogue; }`) — never
# `_module.args`. A module-argument name is a GLOBAL namespace shared with anything else composed
# alongside this module, and nixnas (a sibling appliance-adjacent flake, also consuming nixfs's
# own catalogue) picked the exact same argument name for the exact same reason — correct in each
# flake alone, and a hard "defined multiple times" eval failure the one time a consumer composed
# both (infra's mkNixnas). `_module.args` merges with `mergeOneOption`, which rejects a second
# definition even when the two values are identical, so no `inputs.follows` pin could have fixed
# that either. Partial application closes over the value before it ever becomes a module argument
# at all, ruling the collision out by construction: this file is a function of `nixfsCatalogue`
# first, and ONLY THEN a NixOS/system-manager module of `{ config, lib, pkgs, ... }` — the module
# system never calls the outer function, so it never has a chance to inject the standard module
# args into it either.
{ nixfsCatalogue }:
{ config, lib, pkgs, ... }:

let
  cfg = config.nixvault;
  manifest = import ../lib/manifest.nix { };
  inherit (manifest) tiers tierNames categoryNames staticCategories generatedCategories;

  # THE f2fs compression recipe -- ONE, canonical copy, owned by nixfs (the filesystem domain)
  # and consumed here as plain data, never vendored. See nixfs's lib/catalogue.nix
  # (filesystems.f2fs.compression) for the per-flag rationale; `nixfsCatalogue` reaches this
  # module as a plain, partially-applied argument (see the header above), not a config read,
  # because a recipe is a constant, not a per-host fact.
  f2fsOpts = nixfsCatalogue.filesystems.f2fs.compression;
  f2fsMountOptionsStr = lib.concatStringsSep "," f2fsOpts.mountOptions;

  # THE KERNEL FLOOR release_cblocks needs -- read from the SAME nixfs recipe as the mkfs/mount
  # facts above. See this module's own "THE KERNEL FLOOR" header section for why this is a
  # runtime check, not a Nix `assertions` entry: this module owns no `boot.*` surface on either
  # backend it exports to, and system-manager in particular has no `boot.kernelPackages` to
  # force at eval time. `uname -r` is exactly as meaningful on a foreign system-manager host as
  # on NixOS -- it names the kernel the script is ACTUALLY about to run f2fs operations under,
  # which is the only thing that matters here.
  requiredKernel = f2fsOpts.requiredKernel;
  kernelFloorGuard = ''
    running_kernel="$(uname -r)"
    oldest="$(printf '%s\n%s\n' "${requiredKernel}" "$running_kernel" | sort -V | head -n1)"
    if [ "$oldest" != "${requiredKernel}" ]; then
      echo "nixvault: running kernel $running_kernel is older than the ${requiredKernel} floor f2fs's compression release/reserve block accounting needs (see this module's own header) -- refusing to format or write into the vault. Boot a ${requiredKernel}+ kernel first." >&2
      exit 1
    fi
  '';

  # ── nixstorage: read defensively, never imported -- see modules/disks.nix's own header on
  # that sibling repo for the incident this closes. Three repos (this module's own `device` and
  # `luksVolumes[].device` among them) each typed a `/dev/disk/by-id` string for what is, on a
  # real host, the same handful of physical disks, with nothing asserting any two of them agreed.
  # nixstorage's layout module is the one that WRITES PARTITION TABLES, so a drifted string here
  # means a layout run and a nixvault-create/-update run could disagree about which disk is
  # which. Separately, and just as real: on 2026-07-29 a reboot moved a rescue stick from sdr to
  # sdq while a blank 239 GiB drive took over sdr -- a table, or a header-backup run, aimed at
  # the remembered LETTER would have hit the wrong disk entirely. Stable `by-*` paths, resolved
  # by NAME through nixstorage rather than retyped, are what keeps that from happening again.
  #
  # Two separate device facts live in this module, and they deliberately resolve from TWO
  # DIFFERENT nixstorage tables, because they are two different KINDS of device:
  #
  #   nixvault.device (THIS host's own vault container) is a PARTITION -- one carved by a
  #   `nixstorage.layout` image, never a whole disk -- so it resolves from `deviceFromLayout`
  #   against `nixstorage.layout.images.<name>`, the same table (and the same one-way,
  #   defensive read) nixboot's own `esp.fromLayout` already uses for the identical reason.
  #
  #   nixvault.luksVolumes[].device (OTHER volumes this vault merely holds header backups for)
  #   is a WHOLE DISK -- nixvault only ever runs `cryptsetup luksHeaderBackup` against it, never
  #   carves or formats it -- so each entry resolves from its own `fromDisk` against
  #   `nixstorage.disks.<name>` instead, the plain disk table, not a partition layout.
  #
  # Both reads are entirely defensive (`config.nixstorage… or { }`), exactly as nixstorage's own
  # reconciler.nix reads `config.nixid.posix.identities or { }`: importing nixvault WITHOUT
  # nixstorage's layout or disks modules -- or without nixstorage at all -- evaluates fine as
  # long as `device` and each `luksVolumes[].device` are then given directly. The two reads are
  # independent of each other: a host may use one, both, or neither. Direction is one-way in
  # both cases -- nixstorage gains no knowledge of nixvault, ever.
  nsImages = config.nixstorage.layout.images or { };
  nsDisks = config.nixstorage.disks or { };

  vaultSourceImage =
    if cfg.deviceFromLayout != null && nsImages ? "${cfg.deviceFromLayout}"
    then nsImages."${cfg.deviceFromLayout}"
    else null;

  # A layout partition's `name` IS the GPT partition name nixstorage's own image builder passes
  # straight to sgdisk/sfdisk (modules/layout.nix's `partitionModule.name`, typed
  # `strMatching "^[A-Za-z0-9_.-]{1,36}$"`) -- and every character that type permits already
  # sits inside udev's own UNESCAPED by-partlabel safe-charset (systemd's name-encoding only
  # hex-escapes characters outside alnum plus `#+-.:=@_`). So the raw partition name maps
  # straight onto the `/dev/disk/by-partlabel/<name>` symlink with no decode/encode step in
  # between, and the name alone genuinely IS enough to build a stable path from here. That stops
  # being true the day layout.nix's own name type ever widens to allow a space or a non-ASCII
  # character -- re-derive this the moment it does, do not assume it still holds.
  vaultSourcePart =
    if vaultSourceImage == null then null
    else lib.findFirst (p: p.role or null == "luks") null (vaultSourceImage.partitions or [ ]);

  vaultDeviceFromLayout =
    if vaultSourcePart == null then null else "/dev/disk/by-partlabel/${vaultSourcePart.name}";

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

  # Entries whose `device` resolved to nothing at all -- neither stated directly nor resolved
  # from `fromDisk` against `nixstorage.disks`. Named here so the assertion below can say WHICH
  # entries are broken, the same friendliness the top-level `tier`/`device` assertions already
  # give instead of a raw "value is null but a string was expected" trace.
  luksVolumesMissingDevice = map (v: v.name) (builtins.filter (v: v.device == null) cfg.luksVolumes);

  headerPullNames = map (p: p.name) cfg.headerBackupPull;

  # The TRANSPORT half of importHeaderBackups: a real rsync/ssh invocation, parameterised per
  # entry (remote host, key, paths). Unlike the manifest-staging scripts below there is no single
  # shared script here -- one pkgs.writeShellApplication PER declared pull, named for its own
  # entry so an operator can run it by hand (`nixvault-header-pull-<name>`) exactly like every
  # other nixvault tool. See headerBackupPull's own option description for the full "why rsync
  # over ssh, never NFS" reasoning.
  mkHeaderPullScript = p: pkgs.writeShellApplication {
    name = "nixvault-header-pull-${p.name}";
    runtimeInputs = [ pkgs.rsync pkgs.openssh pkgs.coreutils ];
    text = ''
      set -euo pipefail
      install -d -m 0700 "${p.localPath}"
      rsync -a --delete \
        -e "ssh -i ${p.sshKeyFile} -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
        "${p.remoteUser}@${p.remoteHost}:${p.remotePath}" "${p.localPath}/"
    '';
  };

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

      ${lib.optionalString (activeGeneratedCategories != [ ] && cfg.luksVolumes != [ ]) ''
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

      ${lib.optionalString (activeGeneratedCategories != [ ] && cfg.importHeaderBackups != [ ]) ''
        # IMPORT rather than generate -- this host does not have the disks (see
        # importHeaderBackups' own description). A missing source is FATAL, not skipped:
        # silently staging an empty header directory produces a vault that looks like a
        # recovery path and is not, which is precisely the failure mode this module's
        # staleness alarm exists to catch.
        echo "nixvault-assemble: importing pre-generated LUKS header backups..."
        install -d -m 0700 "$staging/luksHeaderBackups"
        install -d -m 0700 "$staging/deviceRoleMap"
        ${lib.concatMapStringsSep "\n" (src: ''
          if [ ! -d "${src}" ]; then
            echo "nixvault-assemble: header import source '${src}' does not exist or is not a directory" >&2
            exit 1
          fi
          echo "  <- ${src}"
          cp -a --no-preserve=ownership "${src}"/. "$staging/luksHeaderBackups/"
        '') cfg.importHeaderBackups}
        # A role map may travel alongside the headers; move it to its own category if so.
        if [ -e "$staging/luksHeaderBackups/device-role-map.txt" ]; then
          mv "$staging/luksHeaderBackups/device-role-map.txt" "$staging/deviceRoleMap/"
        fi
        n=$(find "$staging/luksHeaderBackups" -type f -name '*.img' | wc -l)
        [ "$n" -gt 0 ] || { echo "nixvault-assemble: imported 0 header files -- refusing to stage an empty recovery core" >&2; exit 1; }
        echo "nixvault-assemble: imported $n header backup(s)"
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

      # ADOPT AN ALREADY-OPEN CONTAINER RATHER THAN DEMANDING THE PASSPHRASE AGAIN.
      #
      # "There is no such thing as an unattended luksOpen" (this file's header) is true
      # of a container nothing else has opened -- and misses the deployment this vault
      # is actually built for. On a host whose initrd already unlocks every declared
      # LUKS member from ONE operator passphrase (the kernel keyring caches it across
      # the whole set), the vault can be declared as one more member. It is then open
      # before userspace exists, and this tool has nothing left to unlock.
      #
      # That is the difference between "committing must be a deliberate human act" --
      # true, and unchanged -- and "committing must re-prompt". The human act is the
      # ONE passphrase entry at boot. Re-prompting for a container that is already open
      # is not extra security, it is a second tax on the same decision, and it is what
      # blocks the whole unattended assemble->commit lifecycle on such a host.
      #
      # WE CLOSE ONLY WHAT WE OPENED, and on a chain-open host that means WE NEVER
      # CLOSE IT AT ALL -- the container is opened once by the initrd and then simply
      # stays open for the life of the boot. That is the intended steady state, not a
      # leak to be tidied up later:
      #
      #   an unattended commit that closes the container has destroyed its own next
      #   run. There is no secret available to reopen it -- that is the entire premise
      #   of passphrase-only -- so the first timer firing would succeed, tear the
      #   mapper down, and every firing after it would find nothing to adopt and no
      #   console to prompt on. The vault would drift out of sync silently,
      #   which is precisely the failure this module exists to prevent.
      #
      # The alternatives were considered and are all worse HERE: a keyfile or a
      # TPM-sealed second keyslot would allow unattended reopen, but both put the
      # unlock path back on the machine whose loss this vault is meant to survive, and
      # a PCR-sealed slot is silently invalidated by a routine firmware update. Close-
      # on-idle is the same problem wearing a hat -- "reopen" still needs the secret.
      #
      # Holding it open costs a dm-crypt mapping and leaves the plaintext reachable by
      # root on a running box. That is not new exposure: root there already reads the
      # age keys, the Secure Boot PKI and every LUKS header at their SOURCE paths --
      # this vault is a copy of material that host already holds in the clear. What the
      # container protects is the MEDIUM once it is unplugged, in a drawer, or in
      # transit. Closing it on a live host defends nothing and breaks the lifecycle.
      opened_here=0
      if [ -e "/dev/mapper/$mapper" ]; then
        echo "nixvault-update: /dev/mapper/$mapper is already open (initrd or a prior unlock) -- adopting it, no passphrase needed."
      else
        echo "nixvault-update: opening $device as /dev/mapper/$mapper -- you will be asked for the passphrase."
        cryptsetup open "$device" "$mapper"
        opened_here=1
      fi

      mnt="$(mktemp -d)"
      cleanup() {
        umount "$mnt" 2>/dev/null || true
        rmdir "$mnt" 2>/dev/null || true
        [ "$opened_here" = 1 ] && cryptsetup close "$mapper" 2>/dev/null || true
      }
      trap cleanup EXIT

      echo "nixvault-update: mounting the vault's f2fs filesystem..."
      mount -t f2fs -o "${f2fsMountOptionsStr}" "/dev/mapper/$mapper" "$mnt"

      # THE INCREMENTAL COMMIT -- the whole reason this module dropped squashfs (see this file's
      # own header). Plain rsync (never --inplace: a changed file is written to a NEW temp file
      # and renamed over the old one, so an already-released compressed file is never rewritten
      # IN PLACE -- the one write pattern f2fs's release_cblocks leaves EIO/EPERM-blocked, see
      # nixfs's lib/catalogue.nix (filesystems.f2fs.compression). --checksum, not mtime/size,
      # because a GENERATED category (a fresh `cryptsetup luksHeaderBackup` run) gets a
      # brand-new mtime on every nixvault-assemble
      # even when its content has not actually changed -- mtime-based comparison would wrongly
      # treat that as a change and rewrite it every single commit, defeating the entire point.
      echo "nixvault-update: syncing the staged manifest in -- only files that actually changed are written..."
      rsync -a --delete --checksum "$staging"/ "$mnt"/

      echo "nixvault-update: releasing this commit's reserved-but-unused compressed blocks back to the filesystem (idempotent -- already-released files are a harmless no-op; see nixfs's lib/catalogue.nix, filesystems.f2fs.compression)..."
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
      # Same rule as the trap: close ONLY what this tool opened. On a host where the
      # initrd chain-opened the container off the operator's single boot passphrase,
      # closing it here would tear the vault down after the first commit and every
      # later one would find it gone -- turning an unattended lifecycle into a silent
      # one-shot. (The trap was guarded first and this line was missed; the symptom was
      # exactly that: adoption logged correctly, mapper absent afterwards.)
      [ "$opened_here" = 1 ] && cryptsetup close "$mapper" || true
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
      default = vaultDeviceFromLayout;
      defaultText = lib.literalExpression ''
        the by-partlabel path of deviceFromLayout's own "luks"-role partition, else null
      '';
      example = "/dev/disk/by-id/example-vault-partition";
      description = ''
        The block device -- or a pre-sized regular file, cryptsetup treats both identically -- this
        vault's LUKS container lives in, or will be created in by nixvault-create.

        Defaults from `nixvault.deviceFromLayout` when that names a `nixstorage.layout` image with
        a "luks"-role partition (see that option). Still genuinely host-specific with NO default of
        its own beyond that, the same as nixboot's ESP location: a real device path here would be
        exactly the kind of host-specific detail a public module must never guess or invent on its own. On a
        host that carves its vault partition some other way, or that has no `nixstorage.layout` at
        all, state this directly -- nixvault only ever asserts it ends up set and builds its tools
        against it; it never partitions or sizes anything itself.
      '';
    };

    deviceFromLayout = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "rescue-stick";
      description = ''
        Name of the `nixstorage.layout.images.<name>` describing the medium this vault's LUKS
        container lives on. When set, `device` defaults to that image's own "luks"-role
        partition's `/dev/disk/by-partlabel/<name>` path, instead of being restated here.

        WHY THIS EXISTS. nixstorage's layout module is the one that WRITES PARTITION TABLES for
        this vault's own medium, so a device path typed separately here -- with nothing asserting
        it still names the same partition the layout carved -- is exactly the drift that lets a
        `nixstorage-layout` run and a `nixvault-create`/`nixvault-update` run silently disagree
        about which partition the vault actually is. Naming the image instead of retyping its
        path is the same fix nixboot's own `esp.fromLayout` already applies to the identical
        table, for the identical reason.

        Which image describes THIS host's vault cannot be inferred -- a host may declare several
        layout images for entirely unrelated media -- so it is named rather than guessed. Leave
        null on a host that carves its vault partition some other way, or has no
        `nixstorage.layout` at all; nixvault never imports nixstorage and reads it defensively
        (`config.nixstorage.layout.images or { }`), so this is completely inert when nixstorage
        is absent.
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
      type = lib.types.listOf (lib.types.submodule ({ config, ... }: {
        options = {
          name = lib.mkOption {
            type = lib.types.str;
            description = "A short, filesystem-safe label for what this volume holds -- becomes the header-backup filename and its row in the device-role map. Must be unique across the whole list.";
          };

          fromDisk = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default = null;
            example = "example-root-disk";
            description = ''
              Name of a `nixstorage.disks.<name>` entry this volume's header backup should be taken
              from. When set, `device` defaults to that disk's own `device` path instead of being
              restated here.

              WHY THIS EXISTS -- the same drift `nixvault.deviceFromLayout` closes for the vault's
              own container, one level down: these entries are WHOLE DISKS (nixvault only ever runs
              `cryptsetup luksHeaderBackup` against them, never carves or formats them), so they
              resolve from `nixstorage.disks` -- the plain disk table -- rather than from a layout
              image. A disk named here instead of retyped cannot drift from what a layout run or any
              other consumer calls the same physical disk.

              Leave null on a host with no `nixstorage.disks` table at all, or that simply prefers
              to state the path directly; `device` then behaves exactly as before. nixvault never
              imports nixstorage and reads it defensively (`config.nixstorage.disks or { }`), so
              this is completely inert when nixstorage is absent.
            '';
          };

          device = lib.mkOption {
            type = lib.types.nullOr lib.types.str;
            default =
              if config.fromDisk != null && nsDisks ? "${config.fromDisk}"
              then nsDisks."${config.fromDisk}".device
              else null;
            defaultText = lib.literalExpression "the fromDisk entry's own device path from nixstorage.disks, else null (then required directly)";
            description = ''
              The block device (or by-id path) a header backup is taken from. Read-only as far as
              nixvault is concerned: it only ever runs `cryptsetup luksHeaderBackup` against this,
              never luksFormat or anything that writes to it.

              Defaults from this entry's own `fromDisk` when that names a `nixstorage.disks` entry
              (see that option). Genuinely required either way -- state it directly on a host with
              no `nixstorage.disks` table, or that prefers not to name one; leaving both unset fails
              the build with a named-entry assertion rather than a silent null device.
            '';
          };
        };
      }));
      default = [ ];
      example = [{ name = "example-root"; device = "/dev/disk/by-id/example-encrypted-root"; }];
      description = ''
        Every LUKS-encrypted volume this vault should carry a header backup for -- across every
        host, not just whatever this particular host happens to own. A damaged header makes the data behind
        it unrecoverable regardless of the passphrase, so this list is the vault's single
        highest-value payload; both tiers pack it unconditionally. No realistic example is given
        beyond the placeholder shape above, because a real device path here would be exactly the
        host-specific detail this repository must never carry.
      '';
    };

    importHeaderBackups = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      example = [ "/var/lib/luks-headers" ];
      description = ''
        Directories of ALREADY-GENERATED LUKS header backups to stage into this vault,
        instead of producing them locally from `luksVolumes`.

        WHY THIS EXISTS. `luksHeaderBackups` is a GENERATED category: it is produced at
        assemble time by running `cryptsetup luksHeaderBackup` against `luksVolumes`,
        which only works on the host that physically has those disks. That makes a
        SECOND vault on a DIFFERENT machine -- the whole point of failure-domain
        diversity, since a disaster taking the primary host also takes the medium
        plugged into it -- structurally unable to carry the other hosts' headers. It would
        hold keys and a runbook and nothing that actually recovers a volume.

        A host that sets this stages the supplied directories verbatim into the
        `luksHeaderBackups` category. The headers then live INSIDE that host's own
        container, so they remain available after the machine that generated them is
        gone -- which is the entire reason to put them somewhere else.

        The path only has to be readable AT ASSEMBLE TIME, while both machines are
        alive. It may perfectly well be an NFS mount from the very host being protected;
        once committed, the copy inside this vault is independent of it.

        Mutually exclusive with a non-empty `luksVolumes` -- see the assertion. One host
        generates, another imports; a host doing both would produce two sets of headers
        in one directory with no way to tell which is authoritative.
      '';
    };

    headerBackupPull = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          name = lib.mkOption {
            type = lib.types.str;
            example = "primary";
            description = ''
              A short, unique identifier for this pull -- becomes its systemd service and timer
              name (`nixvault-header-pull-<name>`). Distinct entries need distinct names even
              when this list holds only one.
            '';
          };

          remoteHost = lib.mkOption {
            type = lib.types.str;
            description = "The publishing host -- an address or name ssh(1) can resolve on its own; never resolved or validated by this module.";
          };

          remoteUser = lib.mkOption {
            type = lib.types.str;
            default = "root";
            description = "Remote user the pull connects as -- the identity the remote's forced-command key is bound to server-side, not a privilege choice made here.";
          };

          remotePath = lib.mkOption {
            type = lib.types.str;
            description = ''
              Directory on the remote host to pull from, verbatim -- the same directory that
              host's own `nixluks.headerBackup.destination` resolves its per-volume files under.
              A trailing slash matters to rsync exactly as it always does: with one, this
              directory's CONTENTS land in `localPath`; without one, a copy of the directory
              itself is nested inside it. State it exactly as the remote publishes it.
            '';
          };

          sshKeyFile = lib.mkOption {
            type = lib.types.path;
            description = ''
              Private key for this pull. Already present on disk -- generated and deployed out
              of band, never by this module (a header-pull key is exactly the kind of secret
              nixvault itself never touches or manages). Confined server-side to a forced
              `rsync --server --sender` over exactly `remotePath`, with `restrict` (no shell, no
              forwarding, no pty) -- a key that can only read the one directory it exists to
              read.
            '';
          };

          localPath = lib.mkOption {
            type = lib.types.path;
            description = ''
              Where the pulled files land locally. List this SAME path in
              `nixvault.importHeaderBackups` to actually stage them into the vault -- this option
              only gets the bytes onto local disk, it does not make `nixvault-assemble` read
              them. The two are kept separate rather than auto-linked: a silently-injected import
              path is exactly the kind of inference this module's option surface never does.
            '';
          };

          schedule = lib.mkOption {
            type = lib.types.str;
            default = "daily";
            description = "systemd OnCalendar= cadence for this pull. Independent of nixvault.schedule.onCalendar -- ordered ahead of nixvault-assemble by Before=, not by sharing a timer.";
          };
        };
      });
      default = [ ];
      example = [{
        name = "example-publisher";
        remoteHost = "example-publisher.lan";
        remotePath = "/var/lib/example/luks-headers/";
        sshKeyFile = "/root/.ssh/id_ed25519_headerpull";
        localPath = "/var/lib/nixvault-pulled-headers";
      }];
      description = ''
        ONE-WAY, signed pulls of already-published LUKS header backups from a remote host that
        owns disks this vault cannot reach -- the TRANSPORT half of `importHeaderBackups` (see
        that option): getting bytes onto local disk is this option's job, staging them into the
        vault is `importHeaderBackups`' own. Generation stays the publishing host's job (that
        host's own `nixluks.headerBackup.destination`/`.schedule`); this module has no opinion on
        how that side is built, only on how to fetch what it already produced.

        Uses rsync over ssh, deliberately never NFS or any other unauthenticated transport -- a
        LUKS header is the KDF-wrapped master key plus every keyslot, offline-attackable with no
        rate limit by anyone who can read it, so the pull is both authenticated (a dedicated,
        forced-command key) and encrypted in transit, landing in a directory this module creates
        0700 before the first pull.

        Ordered BEFORE nixvault-assemble whenever that timer is enabled
        (`nixvault.assemble.enable`), so a failed pull surfaces as a failed assemble --
        `nixvault-assemble` already refuses to stage zero header files from an empty
        `importHeaderBackups` directory rather than produce a vault that looks like a recovery
        path and is not, and this is the identical refusal one step upstream.
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

    commit.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Run nixvault-update automatically on a timer, committing the staged manifest into
        the vault without an operator present.

        OFF by default, and only correct on a host where the vault's LUKS container is
        ALREADY OPEN -- i.e. one whose initrd unlocks every declared member from a single
        operator passphrase, with the vault declared as one of them. There, the human act
        is the one passphrase entry at boot, and re-prompting per commit is a second tax
        on the same decision.

        On any other host this timer is useless rather than dangerous: nixvault-update
        refuses to prompt from a unit with no console and exits non-zero, so the commit
        simply does not happen and the failure is visible. It can never silently write a
        vault the operator did not authorise, and it never opens the container itself --
        it only adopts one that is already open.
      '';
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
        operator's paging or notification channel to call -- point this at whatever the consuming host
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

  # mkMerge, not one plain attrset: the header-pull fragment below assigns `systemd.services` and
  # `systemd.timers` wholesale (built from a runtime list via lib.listToAttrs), which the Nix
  # parser cannot merge with the dotted `systemd.services.nixvault-assemble = ...` style bindings
  # above at parse time -- a literal attribute path and a dynamically-computed one at the same key
  # are not the same kind of definition, even though both are entirely valid NixOS config
  # fragments on their own. lib.mkMerge defers the merge to eval time, where the module system
  # already knows how to combine two attrsets that both touch `systemd.services`.
  config = lib.mkIf cfg.enable (lib.mkMerge [
    {
      nixvault.manifestCategories = activeTier.categories;
      nixvault.budgetMiB = activeTier.budgetMiB;

      assertions = [
        {
          assertion = !(cfg.luksVolumes != [ ] && cfg.importHeaderBackups != [ ]);
          message = ''
            nixvault.luksVolumes and nixvault.importHeaderBackups are both non-empty. Pick one.

            They are two answers to the same question -- "where do this vault's LUKS header
            backups come from" -- and doing both writes two sets into one directory with no
            way to tell which is authoritative. A header that looks like a recovery path and
            is not is the exact failure this module's staleness alarm exists to catch.

            GENERATE (luksVolumes) on the host that physically has the disks. IMPORT
            (importHeaderBackups) on a second host whose whole purpose is to hold a copy
            somewhere the first host's disaster does not reach.
          '';
        }
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
            created in -- and nixvault will not guess it. Either state it directly, or set
            nixvault.deviceFromLayout to a nixstorage.layout image with a "luks"-role partition.
          '';
        }
        {
          assertion = (lib.length (lib.unique luksVolumeNames)) == (lib.length luksVolumeNames);
          message = "nixvault.luksVolumes has duplicate 'name' entries -- each name becomes a header-backup filename and a device-role-map row, so it must be unique. Got: ${lib.concatStringsSep ", " luksVolumeNames}.";
        }
        {
          assertion = (lib.length (lib.unique headerPullNames)) == (lib.length headerPullNames);
          message = "nixvault.headerBackupPull has duplicate 'name' entries -- each name becomes a systemd unit name, so it must be unique. Got: ${lib.concatStringsSep ", " headerPullNames}.";
        }
        {
          # Friendlier than the raw "value is null but a string was expected" trace this would
          # otherwise fail with -- the same reasoning the tier/device assertions above already
          # apply, extended to the per-entry default that fromDisk now contributes.
          assertion = luksVolumesMissingDevice == [ ];
          message = ''
            nixvault.luksVolumes has entrie(s) with no resolvable device: ${lib.concatStringsSep ", " luksVolumesMissingDevice}.

            Each entry needs its device either stated directly, or resolved from that entry's own
            fromDisk naming a nixstorage.disks.<name> entry. nixvault will not guess a whole-disk
            path any more than it guesses its own nixvault.device.
          '';
        }
      ];

      warnings = sourceCategoryOutsideTierWarnings;

      environment.systemPackages = [
        assembleScript
        createScript
        updateScript
        verifyScript
      ] ++ lib.optional cfg.exportTool.enable exportScript
      ++ map mkHeaderPullScript cfg.headerBackupPull;

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

      # Unattended commit -- ONLY meaningful where the container is already open (see
      # commit.enable). The unit deliberately does NOT provide a passphrase by any means:
      # if the mapper is absent, nixvault-update's own `cryptsetup open` has no console,
      # fails, and the unit fails loudly. That is the intended behaviour -- a missing
      # unlock must surface, never be worked around with a keyfile.
      systemd.services.nixvault-commit = lib.mkIf cfg.commit.enable {
        description = "nixvault: commit the staged manifest into the (already-open) vault";
        after = [ "nixvault-assemble.service" "local-fs.target" ];
        wants = [ "nixvault-assemble.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${updateScript}/bin/nixvault-update";
          StandardInput = "null";
        };
      };

      systemd.timers.nixvault-commit = lib.mkIf cfg.commit.enable {
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
    }

    # The header-pull transport -- one service/timer PER declared entry, ordered ahead of
    # nixvault-assemble (when that timer runs at all) so a failed pull surfaces as a failed
    # assemble rather than a silently-stale import directory. See headerBackupPull's own option
    # description for the full reasoning. A separate mkMerge fragment (see the comment on
    # `config` above) because these two keys are built wholesale from a runtime list rather than
    # named as literal dotted paths, which the parser cannot combine with the fragment above.
    {
      systemd.services = lib.listToAttrs (map
        (p: {
          name = "nixvault-header-pull-${p.name}";
          value = {
            description = "nixvault: pull published LUKS header backups from ${p.remoteHost} (read-only, forced-command key)";
            before = lib.optional cfg.assemble.enable "nixvault-assemble.service";
            serviceConfig = {
              Type = "oneshot";
              ExecStart = "${mkHeaderPullScript p}/bin/nixvault-header-pull-${p.name}";
            };
          };
        })
        cfg.headerBackupPull);

      systemd.timers = lib.listToAttrs (map
        (p: {
          name = "nixvault-header-pull-${p.name}";
          value = {
            wantedBy = [ "timers.target" ];
            timerConfig = {
              OnCalendar = p.schedule;
              Persistent = true;
            };
          };
        })
        cfg.headerBackupPull);
    }
  ]);
}
