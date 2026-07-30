#
# The manifest, in the two halves a host actually reasons about.
#
# `categories` is the reviewable list of WHAT a vault can carry, generically. Every entry describes
# a class of recovery material, never a real path from any real deployment -- this repo is public, so an
# entry says "the operator's own knowledge tree", never a filesystem path that would mean something
# to a specific machine.
#
# `tiers` is which categories a given size budget actually buys. Two tiers, the same shape as
# nixram's levels and nixfs's filesystem list: a small, reviewable enum a host picks one value from,
# with NO default (see modules/nixvault.nix) because which tier a host carries is a per-host
# capacity fact, not something this file can guess.
#
# GENERATED VS STATIC. Most categories are STATIC: the consuming host supplies a list of existing
# paths via `nixvault.sources.<category>`, and the packing pipeline copies them in verbatim. Two
# categories are GENERATED instead -- `luksHeaderBackups` and `deviceRoleMap` -- because their
# content does not pre-exist as a file anywhere: it comes from running `cryptsetup luksHeaderBackup`
# against a live device at pack time. Those two are driven by `nixvault.luksVolumes` (name + device
# pairs) rather than by a list of paths. See `generatedCategories` below; the module is the only
# place that distinguishes the two, this file just says which names fall in which bucket.
#
# WHY LUKS HEADER BACKUPS AND SOPS AGE KEYS COME FIRST, EVERY TIER. A vault's primary purpose is
# getting back into an operator's own encrypted storage when a machine's own unlock path is gone --
# not a convenience copy of notes. A damaged LUKS header makes the data behind it unrecoverable
# regardless of how correct the passphrase is, and a missing sops age key makes every other secret
# this vault carries inert ciphertext. Both tiers include both, unconditionally.
#
{ ... }:
let
  categories = {
    luksHeaderBackups = {
      summary = "cryptsetup luksHeaderBackup output for every LUKS-encrypted volume this vault exists to help recover -- not just the volumes on the host that carries this copy";
      detail = ''
        A damaged or overwritten LUKS header makes the data behind it unrecoverable no matter how
        correct the passphrase is, so a header backup is the single highest-value thing a vault
        carries. GENERATED at pack time from `nixvault.luksVolumes`, one file per declared volume --
        never a static source path, because the source is a live device, not a file that already
        exists somewhere.
      '';
      generated = true;
    };

    deviceRoleMap = {
      summary = "a plain-text table mapping each header backup to the physical device and role it belongs to";
      detail = ''
        A header backup on its own does not say which drive it came from. GENERATED alongside
        `luksHeaderBackups` from the same `nixvault.luksVolumes` list, so the two can never drift
        out of sync with each other.
      '';
      generated = true;
    };

    sopsAgeKeys = {
      summary = "the age private keys that decrypt this operator's sops-encrypted secrets";
      detail = ''
        Without these, every other sops-encrypted file this vault carries -- or that the operator
        keeps anywhere else -- is inert ciphertext. Omitting this category would make the rest of
        the vault decorative.
      '';
      generated = false;
    };

    recoveryKeys = {
      summary = "standalone disk-encryption recovery keys issued outside the normal passphrase/keyslot path";
      detail = ''
        Some encrypted volumes carry a separate recovery key alongside their normal unlock path
        (issued once, stored once, never typed day to day). Those live here, distinct from the
        header backups above -- a header backup lets you attempt recovery at all; a recovery key is
        one specific way in.
      '';
      generated = false;
    };

    overlayIdentity = {
      summary = "the host's overlay-network identity, so a rescue system is the SAME peer";
      detail = ''
        A mesh/overlay client (NetBird, Tailscale) keeps a per-host private key and peer
        registration in its state directory. Losing it does not merely disconnect the host --
        it makes the host a DIFFERENT peer on next start, silently re-enrolling under a new
        identity, which is how an operator ends up with a graveyard of dead peers and a routing
        peer that no longer routes.

        It is carried here for a second, sharper reason: a rescue system needs to be
        REACHABLE, and reachable as the machine you already know, not as a stranger. That
        state normally lives on the host's own root filesystem -- which is exactly the thing
        that is gone when the rescue boots. A vault on removable media is reachable with
        every pool dead, so it is the only place this can live and still be there when it
        is needed.

        Small (tens of KiB) and high-value. Both tiers pack it.
      '';
      generated = false;
    };

    secureBootPki = {
      summary = "the Secure Boot signing keys (PK/KEK/db) needed to re-sign a boot chain after a board swap";
      detail = ''
        A replacement mainboard with its own fresh, empty Secure Boot key database needs the
        operator's own PKI bundle to re-enroll and re-sign, or the machine cannot boot its own
        signed images again.
      '';
      generated = false;
    };

    runbook = {
      summary = "a plain-text recovery runbook, readable with nothing but `cat`";
      detail = ''
        The one document in the vault that assumes no tooling at all beyond a working shell: what
        each header backup is for, which passphrase unlocks what, and the order of operations for a
        cold recovery. Written for the operator at 3am with a borrowed laptop, not for a person who
        already remembers how this vault is built.
      '';
      generated = false;
    };

    knowledgeTree = {
      summary = "a curated slice of the operator's own notes -- never a bulk copy";
      detail = ''
        A small, deliberately-chosen set of reference material: how to reach things, who to
        contact, what depends on what. Never "as much as fits" -- a knowledge tree can easily run to
        terabytes once it includes bulk media or model weights, which is exactly the wrong instinct
        for a vault. The consuming host's own config decides what is curated in.
      '';
      generated = false;
    };

    repoSources = {
      summary = "checked-out source for the operator's own infrastructure-as-code repositories";
      detail = ''
        The configurations that rebuild every host, offline-legible without needing to clone
        anything. Only worth the space once the header backups, keys, and runbook above are already
        covered -- hence a `medium`-tier-only category.
      '';
      generated = false;
    };

    repoDocs = {
      summary = "rendered or generated documentation the operator wants offline-legible";
      detail = ''
        Built docs (a rendered site, a generated reference) rather than the source that builds
        them -- readable without a toolchain, which matters exactly when this vault is the only
        thing left.
      '';
      generated = false;
    };
  };

  smallCategories = [
    "luksHeaderBackups"
    "deviceRoleMap"
    "sopsAgeKeys"
    "recoveryKeys"
    "overlayIdentity"
    "secureBootPki"
    "runbook"
  ];

  tiers = {
    # ~272 MiB of measured header-backup weight plus a few MiB of keys and a runbook, comfortably
    # inside 500 MiB. The floor every vault-carrying host gets: the recovery core, nothing wider.
    small = {
      budgetMiB = 500;
      categories = smallCategories;
    };

    # Everything `small` has, plus the wider material that is worth carrying once the recovery core
    # is already covered: a curated knowledge tree, the operator's own repo sources, and rendered
    # docs.
    medium = {
      budgetMiB = 4096;
      categories = smallCategories ++ [ "knowledgeTree" "repoSources" "repoDocs" ];
    };
  };
in
{
  inherit categories tiers;

  categoryNames = builtins.attrNames categories;
  tierNames = builtins.attrNames tiers;

  generatedCategories =
    builtins.filter (c: categories.${c}.generated) (builtins.attrNames categories);

  staticCategories =
    builtins.filter (c: !categories.${c}.generated) (builtins.attrNames categories);
}
