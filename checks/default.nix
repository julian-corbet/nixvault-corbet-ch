# checks/default.nix
#
# EVAL-TIME tests, the same posture as the sibling nixfs project: each test evaluates a real
# configuration through NixOS's own eval-config.nix and inspects what the module RENDERS or
# whether the build fails. Nothing here boots anything -- the claims under test (which tier resolves
# to which categories, which tools are always/never wired to systemd, which combinations must fail
# the build) are entirely eval-time properties. `lifecycle-vm-test` (its own file) is the one real
# runtime test: a `pkgs.testers.nixosTest` that exercises the whole create/assemble/commit/drift
# lifecycle against a real LUKS container on a loopback file inside the VM.
#
# The claims worth failing CI over:
#
#   1. `tier` and `device` have no default and enabling without either is a hard build failure --
#      the whole reason nixram's own "EVAL SAFETY" pattern exists is that a silent guess here is
#      worse than a loud refusal.
#   2. Each tier resolves to exactly the categories and budget lib/manifest.nix says it should.
#   3. nixvault-create and nixvault-update are NEVER reachable from systemd, in any configuration --
#      both need a human-known passphrase and must never be runnable unattended.
#   4. Sources given for a category outside the active tier warn instead of being silently dropped.
#   5. Duplicate `luksVolumes` names fail the build (they would collide as header-backup filenames).
#   6. Both backends agree -- the NixOS and system-manager evaluations of the same input resolve to
#      the identical tool set and manifest shape, proving modules/nixvault.nix's own "ONE FILE, BOTH
#      BACKENDS" claim rather than merely asserting it in a comment.
#   7. `lib.probeFact` (consumed from nixhost's own `lib/facts.nix` via this repo's `nixhost`
#      flake input, see flake.nix) actually distinguishes, THROUGH this real module's wiring,
#      "nixstorage not composed at all" from
#      "nixstorage composed but `layout.images`/`disks` renamed" for BOTH facts this module reads
#      -- before this group existed, NEITHER read was exercised by any check in this file at all.
#      The renamed case warns exactly once per fact, naming the option path, and never fails the
#      build on its own.
{ pkgs, lib, nixpkgs, system, nixvaultModule, systemManagerLib }:

let
  manifest = import ../lib/manifest.nix { };

  sorted = lib.sort (a: b: a < b);

  evalNixos = extraConfig:
    (import (nixpkgs + "/nixos/lib/eval-config.nix") {
      inherit system;
      modules = [
        nixvaultModule
        extraConfig
        {
          boot.loader.grub.enable = false;
          fileSystems."/" = { device = "none"; fsType = "tmpfs"; };
          system.stateVersion = "25.05";
        }
      ];
    }).config;

  # NixOS enforces assertions when `system.build.toplevel` is forced, not on a bare read of
  # `config.assertions` (a passive list). `seq` reaches the wrapping throw without deep-forcing the
  # whole system closure.
  nixosBuildFails = extraConfig:
    !(builtins.tryEval (builtins.seq (evalNixos extraConfig).system.build.toplevel true)).success;

  check = name: ok: detail: { inherit name ok detail; };

  # ── Fixtures ─────────────────────────────────────────────────────────────────────────────────
  validBase = {
    nixvault.enable = true;
    nixvault.tier = "small";
    nixvault.device = "/dev/disk/by-id/test-vault-device";
  };

  cfg-small = evalNixos validBase;
  cfg-medium = evalNixos (lib.recursiveUpdate validBase { nixvault.tier = "medium"; });
  cfg-disabled = evalNixos { nixvault.enable = false; };

  cfg-no-export = evalNixos (lib.recursiveUpdate validBase { nixvault.exportTool.enable = false; });
  cfg-no-assemble = evalNixos (lib.recursiveUpdate validBase { nixvault.assemble.enable = false; });

  cfg-warn = evalNixos (lib.recursiveUpdate validBase {
    nixvault.sources.knowledgeTree = [ "/example/knowledge-tree" ];
  });
  cfg-nowarn = evalNixos (lib.recursiveUpdate validBase {
    nixvault.tier = "medium";
    nixvault.sources.knowledgeTree = [ "/example/knowledge-tree" ];
  });

  # ── fact-wiring fixtures: `lib.probeFact` proven THROUGH the real modules/nixvault.nix ──────
  #
  # `nsImages`/`nsDisks` (and their warnings) are computed unconditionally whenever
  # `nixvault.enable` is true -- see modules/nixvault.nix's own comment above
  # `nixstorageLayoutImagesProbe` -- so `validBase` alone (device given directly, no
  # `deviceFromLayout`/`fromDisk` anywhere) already exercises state (a): nixstorage composed
  # nowhere in `cfg-small`/`cfg-medium`, and it must stay silent -- covered below via those
  # existing fixtures directly.
  #
  # Faithful nixstorage, matching the real shape both probes read.
  nixstorageFaithfulStub = {
    options.nixstorage.layout.images = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
    options.nixstorage.disks = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
  };

  cfg-facts-nixstorage-faithful = evalNixos (lib.recursiveUpdate validBase { imports = [ nixstorageFaithfulStub ]; });

  # THE DECOYS: nixstorage's real option surfaces, each renamed ONE AT A TIME. Composes the SAME
  # top-level `nixstorage` namespace the real sibling would (so `config ? nixstorage` reads true
  # -- state (a), "not composed at all", must NOT be what these fixtures exercise), with the
  # specific path under test renamed to a plausible neighbour -- while the OTHER fact this module
  # also reads stays faithfully declared, so each fixture isolates exactly one probe. Without the
  # faithful sibling declaration, the other probe would ALSO see its own path missing under
  # `nixstorage` and warn too, for a reason that has nothing to do with the rename under test.
  nixstorageLayoutRenamedStub = {
    options.nixstorage.layout.partitions = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
    options.nixstorage.disks = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
  };

  nixstorageDisksRenamedStub = {
    options.nixstorage.layout.images = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
    options.nixstorage.blockDevices = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = { };
    };
  };

  cfg-facts-layout-renamed = evalNixos (lib.recursiveUpdate validBase { imports = [ nixstorageLayoutRenamedStub ]; });
  cfg-facts-disks-renamed = evalNixos (lib.recursiveUpdate validBase { imports = [ nixstorageDisksRenamedStub ]; });

  examplePull = {
    name = "example-publisher";
    remoteHost = "example-publisher.lan";
    remotePath = "/var/lib/example/luks-headers/";
    sshKeyFile = "/root/.ssh/id_ed25519_headerpull";
    localPath = "/var/lib/nixvault-pulled-headers";
  };

  cfg-header-pull = evalNixos (lib.recursiveUpdate validBase {
    nixvault.headerBackupPull = [ examplePull ];
  });
  cfg-header-pull-no-assemble = evalNixos (lib.recursiveUpdate validBase {
    nixvault.assemble.enable = false;
    nixvault.headerBackupPull = [ examplePull ];
  });

  toolNames = [
    "nixvault-assemble"
    "nixvault-create"
    "nixvault-update"
    "nixvault-verify"
    "nixvault-export-offsite"
  ];

  hasTool = cfg: name:
    lib.any (p: lib.hasInfix name (p.name or "")) cfg.environment.systemPackages;

  # ── system-manager backend -- proves modules/nixvault.nix's "ONE FILE, BOTH BACKENDS" claim ────
  # makeSystemConfig gates its entire return value on assertions passing (nix/lib.nix's
  # returnIfNoAssertions), so `.config` is unreachable when one fails -- a faithful match for what
  # a real `nix build .#systemConfigs.<host>` does, the same shape as nixfs's own evalSm.
  evalSm = extraConfig:
    (systemManagerLib.makeSystemConfig {
      modules = [
        nixvaultModule
        extraConfig
        { nixpkgs.hostPlatform = system; }
      ];
    }).config;

  cfg-sm-small = evalSm validBase;
  cfg-sm-medium = evalSm (lib.recursiveUpdate validBase { nixvault.tier = "medium"; });
  cfg-sm-header-pull = evalSm (lib.recursiveUpdate validBase {
    nixvault.headerBackupPull = [ examplePull ];
  });

  backendParityChecks = [
    (check "backend-parity/small-manifest-categories-match"
      (sorted cfg-sm-small.nixvault.manifestCategories == sorted cfg-small.nixvault.manifestCategories)
      "system-manager: ${builtins.toJSON (sorted cfg-sm-small.nixvault.manifestCategories)}, NixOS: ${builtins.toJSON (sorted cfg-small.nixvault.manifestCategories)}")

    (check "backend-parity/medium-manifest-categories-match"
      (sorted cfg-sm-medium.nixvault.manifestCategories == sorted cfg-medium.nixvault.manifestCategories)
      "system-manager: ${builtins.toJSON (sorted cfg-sm-medium.nixvault.manifestCategories)}, NixOS: ${builtins.toJSON (sorted cfg-medium.nixvault.manifestCategories)}")

    (check "backend-parity/budgetMiB-matches"
      (cfg-sm-small.nixvault.budgetMiB == cfg-small.nixvault.budgetMiB
        && cfg-sm-medium.nixvault.budgetMiB == cfg-medium.nixvault.budgetMiB)
      "system-manager small=${toString cfg-sm-small.nixvault.budgetMiB}/medium=${toString cfg-sm-medium.nixvault.budgetMiB}, NixOS small=${toString cfg-small.nixvault.budgetMiB}/medium=${toString cfg-medium.nixvault.budgetMiB}")

    (check "backend-parity/all-five-tools-present-on-system-manager-too"
      (lib.all (n: hasTool cfg-sm-small n) toolNames)
      "missing under system-manager: ${builtins.toJSON (lib.filter (n: !(hasTool cfg-sm-small n)) toolNames)}")

    (check "backend-parity/create-and-update-are-never-systemd-units-under-system-manager-either"
      (!(cfg-sm-small.systemd.services ? "nixvault-create") && !(cfg-sm-small.systemd.services ? "nixvault-update"))
      "nixvault-create/nixvault-update must never be reachable from system-manager's systemd surface either -- both need a human-known passphrase")

    (check "backend-parity/assemble-and-verify-timers-render-on-system-manager-too"
      (cfg-sm-small.systemd.timers ? "nixvault-assemble" && cfg-sm-small.systemd.timers ? "nixvault-verify")
      "system-manager timers: ${builtins.toJSON (lib.attrNames cfg-sm-small.systemd.timers)}")

    (check "backend-parity/header-pull-service-and-timer-render-on-system-manager-too"
      (cfg-sm-header-pull.systemd.services ? "nixvault-header-pull-example-publisher"
        && cfg-sm-header-pull.systemd.timers ? "nixvault-header-pull-example-publisher")
      "system-manager systemd.services: ${builtins.toJSON (lib.attrNames cfg-sm-header-pull.systemd.services)}, systemd.timers: ${builtins.toJSON (lib.attrNames cfg-sm-header-pull.systemd.timers)}")
  ];

  results = [
    # --- 1. no default is a hard failure, never a silent guess ---------------------------------
    (check "tier/unset-fails-the-build"
      (nixosBuildFails { nixvault.enable = true; nixvault.device = "/dev/disk/by-id/test"; })
      "expected enabling with no tier to fail the build, but it succeeded")

    (check "device/unset-fails-the-build"
      (nixosBuildFails { nixvault.enable = true; nixvault.tier = "small"; })
      "expected enabling with no device to fail the build, but it succeeded")

    (check "disabled/no-tier-or-device-still-builds"
      (!(nixosBuildFails { nixvault.enable = false; }))
      "a disabled module should never need tier or device -- both assertions are gated on enable")

    # --- 2. each tier resolves to exactly what lib/manifest.nix says ---------------------------
    (check "tiers/small-categories-match-the-manifest"
      (sorted cfg-small.nixvault.manifestCategories == sorted manifest.tiers.small.categories)
      "got: ${builtins.toJSON (sorted cfg-small.nixvault.manifestCategories)}, expected: ${builtins.toJSON (sorted manifest.tiers.small.categories)}")

    (check "tiers/small-budget-is-500"
      (cfg-small.nixvault.budgetMiB == 500)
      "got: ${toString cfg-small.nixvault.budgetMiB}")

    (check "tiers/medium-categories-match-the-manifest"
      (sorted cfg-medium.nixvault.manifestCategories == sorted manifest.tiers.medium.categories)
      "got: ${builtins.toJSON (sorted cfg-medium.nixvault.manifestCategories)}, expected: ${builtins.toJSON (sorted manifest.tiers.medium.categories)}")

    (check "tiers/medium-budget-is-4096"
      (cfg-medium.nixvault.budgetMiB == 4096)
      "got: ${toString cfg-medium.nixvault.budgetMiB}")

    (check "tiers/medium-is-strictly-wider-than-small"
      (lib.all (c: builtins.elem c cfg-medium.nixvault.manifestCategories) cfg-small.nixvault.manifestCategories)
      "medium dropped a category small has: ${builtins.toJSON (lib.filter (c: !(builtins.elem c cfg-medium.nixvault.manifestCategories)) cfg-small.nixvault.manifestCategories)}")

    # --- 3. luksVolumes names must be unique -----------------------------------------------------
    (check "luksVolumes/duplicate-names-fail-the-build"
      (nixosBuildFails (lib.recursiveUpdate validBase {
        nixvault.luksVolumes = [
          { name = "example"; device = "/dev/disk/by-id/a"; }
          { name = "example"; device = "/dev/disk/by-id/b"; }
        ];
      }))
      "expected duplicate luksVolumes names to fail the build, but it succeeded")

    (check "luksVolumes/unique-names-build-fine"
      (
        !(nixosBuildFails (lib.recursiveUpdate validBase {
          nixvault.luksVolumes = [
            { name = "example-a"; device = "/dev/disk/by-id/a"; }
            { name = "example-b"; device = "/dev/disk/by-id/b"; }
          ];
        }))
      )
      "unique luksVolumes names should never fail the build")

    # --- 3b. headerBackupPull -- the LUKS header TRANSPORT, and its own name uniqueness --------
    (check "headerBackupPull/duplicate-names-fail-the-build"
      (nixosBuildFails (lib.recursiveUpdate validBase {
        nixvault.headerBackupPull = [ examplePull examplePull ];
      }))
      "expected duplicate headerBackupPull names to fail the build, but it succeeded")

    (check "headerBackupPull/unique-names-build-fine"
      (
        !(nixosBuildFails (lib.recursiveUpdate validBase {
          nixvault.headerBackupPull = [
            examplePull
            (examplePull // { name = "example-publisher-2"; })
          ];
        }))
      )
      "unique headerBackupPull names should never fail the build")

    (check "headerBackupPull/renders-its-own-service-and-timer"
      (cfg-header-pull.systemd.services ? "nixvault-header-pull-example-publisher"
        && cfg-header-pull.systemd.timers ? "nixvault-header-pull-example-publisher")
      "systemd.services: ${builtins.toJSON (lib.attrNames cfg-header-pull.systemd.services)}, systemd.timers: ${builtins.toJSON (lib.attrNames cfg-header-pull.systemd.timers)}")

    (check "headerBackupPull/timer-uses-the-entry-s-own-schedule-not-nixvault-schedule"
      (cfg-header-pull.systemd.timers."nixvault-header-pull-example-publisher".timerConfig.OnCalendar == "daily")
      "got: ${cfg-header-pull.systemd.timers."nixvault-header-pull-example-publisher".timerConfig.OnCalendar or "MISSING"}")

    (check "headerBackupPull/ordered-before-assemble-when-assemble-is-enabled"
      (lib.elem "nixvault-assemble.service" cfg-header-pull.systemd.services."nixvault-header-pull-example-publisher".before)
      "before: ${builtins.toJSON (cfg-header-pull.systemd.services."nixvault-header-pull-example-publisher".before or [ ])}")

    (check "headerBackupPull/no-assemble-ordering-when-assemble-disabled"
      (cfg-header-pull-no-assemble.systemd.services."nixvault-header-pull-example-publisher".before == [ ])
      "expected no Before= ordering once nixvault.assemble.enable is false: ${builtins.toJSON (cfg-header-pull-no-assemble.systemd.services."nixvault-header-pull-example-publisher".before or [ ])}")

    (check "headerBackupPull/installed-as-a-hand-runnable-tool-too"
      (hasTool cfg-header-pull "nixvault-header-pull-example-publisher")
      "nixvault-header-pull-example-publisher should be in environment.systemPackages, same as every other nixvault tool")

    # --- 4. every tool is installed by default, and the escape hatches actually remove one ------
    (check "packages/all-five-tools-present-by-default"
      (lib.all (n: hasTool cfg-small n) toolNames)
      "missing: ${builtins.toJSON (lib.filter (n: !(hasTool cfg-small n)) toolNames)}")

    (check "packages/exportTool-off-removes-only-the-export-tool"
      (!(hasTool cfg-no-export "nixvault-export-offsite")
        && lib.all (n: hasTool cfg-no-export n) (lib.filter (n: n != "nixvault-export-offsite") toolNames))
      "exportTool.enable = false should remove exactly nixvault-export-offsite")

    (check "packages/disabled-installs-nothing"
      (!(lib.any (p: lib.hasInfix "nixvault" (p.name or "")) cfg-disabled.environment.systemPackages))
      "nixvault.enable = false still installed a nixvault tool")

    # --- 5. nixvault-create and nixvault-update are NEVER systemd units, in any configuration ---
    (check "lifecycle/create-is-never-a-systemd-unit"
      (!(cfg-small.systemd.services ? "nixvault-create") && !(cfg-medium.systemd.services ? "nixvault-create"))
      "nixvault-create must never be reachable from a timer or a oneshot -- it mints a brand-new passphrase")

    (check "lifecycle/update-is-never-a-systemd-unit"
      (!(cfg-small.systemd.services ? "nixvault-update") && !(cfg-medium.systemd.services ? "nixvault-update"))
      "nixvault-update must never be reachable from a timer or a oneshot -- it needs the operator's passphrase interactively")

    # --- 6. assemble.enable is the one thing that toggles the assemble timer/service ------------
    (check "assemble/disabled-removes-its-service-and-timer"
      (!(cfg-no-assemble.systemd.services ? "nixvault-assemble") && !(cfg-no-assemble.systemd.timers ? "nixvault-assemble"))
      "assemble.enable = false should remove both nixvault-assemble.service and its timer")

    (check "assemble/disabled-still-keeps-verify"
      (cfg-no-assemble.systemd.services ? "nixvault-verify" && cfg-no-assemble.systemd.timers ? "nixvault-verify")
      "verify must not depend on assemble.enable -- staleness checking is independent of auto-assembly")

    # --- 7. sources outside the active tier warn, never silently drop --------------------------
    (check "warnings/out-of-tier-source-warns"
      (lib.any (w: lib.hasInfix "knowledgeTree" w) cfg-warn.warnings)
      "warnings: ${builtins.toJSON cfg-warn.warnings}")

    (check "warnings/in-tier-source-is-silent"
      (cfg-nowarn.warnings == [ ])
      "warnings: ${builtins.toJSON cfg-nowarn.warnings}")

    # --- 8. fact-wiring: lib.probeFact through the real module, not just lib/facts.nix's own ----
    #
    # Before this repo adopted lib.probeFact, NOTHING in this file exercised
    # `nixstorage.layout.images`/`nixstorage.disks` at all -- these are the first checks to force
    # either read.
    (check "fact-wiring/no-nixstorage-composed-has-no-warnings"
      (cfg-small.warnings == [ ])
      "got warnings=${builtins.toJSON cfg-small.warnings}, expected none: state (a) -- nixstorage never imported at all -- must stay silent (cfg-small sets nixvault.device directly, never deviceFromLayout/fromDisk)")

    (check "fact-wiring/nixstorage-faithful-has-no-warnings"
      (cfg-facts-nixstorage-faithful.warnings == [ ])
      "got warnings=${builtins.toJSON cfg-facts-nixstorage-faithful.warnings}, expected none: nixstorage composed with its real, un-renamed shape must produce zero warnings")

    (check "fact-wiring/nixstorage-layout-images-renamed-warns-exactly-once"
      (
        let w = cfg-facts-layout-renamed.warnings; in
        lib.length w == 1
        && lib.hasInfix "nixstorage.layout.images" (lib.head w)
        && lib.hasInfix "nixstorage" (lib.head w)
      )
      "got warnings=${builtins.toJSON cfg-facts-layout-renamed.warnings}, expected exactly one, naming nixstorage.layout.images -- the decoy renames it to nixstorage.layout.partitions while nixstorage itself IS composed, and nixvault.deviceFromLayout is unset, so nothing but the probe itself can be the source")

    (check "fact-wiring/nixstorage-layout-images-renamed-does-not-fail-the-build"
      (!(nixosBuildFails (lib.recursiveUpdate validBase { imports = [ nixstorageLayoutRenamedStub ]; })))
      "state (c) must warn, not fail the build -- lib.probeFact defaults to mode = \"warn\", never \"assert\", for these two reads")

    (check "fact-wiring/nixstorage-disks-renamed-warns-exactly-once"
      (
        let w = cfg-facts-disks-renamed.warnings; in
        lib.length w == 1
        && lib.hasInfix "nixstorage.disks" (lib.head w)
        && lib.hasInfix "nixstorage" (lib.head w)
      )
      "got warnings=${builtins.toJSON cfg-facts-disks-renamed.warnings}, expected exactly one, naming nixstorage.disks -- the decoy renames it to nixstorage.blockDevices while nixstorage itself IS composed, and no luksVolumes entry sets fromDisk, so nothing but the probe itself can be the source")

    (check "fact-wiring/nixstorage-disks-renamed-does-not-fail-the-build"
      (!(nixosBuildFails (lib.recursiveUpdate validBase { imports = [ nixstorageDisksRenamedStub ]; })))
      "state (c) must warn, not fail the build, same as the layout.images case above")
  ]
  ++ backendParityChecks;

  failed = builtins.filter (r: !r.ok) results;

  report = lib.concatMapStringsSep "\n" (r: "  - ${r.name}: ${r.detail}") failed;
in
if failed != [ ]
then
  throw ''
    nixvault eval-tests FAILED (${toString (builtins.length failed)}/${toString (builtins.length results)}):
    ${report}
  ''
else {
  # Depending on `passedCount` forces `results`, so the tests genuinely run under `nix flake check`
  # rather than merely being defined.
  eval-tests = pkgs.runCommand "nixvault-eval-tests"
    { passedCount = toString (builtins.length results); }
    ''
      echo "all $passedCount nixvault eval tests passed"
      touch $out
    '';

  # The one REAL runtime test: a pkgs.testers.nixosTest, the house pattern nixram's
  # swappiness-relief-vm-test.nix and nixrescue's checks/ already proved out in this repo family --
  # see that file's own header for exactly what it exercises and why.
  lifecycle-vm-test = import ./lifecycle-vm-test.nix {
    inherit pkgs nixvaultModule;
  };
}
