# checks/default.nix
#
# EVAL-TIME tests, the same posture as the sibling nixfs project: each test evaluates a real
# configuration through NixOS's own eval-config.nix and inspects what the module RENDERS or
# whether the build fails. Nothing here boots anything -- the claims under test (which tier resolves
# to which categories, which tools are always/never wired to systemd, which combinations must fail
# the build) are entirely eval-time properties.
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
{ pkgs, lib, nixpkgs, system, nixvaultModule }:

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

  toolNames = [
    "nixvault-assemble"
    "nixvault-create"
    "nixvault-update"
    "nixvault-verify"
    "nixvault-export-offsite"
  ];

  hasTool = cfg: name:
    lib.any (p: lib.hasInfix name (p.name or "")) cfg.environment.systemPackages;

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
  ];

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
}
