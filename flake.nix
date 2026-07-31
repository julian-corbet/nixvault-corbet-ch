{
  description = "nixvault -- a passphrase-only, per-host disaster-recovery vault (LUKS -> f2fs), assembled from a curated manifest and built on the host it protects";

  inputs = {
    # Used by `checks` only. The module itself takes `pkgs` from the consuming evaluation and never
    # references this input, so a consumer that does not follow it pays no second nixpkgs.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Also used by `checks` only (backend-parity eval tests) -- the module itself is exported
    # unchanged for both backends (see modules/nixvault.nix's "ONE FILE, BOTH BACKENDS" header),
    # so a consumer targeting only one backend pays no cost for the one it doesn't use.
    system-manager.url = "github:numtide/system-manager";
    system-manager.inputs.nixpkgs.follows = "nixpkgs";

    # nixfs — the filesystem domain, and the SOLE owner of the f2fs compression recipe (mkfs
    # feature bits, mount options, the kernel floor they need). It is data, not policy, so it is
    # consumed as a lib value (`nixfs.lib.catalogue`), the same lower-layer-provides-a-lib category
    # as nixtest's own fixtures -- never nixfs's own nixosModules, which this module has no reason
    # to install.
    nixfs.url = "github:julian-corbet/nixfs-corbet-ch";
    nixfs.inputs.nixpkgs.follows = "nixpkgs";

    # nixhost IS an input, for exactly one thing: `lib.probeFact`/`lib.collectProbes`
    # (github:julian-corbet/nixhost-corbet-ch, `lib/facts.nix`) -- the shared, plain-function fix
    # for the cross-namespace defensive-read defect class this module's own
    # `nixstorageLayoutImagesProbe`/`nixstorageDisksProbe` lean on (see nixhost's own
    # `lib/facts.nix` header). `probeFact`/`collectProbes` are closed over as plain function
    # arguments alongside `nixfsCatalogue` (below), never `_module.args` -- for the identical
    # reason `nixfsCatalogue` isn't: a module-argument name is a namespace every module composed
    # alongside this one shares, and `_module.args` merges with `mergeOneOption`, which rejects a
    # second definition even when the values are identical, so no `inputs.follows` pin could fix a
    # collision there either.
    #
    # ONLY `nixpkgs.follows` is pinned here, never a follow on nixhost itself -- this repo has no
    # way to reach into a CONSUMER's own separate `nixhost` input to force them to share a
    # revision. That reconciliation happens on the CONSUMER side, the same shape already used for
    # the nixfs skew between this repo and nixnas (`inputs.nixvault.inputs.nixfs.follows = "nixfs"`
    # plus a runtime assertion comparing both resolved catalogues): a consumer taking both this
    # flake and nixhost directly needs the equivalent `inputs.nixvault.inputs.nixhost.follows =
    # "nixhost"` to avoid locking two separate nixhost revisions side by side.
    nixhost = {
      url = "github:julian-corbet/nixhost-corbet-ch";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, system-manager, nixfs, nixhost }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };

      # The f2fs compression recipe, applied to modules/nixvault.nix as a plain, partially-applied
      # function argument -- a constant this flake closes over, never a per-host `config.nixfs.*`
      # read: a recipe is a fact about f2fs, not something a host declares. NOT
      # `_module.args.nixfsCatalogue`: a module-argument name is a GLOBAL namespace shared with
      # anything else composed alongside this module, and a sibling appliance flake consuming the
      # same nixfs catalogue picked the identical argument name for the identical reason -- correct
      # alone, a hard "defined multiple times" eval failure the moment a consumer composes both.
      # `_module.args` merges with `mergeOneOption`, which rejects a second definition even when
      # the two values are identical, so no `inputs.follows` pin could have fixed that either.
      # Partial application closes over the value before it ever becomes a module argument at all:
      # `import ./modules/nixvault.nix { inherit nixfsCatalogue; }` fully applies the outer
      # function here, in this flake, producing the actual `{ config, lib, pkgs, ... }:` module --
      # the module system never sees, and never has to call, the outer `{ nixfsCatalogue }:`
      # layer, so nixfs never enters `_module.args` at all. A consumer importing
      # `nixosModules.default` still never has to know nixfs exists, let alone follow it
      # themselves. The rule -- a flake must never publish a fact through `_module.args` -- is
      # written down once, for every sibling, in nixfs's own README ("Family convention: consuming
      # lib.catalogue ... never through `_module.args`").
      #
      # `probeFact`/`collectProbes` ride along in the SAME partial application, for the SAME
      # reason -- see the `nixhost` input comment above. modules/nixvault.nix's outer layer is
      # now `{ nixfsCatalogue, probeFact, collectProbes }:`; all three are supplied here, fully
      # applying that layer before the module system ever sees the result.
      nixvaultModule = import ./modules/nixvault.nix {
        nixfsCatalogue = nixfs.lib.catalogue;
        inherit (nixhost.lib) probeFact collectProbes;
      };
    in
    {
      nixosModules.nixvault = nixvaultModule;
      nixosModules.default = self.nixosModules.nixvault;

      # The system-manager (numtide) equivalent, for the one target this design requires nixvault
      # on that is NOT NixOS. The SAME underlying file, unchanged -- see modules/nixvault.nix's
      # own "ONE FILE, BOTH BACKENDS" header for exactly why that is honest rather than lazy:
      # nixvault only ever touches option surface (environment.systemPackages,
      # systemd.services/timers, assertions, warnings) that system-manager supports identically
      # to NixOS. The partial application above is backend-agnostic too -- it happens before
      # either backend's module system ever runs, so both get the identical already-applied
      # module.
      systemManagerModules.nixvault = nixvaultModule;
      systemManagerModules.default = self.systemManagerModules.nixvault;

      # The manifest, exposed so a consumer can inspect the tier/category shape without re-reading
      # the file -- same reason nixfs exposes its catalogue.
      lib.manifest = import ./lib/manifest.nix { };

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixvaultModule = self.nixosModules.nixvault;
          systemManagerLib = system-manager.lib;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
