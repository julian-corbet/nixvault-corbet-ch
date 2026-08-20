{
  description = "nixvault -- keeping the copy that outlives the original: a passphrase-only, per-host disaster-recovery vault (LUKS -> f2fs) built on the host it protects, and the archives that keep the web and the video somebody chose to save";

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

    # ── THE CLUSTER HALF'S TWO INPUTS, USED BY `checks` ALONE ────────────────────────────────────
    #
    # Neither reaches anything this flake exports. `nixidyModules.nixvault` is a plain module file
    # that takes `config`/`lib` from whichever evaluation composes it, exactly like the two host
    # backends above, so a consumer rendering it pays for neither input.
    #
    # They exist because `nix flake check` evaluates no module output on its own: without a renderer
    # and the grammar to render into, the cluster half would be a module verified by nobody, passing
    # CI on flake syntax alone.

    # The renderer the cluster module defines into.
    nixidy = {
      url = "github:arnarg/nixidy";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    # THE APP GRAMMAR THIS REPOSITORY CONSUMES -- the point being proven rather than a shortcut. A
    # consumer imports the grammar itself, and this input is here so the checks can render the
    # cluster module through the REAL grammar and assert what comes out, rather than asserting that a
    # module which merely mentions `nixk3s.apps` evaluates.
    nixk3s = {
      url = "github:julian-corbet/nixk3s-corbet-ch";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixidy.follows = "nixidy";
    };
  };

  outputs = { self, nixpkgs, system-manager, nixfs, nixhost, nixidy, nixk3s }:
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

      # The cluster plane: the archives that run in the cluster rather than on the host the vault
      # protects. A different SHAPE from the two backends above -- it renders Kubernetes objects
      # through a renderer, not systemd units through a backend -- and the same subject, which is
      # why it lives here: an archive keeps the copy that outlives the original, and so does a
      # vault. Only one module in the class, so `.default` is honest rather than invented.
      nixidyModules.nixvault = ./modules/cluster.nix;
      nixidyModules.default = self.nixidyModules.nixvault;

      # The manifest, exposed so a consumer can inspect the tier/category shape without re-reading
      # the file -- same reason nixfs exposes its catalogue.
      lib.manifest = import ./lib/manifest.nix { };

      # The archive catalogue, same reason: what each one IS, inspectable without re-reading the
      # file and without composing the module.
      lib.archives = (import ./lib/archives.nix { }).archives;

      checks = forAllSystems (system:
        let
          pkgs = pkgsFor system;
          clusterArgs = {
            inherit pkgs lib nixidy;
            appsModule = nixk3s.nixidyModules.apps;
            clusterModule = self.nixidyModules.nixvault;
            values = ./examples/all/values.nix;
          };
        in
        import ./checks {
          inherit pkgs lib nixpkgs system;
          nixvaultModule = self.nixosModules.nixvault;
          systemManagerLib = system-manager.lib;
        }
        # x86_64-linux only, and narrow ON PURPOSE. Both cluster checks build a real nixidy
        # environment, so a declared platform that cannot be built here is a platform `nix flake
        # check` skips while exiting 0 -- a check that passed having tested nothing. Narrow the
        # claim rather than weaken the check; the vault half above genuinely runs on both.
        // lib.optionalAttrs (system == "x86_64-linux") {
          # The cluster module's own resolution and every guard it makes, in BOTH directions: an
          # empty surface renders nothing, a declared one resolves, and each refusal gets a
          # declaration that must be refused.
          cluster-eval = import ./checks/cluster-eval.nix clusterArgs;

          # The manifests that actually come out, read back off the rendered bytes rather than off
          # the options that produced them.
          cluster-render = import ./checks/cluster-render.nix clusterArgs;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
