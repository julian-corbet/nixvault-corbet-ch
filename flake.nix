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
    # feature bits, mount options, the kernel floor they need). This vault's f2fs container used
    # to VENDOR that recipe (lib/f2fs-vault-opts.nix, a byte-for-byte copy of nixnas's own
    # store recipe) rather than depend on anything -- the header on that file said as much,
    # explicitly, and even so it was still a second copy of one field-validated set of facts.
    # It is data, not policy, so it is consumed as a lib value (`nixfs.lib.catalogue`), the
    # same lower-layer-provides-a-lib category as nixtest's own fixtures -- never nixfs's own
    # nixosModules, which this module has no reason to install.
    nixfs.url = "github:julian-corbet/nixfs-corbet-ch";
    nixfs.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, system-manager, nixfs }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };

      # The f2fs compression recipe, made available to modules/nixvault.nix as the plain module
      # argument `nixfsCatalogue` -- a constant this flake closes over, never a per-host
      # `config.nixfs.*` read: a recipe is a fact about f2fs, not something a host declares.
      # `_module.args` (rather than `specialArgs`) is what lets this stay entirely internal to
      # the module wrapper below -- a consumer importing `nixosModules.default` never has to
      # know nixfs exists, let alone follow it themselves.
      withNixfsCatalogue = {
        _module.args.nixfsCatalogue = nixfs.lib.catalogue;
        imports = [ ./modules/nixvault.nix ];
      };
    in
    {
      nixosModules.nixvault = withNixfsCatalogue;
      nixosModules.default = self.nixosModules.nixvault;

      # The system-manager (numtide) equivalent, for the one target this design requires nixvault
      # on that is NOT NixOS. The SAME underlying file, unchanged -- see modules/nixvault.nix's
      # own "ONE FILE, BOTH BACKENDS" header for exactly why that is honest rather than lazy:
      # nixvault only ever touches option surface (environment.systemPackages,
      # systemd.services/timers, assertions, warnings) that system-manager supports identically
      # to NixOS, confirmed by reading its actual module source, not assumed -- and that
      # includes `_module.args`, the same generic `lib.evalModules` mechanism the wrapper above
      # uses, not a NixOS-only extension.
      systemManagerModules.nixvault = withNixfsCatalogue;
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
