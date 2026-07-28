{
  description = "nixvault -- a passphrase-only, per-host disaster-recovery vault (LUKS -> squashfs), assembled from a curated manifest and built on the host it protects";

  inputs = {
    # Used by `checks` only. The module itself takes `pkgs` from the consuming evaluation and never
    # references this input, so a consumer that does not follow it pays no second nixpkgs.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Also used by `checks` only (backend-parity eval tests) -- the module itself is exported
    # unchanged for both backends (see modules/nixvault.nix's "ONE FILE, BOTH BACKENDS" header),
    # so a consumer targeting only one backend pays no cost for the one it doesn't use.
    system-manager.url = "github:numtide/system-manager";
    system-manager.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, system-manager }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      nixosModules.nixvault = ./modules/nixvault.nix;
      nixosModules.default = self.nixosModules.nixvault;

      # The system-manager (numtide) equivalent, for the one target this design requires nixvault
      # on that is NOT NixOS. The SAME file, unchanged -- see modules/nixvault.nix's own
      # "ONE FILE, BOTH BACKENDS" header for exactly why that is honest rather than lazy: nixvault
      # only ever touches option surface (environment.systemPackages, systemd.services/timers,
      # assertions, warnings) that system-manager supports identically to NixOS, confirmed by
      # reading its actual module source, not assumed.
      systemManagerModules.nixvault = ./modules/nixvault.nix;
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
