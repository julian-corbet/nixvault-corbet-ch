{
  description = "nixvault -- a passphrase-only, per-host disaster-recovery vault (LUKS -> squashfs), assembled from a curated manifest and built on the host it protects";

  inputs = {
    # Used by `checks` only. The module itself takes `pkgs` from the consuming evaluation and never
    # references this input, so a consumer that does not follow it pays no second nixpkgs.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      lib = nixpkgs.lib;
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      nixosModules.nixvault = ./modules/nixvault.nix;
      nixosModules.default = self.nixosModules.nixvault;

      # The manifest, exposed so a consumer can inspect the tier/category shape without re-reading
      # the file -- same reason nixfs exposes its catalogue.
      lib.manifest = import ./lib/manifest.nix { };

      checks = forAllSystems (system:
        import ./checks {
          pkgs = pkgsFor system;
          inherit lib nixpkgs system;
          nixvaultModule = self.nixosModules.nixvault;
        });

      formatter = forAllSystems (system: (pkgsFor system).nixpkgs-fmt);
    };
}
