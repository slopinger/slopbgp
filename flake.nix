{
  description = "slopbgp: revolutionary BGP-4 & MP-BGP routing daemon in Gleam for DN42";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { self, nixpkgs }: let
    systems = [ "x86_64-linux" "aarch64-linux" ];
    eachSystem = nixpkgs.lib.genAttrs systems;
  in {
    packages = eachSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      manifest = builtins.fromTOML (builtins.readFile ./manifest.toml);
      dependencies = map (dep: {
        inherit (dep) name version;
        archive = pkgs.fetchurl {
          url = "https://repo.hex.pm/tarballs/${dep.name}-${dep.version}.tar";
          sha256 = dep.outer_checksum;
        };
      }) manifest.packages;
      packageIndex = (pkgs.formats.toml {}).generate "packages.toml" {
        packages = builtins.listToAttrs (map (dep: { name = dep.name; value = dep.version; }) dependencies);
        git = {};
      };
    in {
      default = pkgs.stdenvNoCC.mkDerivation {
        pname = "slopbgp";
        version = "0.1.0";
        src = pkgs.lib.cleanSourceWith {
          src = self;
          filter = path: type: !(builtins.elem (builtins.baseNameOf path) [ ".git" "build" ".direnv" "result" ]);
        };
        nativeBuildInputs = [ pkgs.gleam pkgs.beamPackages.erlang pkgs.rebar3 pkgs.makeWrapper ];
        env.ERL_FLAGS = "+S 4:4";
        postUnpack = ''
          cd "$sourceRoot"
          mkdir -p build/packages
          cp ${packageIndex} build/packages/packages.toml
          chmod u+w build/packages/packages.toml
          ${pkgs.lib.concatMapStringsSep "\n" (dep: ''
            mkdir -p build/packages/${dep.name} unpack-hex
            tar -xf ${dep.archive} -C unpack-hex
            tar -xzf unpack-hex/contents.tar.gz -C build/packages/${dep.name}
            rm -rf unpack-hex
          '') dependencies}
          cd ..
        '';
        buildPhase = ''
          runHook preBuild
          export HOME=$TMPDIR
          gleam export erlang-shipment
          patchShebangs build/erlang-shipment/entrypoint.sh
          runHook postBuild
        '';
        doCheck = true;
        checkPhase = ''
          gleam format --check src test
          gleam test
        '';
        installPhase = ''
          mkdir -p $out/lib/slopbgp $out/bin
          cp -r build/erlang-shipment/. $out/lib/slopbgp/
          makeWrapper $out/lib/slopbgp/entrypoint.sh $out/bin/slopbgp \
            --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.beamPackages.erlang ]} --add-flags run
          ln -s $out/bin/slopbgp $out/bin/slopbgpctl
        '';
        meta = { license = pkgs.lib.licenses.mit; platforms = systems; mainProgram = "slopbgp"; };
      };
    });
    checks = eachSystem (system: { package = self.packages.${system}.default; });
    hydraJobs = {
      package = eachSystem (system: self.packages.${system}.default);
    };
    devShells = eachSystem (system: {
      default = nixpkgs.legacyPackages.${system}.mkShell {
        packages = with nixpkgs.legacyPackages.${system}; [ gleam beamPackages.erlang rebar3 ];
        ERL_FLAGS = "+S 4:4";
      };
    });
    nixosModules.default = import ./nix/module.nix { inherit self; };
  };
}
