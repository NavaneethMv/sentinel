{
  description = "Sentinel Python development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        devShells.default = pkgs.mkShell {
          name = "sentinel";

          packages = with pkgs; [
            python313
            uv
            ruff
            just
            git
            curl
          ];

          shellHook = ''
            echo "Sentinel Dev Shell"
            
            # Setup venv if it doesn't exist
            if [ ! -d ".venv" ]; then
              echo "Creating virtual environment..."
              ${pkgs.uv}/bin/uv venv
            fi
            source .venv/bin/activate
            
            echo "Python: $(python --version)"
            echo "UV: $(uv --version)"
          '';
        };
      });
}