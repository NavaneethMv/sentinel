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
            # Adding PyYAML here ensures system-level dependencies are met
            python313Packages.pyyaml 
            python313Packages.lark
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
            
            # Since you're using uv, you might want to ensure it's synced
            # uv pip install pyyaml
            
            echo "Python: $(python --version)"
            echo "UV: $(uv --version)"
            echo "PyYAML: $(python -c 'import yaml; print("Installed")' 2>/dev/null || echo "Not found in venv")"
          '';
        };
      });
}