{
  description = "RFC 6455 WebSocket framing, handshake, and message assembly.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-http-message-kit = {
      url = "github:nerima-lisp/cl-http-message-kit";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-weave,
      cl-http-message-kit,
      ...
    }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forEachSystem =
        function:
        nixpkgs.lib.genAttrs systems (system: function system (import nixpkgs { inherit system; }));
    in
    {
      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);

      # The source tree, installed where an ASDF source registry expects to
      # find it. A consumer adds "${cl-websocket-kit}/share/common-lisp/source//"
      # to CL_SOURCE_REGISTRY; there is nothing to compile ahead of time.
      packages = forEachSystem (
        system: pkgs: {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "cl-websocket-kit";
            version = "0.1.0";
            src = self;
            dontBuild = true;
            installPhase = ''
              runHook preInstall
              target="$out/share/common-lisp/source/cl-websocket-kit"
              mkdir -p "$target"
              cp -r cl-websocket-kit.asd src t "$target"/
              runHook postInstall
            '';
            meta = {
              description = "RFC 6455 WebSocket framing, handshake, and message assembly";
              license = pkgs.lib.licenses.mit;
            };
          };
        }
      );

      devShells = forEachSystem (
        system: pkgs: {
          default = pkgs.mkShell {
            packages = [
              cl-weave.packages.${system}.default
              cl-http-message-kit.packages.${system}.default
              pkgs.sbcl
              pkgs.coreutils
              pkgs.perl
            ];
          };
        }
      );

      apps = forEachSystem (
        system: pkgs:
        let
          clWeave = cl-weave.packages.${system}.default;
          messageKit = cl-http-message-kit.packages.${system}.default;
          sourceRegistry = "${clWeave}/share/common-lisp/source//:${messageKit}/share/common-lisp/source//";
          test = pkgs.writeShellApplication {
            name = "cl-websocket-kit-test";
            runtimeInputs = [
              pkgs.sbcl
              clWeave
              messageKit
            ];
            text = ''
              export CL_SOURCE_REGISTRY="$PWD//:${sourceRegistry}"
              sbcl --noinform --non-interactive \
                --eval '(require :asdf)' \
                --eval '(asdf:test-system "cl-websocket-kit")'
            '';
          };
        in
        {
          default = {
            type = "app";
            program = "${test}/bin/cl-websocket-kit-test";
          };
          test = {
            type = "app";
            program = "${test}/bin/cl-websocket-kit-test";
          };
        }
      );
    };
}
