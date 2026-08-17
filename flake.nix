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

    cl-host-kit = {
      url = "github:nerima-lisp/cl-host-kit/v0.3.1";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-boundary-kit = {
      url = "github:nerima-lisp/cl-boundary-kit/v2.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-host-kit.follows = "cl-host-kit";
    };

    cl-http-kit = {
      url = "github:nerima-lisp/cl-http-kit";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-boundary-kit.follows = "cl-boundary-kit";
      inputs.cl-host-kit.follows = "cl-host-kit";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-weave,
      cl-http-message-kit,
      cl-host-kit,
      cl-boundary-kit,
      cl-http-kit,
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
      mkCommonLispSource =
        pkgs: system-name: source:
        pkgs.stdenvNoCC.mkDerivation {
          pname = "${system-name}-source";
          version = "unstable";
          src = source;
          dontBuild = true;
          installPhase = ''
            runHook preInstall
            target="$out/share/common-lisp/source/${system-name}"
            mkdir -p "$target"
            cp -r . "$target"/
            runHook postInstall
          '';
        };
    in
    {
      formatter = forEachSystem (system: pkgs: pkgs.nixfmt-tree);

      # The source tree, installed where an ASDF source registry expects to
      # find it. A consumer registers the package directory directly; there
      # is nothing to compile ahead of time.
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
        system: pkgs:
        let
          httpKit = mkCommonLispSource pkgs "cl-http-kit" cl-http-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
        in
        {
          default = pkgs.mkShell {
            packages = [
              cl-weave.packages.${system}.default
              cl-http-message-kit.packages.${system}.default
              httpKit
              boundaryKit
              hostKit
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
          httpKit = mkCommonLispSource pkgs "cl-http-kit" cl-http-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
          sourceRegistry = builtins.concatStringsSep ":" [
            "${messageKit}/share/common-lisp/source/cl-http-message-kit"
            "${httpKit}/share/common-lisp/source/cl-http-kit"
            "${boundaryKit}/share/common-lisp/source/cl-boundary-kit"
            "${hostKit}/share/common-lisp/source/cl-host-kit"
          ];
          test = pkgs.writeShellApplication {
            name = "cl-websocket-kit-test";
            runtimeInputs = [
              pkgs.sbcl
              clWeave
              messageKit
              httpKit
              boundaryKit
              hostKit
            ];
            text = ''
              export CL_SOURCE_REGISTRY="$PWD:${sourceRegistry}"
              cl-weave run --load "$PWD/cl-websocket-kit.asd" \
                cl-websocket-kit/test --reporter spec --max-workers 1 \
                --fail-with-no-tests --test-timeout-ms 30000
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
