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
      url = "github:nerima-lisp/cl-http-kit/land/main-catchup";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-boundary-kit.follows = "cl-boundary-kit";
      inputs.cl-host-kit.follows = "cl-host-kit";
      inputs.cl-crypto-kit.follows = "cl-crypto-kit";
      inputs.cl-deflate-kit.follows = "cl-deflate-kit";
      inputs.cl-tls-kit.follows = "cl-tls-kit";
    };

    cl-crypto-kit = {
      url = "github:nerima-lisp/cl-crypto-kit/takeokunn-crypto-integration";
      flake = false;
    };

    cl-deflate-kit = {
      url = "github:nerima-lisp/cl-deflate-kit/takeokunn-deflate-core";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
    };

    cl-tls-kit = {
      url = "github:nerima-lisp/cl-tls-kit/takeokunn-tls13-handshake";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-crypto-kit.follows = "cl-crypto-kit";
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
      cl-crypto-kit,
      cl-deflate-kit,
      cl-tls-kit,
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
            version = "0.2.0";
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
          cryptoKit = mkCommonLispSource pkgs "cl-crypto-kit" cl-crypto-kit;
          deflateKit = mkCommonLispSource pkgs "cl-deflate-kit" cl-deflate-kit;
          tlsKit = mkCommonLispSource pkgs "cl-tls-kit" cl-tls-kit;
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
              cryptoKit
              deflateKit
              tlsKit
              pkgs.sbcl
              pkgs.coreutils
              pkgs.openssl
              pkgs.perl
              pkgs.socat
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
          cryptoKit = mkCommonLispSource pkgs "cl-crypto-kit" cl-crypto-kit;
          deflateKit = mkCommonLispSource pkgs "cl-deflate-kit" cl-deflate-kit;
          tlsKit = mkCommonLispSource pkgs "cl-tls-kit" cl-tls-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
          sourceRegistry = builtins.concatStringsSep ":" [
            "${messageKit}/share/common-lisp/source/cl-http-message-kit"
            "${httpKit}/share/common-lisp/source/cl-http-kit"
            "${boundaryKit}/share/common-lisp/source/cl-boundary-kit"
            "${hostKit}/share/common-lisp/source/cl-host-kit"
            "${cryptoKit}/share/common-lisp/source/cl-crypto-kit"
            "${deflateKit}/share/common-lisp/source/cl-deflate-kit"
            "${tlsKit}/share/common-lisp/source/cl-tls-kit"
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
              cryptoKit
              deflateKit
              tlsKit
              pkgs.openssl
              pkgs.socat
            ];
            text = ''
              export SBCL_HOME="${pkgs.sbcl}/lib/sbcl"
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

      checks = forEachSystem (
        system: pkgs:
        let
          clWeave = cl-weave.packages.${system}.default;
          messageKit = cl-http-message-kit.packages.${system}.default;
          httpKit = mkCommonLispSource pkgs "cl-http-kit" cl-http-kit;
          cryptoKit = mkCommonLispSource pkgs "cl-crypto-kit" cl-crypto-kit;
          deflateKit = mkCommonLispSource pkgs "cl-deflate-kit" cl-deflate-kit;
          tlsKit = mkCommonLispSource pkgs "cl-tls-kit" cl-tls-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
          sourceRegistry = builtins.concatStringsSep ":" [
            "${messageKit}/share/common-lisp/source/cl-http-message-kit"
            "${httpKit}/share/common-lisp/source/cl-http-kit"
            "${boundaryKit}/share/common-lisp/source/cl-boundary-kit"
            "${hostKit}/share/common-lisp/source/cl-host-kit"
            "${cryptoKit}/share/common-lisp/source/cl-crypto-kit"
            "${deflateKit}/share/common-lisp/source/cl-deflate-kit"
            "${tlsKit}/share/common-lisp/source/cl-tls-kit"
          ];
        in
        {
          default = pkgs.stdenvNoCC.mkDerivation {
            pname = "cl-websocket-kit-tests";
            version = "0.2.0";
            src = self;
            nativeBuildInputs = [
              pkgs.sbcl
              clWeave
              messageKit
              httpKit
              boundaryKit
              hostKit
              cryptoKit
              deflateKit
              tlsKit
              pkgs.openssl
              pkgs.socat
            ];
            dontConfigure = true;
            dontBuild = true;
            doCheck = true;
            checkPhase = ''
              export HOME="$TMPDIR/home"
              export XDG_CACHE_HOME="$TMPDIR/cache"
              mkdir -p "$HOME" "$XDG_CACHE_HOME"
              export SBCL_HOME="${pkgs.sbcl}/lib/sbcl"
              export CL_SOURCE_REGISTRY="$PWD:${sourceRegistry}"
              cl-weave run --load "$PWD/cl-websocket-kit.asd" \
                cl-websocket-kit/test --reporter spec --max-workers 1 \
                --fail-with-no-tests --test-timeout-ms 30000
            '';
            installPhase = "mkdir -p $out; touch $out/passed";
          };
        }
      );
    };
}
