{
  description = "RFC 6455 WebSocket framing, handshake, and message assembly.";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    cl-weave = {
      url = "github:nerima-lisp/cl-weave/v1.3.0";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    cl-http-message-kit = {
      url = "github:nerima-lisp/cl-http-message-kit/v2.0.0";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-hpack-codec-kit.follows = "cl-hpack-codec-kit";
    };

    cl-hpack-codec-kit = {
      url = "github:nerima-lisp/cl-hpack-codec-kit/v1.1.2";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
    };

    cl-codec-kit = {
      url = "github:nerima-lisp/cl-codec-kit/v0.5.0";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
    };

    cl-deflate-kit = {
      url = "github:nerima-lisp/cl-deflate-kit/v0.4.0";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
    };

    cl-crypto-kit = {
      url = "github:nerima-lisp/cl-crypto-kit/v0.2.2";
      flake = false;
    };

    cl-tls-kit = {
      url = "github:nerima-lisp/cl-tls-kit/f39e05059c572bb51df93dd25f619d64d6749ecc";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-crypto-kit.follows = "cl-crypto-kit";
    };

    cl-quic-kit = {
      url = "github:nerima-lisp/cl-quic-kit/v0.1.1";
      flake = false;
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
      url = "github:nerima-lisp/cl-http-kit/48d5a0141fe8899571b79a2b1027f481c1d8307f";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.cl-weave.follows = "cl-weave";
      inputs.cl-boundary-kit.follows = "cl-boundary-kit";
      inputs.cl-host-kit.follows = "cl-host-kit";
      inputs.cl-codec-kit.follows = "cl-codec-kit";
      inputs.cl-deflate-kit.follows = "cl-deflate-kit";
      inputs.cl-crypto-kit.follows = "cl-crypto-kit";
      inputs.cl-hpack-codec-kit.follows = "cl-hpack-codec-kit";
      inputs.cl-http-message-kit.follows = "cl-http-message-kit";
      inputs.cl-quic-kit.follows = "cl-quic-kit";
      inputs.cl-tls-kit.follows = "cl-tls-kit";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      cl-weave,
      cl-http-message-kit,
      cl-hpack-codec-kit,
      cl-host-kit,
      cl-boundary-kit,
      cl-codec-kit,
      cl-deflate-kit,
      cl-crypto-kit,
      cl-tls-kit,
      cl-quic-kit,
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
          hpackKit = mkCommonLispSource pkgs "cl-hpack-codec-kit" cl-hpack-codec-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
          codecKit = mkCommonLispSource pkgs "cl-codec-kit" cl-codec-kit;
          deflateKit = mkCommonLispSource pkgs "cl-deflate-kit" cl-deflate-kit;
          cryptoKit = mkCommonLispSource pkgs "cl-crypto-kit" cl-crypto-kit;
          tlsKit = mkCommonLispSource pkgs "cl-tls-kit" cl-tls-kit;
          quicKit = mkCommonLispSource pkgs "cl-quic-kit" cl-quic-kit;
        in
        {
          default = pkgs.mkShell {
            packages = [
              cl-weave.packages.${system}.default
              cl-http-message-kit.packages.${system}.default
              hpackKit
              httpKit
              boundaryKit
              hostKit
              codecKit
              deflateKit
              cryptoKit
              tlsKit
              quicKit
              pkgs.sbcl
              pkgs.coreutils
              pkgs.perl
              pkgs.openssl
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
          hpackKit = mkCommonLispSource pkgs "cl-hpack-codec-kit" cl-hpack-codec-kit;
          boundaryKit = mkCommonLispSource pkgs "cl-boundary-kit" cl-boundary-kit;
          hostKit = mkCommonLispSource pkgs "cl-host-kit" cl-host-kit;
          codecKit = mkCommonLispSource pkgs "cl-codec-kit" cl-codec-kit;
          deflateKit = mkCommonLispSource pkgs "cl-deflate-kit" cl-deflate-kit;
          cryptoKit = mkCommonLispSource pkgs "cl-crypto-kit" cl-crypto-kit;
          tlsKit = mkCommonLispSource pkgs "cl-tls-kit" cl-tls-kit;
          quicKit = mkCommonLispSource pkgs "cl-quic-kit" cl-quic-kit;
          bordeauxThreads = pkgs.sbclPackages.bordeaux-threads;
          sourceRegistry = builtins.concatStringsSep ":" (
            [
              "${messageKit}/share/common-lisp/source/cl-http-message-kit"
              "${hpackKit}/share/common-lisp/source/cl-hpack-codec-kit"
              "${httpKit}/share/common-lisp/source/cl-http-kit"
              "${boundaryKit}/share/common-lisp/source/cl-boundary-kit"
              "${hostKit}/share/common-lisp/source/cl-host-kit"
              "${codecKit}/share/common-lisp/source/cl-codec-kit"
              "${deflateKit}/share/common-lisp/source/cl-deflate-kit"
              "${cryptoKit}/share/common-lisp/source/cl-crypto-kit"
              "${tlsKit}/share/common-lisp/source/cl-tls-kit"
              "${quicKit}/share/common-lisp/source/cl-quic-kit"
              "${bordeauxThreads}"
            ]
            ++ map toString bordeauxThreads.propagatedBuildInputs
          );
          test = pkgs.writeShellApplication {
            name = "cl-websocket-kit-test";
            runtimeInputs = [
              pkgs.sbcl
              pkgs.openssl
              pkgs.socat
              clWeave
              messageKit
              hpackKit
              httpKit
              boundaryKit
              hostKit
              codecKit
              deflateKit
              cryptoKit
              tlsKit
              quicKit
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
    };
}
