# cl-websocket-kit

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

cl-websocket-kit implements RFC 6455 together with a bounded HTTP/1.1 and
network transport layer: frame encoding and decoding, masking, fragmentation,
control frames, close codes, UTF-8 validation, bounded message assembly, the
HTTP Upgrade handshake, persistent HTTP/1.1 connections, TCP client/listener
lifecycle, optional TLS, and HTTP CONNECT/SOCKS5 proxy traversal.

It uses
[cl-http-message-kit](https://github.com/nerima-lisp/cl-http-message-kit) for
HTTP request and response values and `cl-http-kit/http2` plus
`cl-http-kit/http3` for the HTTP/2 and HTTP/3 header and frame codecs. Native
TCP and DNS support is provided on SBCL. TLS is optional and loaded through
`cl+ssl` when that system is installed.

## Install

```lisp
(asdf:load-system "cl-websocket-kit")
```

## Usage

```lisp
(websocket-kit:websocket-accept-key "dGhlIHNhbXBsZSBub25jZQ==")
;; => "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

(let* ((frame (websocket-kit:make-websocket-frame
               :opcode 1
               :payload (map '(vector (unsigned-byte 8)) #'char-code "Hi")))
       (wire (websocket-kit:serialize-websocket-frame frame)))
  (websocket-kit:websocket-frame-payload
   (websocket-kit:parse-websocket-frame wire)))
;; => #(72 105)
```

## The handshake takes a sender, not a dependency

`websocket-client-handshake` performs no I/O of its own. It builds and
validates, and calls a function you supply to carry out the HTTP/1.1 exchange:

```lisp
(websocket-kit:websocket-client-handshake
 stream request
 (lambda (request stream &rest options)
   (apply #'your-http1-send request stream options)))
```

The function receives the request and stream plus `:timeout`, `:deadline`,
`:max-header-bytes`, `:max-body-bytes`, `:collect-body-p` and
`:clock-function`, and must return the response and, as a second value,
whether the connection is reusable.

For the complete built-in client path, `connect-websocket` combines TCP,
optional HTTP CONNECT or SOCKS5 proxying, TLS, the HTTP/1.1 Upgrade exchange,
and the WebSocket connection object. The lower-level handshake remains
available when an application already owns its HTTP transport.

## Things the kit refuses to guess

A masking key is never generated implicitly. `make-websocket-frame` takes
`:mask-p t` together with an explicit `:masking-key`, so the randomness policy
is stated at the client boundary rather than buried in a library default.

`make-websocket-upgrade-request` likewise requires `:key`, the Base64
`Sec-WebSocket-Key`, for the same reason.

WebSocket URI strings using `ws` or `wss` are accepted by
`make-websocket-upgrade-request` and mapped to the underlying HTTP model as
`http` or `https`. HTTP URI values can also be supplied directly.

The server-side request predicate enforces the HTTP Upgrade invariants that
belong to this layer: `GET` over HTTP/1.1, exactly one valid `Host`, upgrade
and connection tokens, version 13, a valid key, no request body or trailers,
and syntactically valid protocol and extension fields. Origin authorization
is policy-controlled: an
`origin-policy` function can authorize the Origin header;
`make-websocket-origin-policy` builds a strict exact-match allowlist predicate
for browser-facing listeners. The response builder and client validator only
accept protocols and extension names that were offered by the peer.

Text messages and close reasons are validated as UTF-8. Peer-originated
invalid UTF-8 is signaled as `websocket-invalid-data`; size violations use
`websocket-size-limit-exceeded`. The default frame and message limit is 16
MiB, and all message/session readers expose explicit limits.

Extension negotiation is intentionally transport-agnostic: the handshake
tracks the exact extension names and parameters offered and selected. By
default, every selected extension parameter must exactly match the offer. The
optional `:extension-selection-policy` receives the serialized selected and
offered extension values so an application can implement role-aware parameter
negotiation; it still cannot select an extension name that was not offered. The
core provides generic payload transformation hooks and bundles a
pure-Lisp `permessage-deflate` codec. Frame values preserve
`:reserved-bits`; parsers and readers reject RSV bits by default and accept an
explicit `:allowed-reserved-bits` mask after negotiation. The application
still owns extension negotiation and selection policy, per-connection codec
state, per-frame validity rules, and decompression limits.
The native client and listener paths reject a selected permessage-deflate
extension before data transfer unless both payload transformers and RSV1 are
provided; they do not silently treat compressed payloads as plain text.

Message readers cap data fragments and control frames by default. A session
can additionally set `:max-frames` for a connection-wide frame budget; leave
it `NIL` for a deliberately long-lived connection whose application owns that
policy.

The HTTP layer enforces strict CRLF framing, token and field-value validation,
request-target validation, duplicate `Content-Length` consistency, supported
`Transfer-Encoding`, status-specific no-body rules, chunked trailers, body and
header limits, request deadlines, idle timeouts, and keep-alive reuse rules.
The HTTP/1.1 WebSocket framing path currently accepts a single `chunked`
`Transfer-Encoding` coding; HTTP/2 and HTTP/3 framing is exposed by the
transport-agnostic APIs below.
`serve-http-connection` handles multiple requests on one stream and closes at
the configured request limit.

The network layer supplies `connect-websocket`, `open-websocket-listener`,
`accept-websocket-connection`, and `serve-websocket-listener`. Listeners track
active and total connections, enforce concurrent connection limits, wake
blocked accept/worker operations during shutdown, and expose worker and
heartbeat/idle-timeout controls through the connection/session APIs.
HTTP/1.1 upgrade acceptance uses finite defaults for
`+websocket-default-handshake-timeout+`, header bytes, header fields, and
body bytes; `serve-websocket-listener` also applies the default WebSocket
message, payload, fragment, and control-frame limits. Explicit `NIL` can
disable the HTTP/1.1 timeout or boundary for a low-level caller, while
session message limits must be positive integers when overridden.

The built-in request, response, and network path is HTTP/1.1. The kit also
provides transport-agnostic HTTP/2 and HTTP/3 extended CONNECT header, frame,
and SETTINGS codecs, including stateful HPACK/QPACK handling and HTTP/2
continuation fragmentation. Message bridge APIs carry RFC 6455 text/binary
frames through HTTP/2 or HTTP/3 DATA frames and reconstruct them. The
HTTP/2/3 connection API manages protocol prefaces, SETTINGS, stream IDs,
header blocks, GOAWAY, flow-control windows, and HTTP/3 control/QPACK stream
routing over caller-supplied transport callbacks. The native
`connect-websocket` and listener APIs remain HTTP/1.1; they do not perform
HTTP/2 or HTTP/3 ALPN negotiation. The HTTP/2 HPACK encoder and decoder accept
caller-managed dynamic-table contexts and optional Huffman coding; HTTP/3
connection state maintains QPACK encoder/decoder tables and processes their
unidirectional streams. These APIs do not open QUIC or provide DNS, TLS/ALPN,
or an HTTP/2/3 event loop: applications must provide the negotiated
transport, stream scheduling, flow control, and connection shutdown policy.
For an established stream, `make-websocket-http2-session` and
`make-websocket-http3-session` provide stateful incremental receive/send,
message-size and DATA-frame limits, automatic Ping/Pong handling, Close
echoing, and clean stream end tracking. Their callbacks own the underlying
HTTP/2 or QUIC I/O, flow control, scheduling, and transport shutdown;
write callbacks must accept each complete frame batch before returning and may
return `NIL`, `T`, or the accepted byte count; partial acceptance is reported
as a transport error. Session protocol and transport failures are terminal;
`websocket-http2-3-session-abort` is available when the application must abort
that transport without sending a WebSocket Close frame. Session `close` writes
the WebSocket Close frame and local stream end but does not wait for the peer's
Close frame; applications that need a drain phase must keep that policy in the
transport callback and use `abort` after the policy completes. Session payload
encoders run before fragmentation and decoders run before message assembly;
both results are checked against the configured message limit. A decoder must
enforce any temporary-allocation or compression ratio limit before producing
an unbounded result.
Session and connection `:timeout` values are relative to `:clock-function`,
`:deadline` values are absolute clock values, and the earlier effective
deadline wins. When one is available, it is passed to read and write
transport callbacks as `:deadline`; calls without a deadline retain the
legacy callback shape.
WebSocket extension payload transformations are integrated through
`PAYLOAD-ENCODER`, `PAYLOAD-DECODER`, and RSV options on frame, message,
connection, and session APIs. The bundled permessage-deflate codec can be used
as the concrete codec, but negotiation/selection policy and the per-connection
state choice remain application-controlled; validate its RSV/message semantics
before enabling the matching RSV bit.

## API

| Group | Operations |
| --- | --- |
| Frames | `make-websocket-frame`, `serialize-websocket-frame`, `parse-websocket-frame`, `read-websocket-frame`, `write-websocket-frame`, and the `websocket-frame-*` accessors |
| Messages | `read-websocket-message`, `write-websocket-message`, `websocket-ping`, `websocket-pong`, `websocket-close`, `serve-websocket-session` |
| HTTP/1.1 | `serialize-http-request`, `serialize-http-response`, `parse-http-request`, `parse-http-response`, `read-http-request`, `read-http-response`, `serve-http-connection`, `perform-http-request` |
| HTTP/2/3 | `make-websocket-http2-connect-headers`, `encode-websocket-http2-headers-frames`, `encode-websocket-http2-data-frames`, `encode-websocket-http2-message-data-frames`, `decode-websocket-http2-websocket-data-frames`, `make-websocket-http3-connect-headers`, `encode-websocket-http3-headers-frame`, `encode-websocket-http3-data-frames`, `encode-websocket-http3-message-data-frames`, `decode-websocket-http3-websocket-data-frames`, the matching decode/settings functions, `make-websocket-http2-connection`, `make-websocket-http3-connection`, connection start/pump/feed/stream/window/close/abort operations, QPACK instruction operations, `make-websocket-http2-session`, `make-websocket-http3-session`, and the session send/receive/close/abort operations |
| Handshake | `websocket-accept-key`, `make-websocket-upgrade-request`, `make-websocket-origin-policy`, `websocket-upgrade-request-p`, `websocket-upgrade-response`, `websocket-client-handshake` |
| Network | `connect-websocket`, `open-websocket-client`, `open-websocket-listener`, `accept-websocket-connection`, `serve-websocket-listener`, `close-websocket-connection`, `close-websocket-listener` |
| Proxy/TLS | `make-http-connect-proxy`, `make-socks5-proxy`, `make-websocket-tls-upgrader`, `make-websocket-tls-server-wrapper` |
| Close payloads | `websocket-valid-close-code-p`, `make-websocket-close-payload`, `parse-websocket-close-payload` |
| Conditions | `websocket-error`, `websocket-http-error`, `websocket-timeout`, `websocket-transport-error`, `websocket-size-limit-exceeded`, `websocket-invalid-data` |

`websocket-size-limit-exceeded` and `websocket-invalid-data` are subtypes of
`websocket-error`, so a session mapping conditions to close codes can match
the specific ones first: a budget breach closes with 1009, invalid UTF-8 with
1007, and any other protocol fault with 1002.

## License

MIT. See [LICENSE](LICENSE).
