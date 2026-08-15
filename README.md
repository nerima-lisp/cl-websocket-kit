# cl-websocket-kit

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

cl-websocket-kit implements RFC 6455: frame encoding and decoding, masking,
close codes, message assembly across continuation frames, the accept-key
computation, and the client and server sides of the upgrade handshake.

It depends only on
[cl-http-message-kit](https://github.com/nerima-lisp/cl-http-message-kit),
for the request and response values the handshake is expressed in. It contains
no HTTP/1.1 implementation and opens no sockets.

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

This is what lets the kit ship without an HTTP/1.1 stack: you pair it with
whichever one you already have.

## Things the kit refuses to guess

A masking key is never generated implicitly. `make-websocket-frame` takes
`:mask-p t` together with an explicit `:masking-key`, so the randomness policy
is stated at the client boundary rather than buried in a library default.

`make-websocket-upgrade-request` likewise requires `:key`, the Base64
`Sec-WebSocket-Key`, for the same reason.

The handshake URI uses the `http` or `https` scheme, not `ws` or `wss`: the
handshake really is an HTTP request, and the WebSocket schemes are an
addressing convention that maps onto it.

## API

| Group | Operations |
| --- | --- |
| Frames | `make-websocket-frame`, `serialize-websocket-frame`, `parse-websocket-frame`, `read-websocket-frame`, `write-websocket-frame`, and the `websocket-frame-*` accessors |
| Messages | `read-websocket-message`, `write-websocket-message`, `websocket-ping`, `websocket-pong`, `websocket-close`, `serve-websocket-session` |
| Handshake | `websocket-accept-key`, `make-websocket-upgrade-request`, `websocket-upgrade-request-p`, `websocket-upgrade-response`, `websocket-client-handshake` |
| Close payloads | `websocket-valid-close-code-p`, `make-websocket-close-payload`, `parse-websocket-close-payload` |
| Conditions | `websocket-error`, `websocket-size-limit-exceeded` |

`websocket-size-limit-exceeded` is a subtype of `websocket-error`, so a
session mapping conditions to close codes can match the specific one first: a
budget breach closes with 1009, any other protocol fault with 1002.

## License

MIT. See [LICENSE](LICENSE).
