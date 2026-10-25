# Changelog

## Unreleased

- WebSocket client TCP, proxy, and TLS transport now use cl-http-kit. `make-websocket-tls-upgrader` and `connect-websocket` accept `:tls-trust-anchors` for private CA verification.
- The TLS server closes its TCP transport after peer `close_notify`, and oversized TLS record errors retain the peer-declared record length.
