# Changelog

## Unreleased

- WebSocket client TCP, proxy, and TLS transport now use cl-http-kit. `make-websocket-tls-upgrader` and `connect-websocket` accept `:tls-trust-anchors` for private CA verification.
