# Changelog

## 0.2.0

- WebSocket client TCP, proxy, and TLS transport now use `cl-http-kit` v0.5.0.
  `make-websocket-tls-upgrader` and `connect-websocket` accept
  `:tls-trust-anchors` for private CA verification.
- HTTP/2 HPACK and HTTP/3 QPACK operations use `cl-http-message-kit`'s public APIs.
- WSS listeners delegate TLS 1.3 handling to `cl-http-kit` with session tickets
  disabled. Peer `close_notify` closes the TCP transport, and oversized TLS
  record errors retain the peer-declared record length.
- The public TLS server wrapper cannot configure an aggregate certificate-chain
  size limit or a 16-certificate count limit. The X.509 parser limits each
  certificate to 1 MiB.
