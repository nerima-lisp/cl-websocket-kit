(in-package #:asdf-user)

(asdf:defsystem "cl-websocket-kit"
  :description "HTTP/1.1, HTTP/2, HTTP/3, and RFC 6455 WebSocket framing, transport, and sessions."
  :author "nerima-lisp"
  :license "MIT"
  :version "0.2.0"
  :depends-on ("cl-http-message-kit"
               "cl-crypto-kit"
               "cl-http-kit/http2"
               "cl-http-kit/http3"
               "cl-http-kit/tls")
  :pathname "src"
  :serial t
  :components ((:file "package")
               (:file "conditions")
               (:file "frame")
               (:file "support")
               (:file "permessage-deflate")
               (:file "http")
               (:file "http2-3")
               (:file "crypto")
               (:file "message")
               (:file "http2-3-websocket")
               (:file "http2-3-session")
               (:file "http2-3-connection")
               (:file "handshake")
               (:file "network"))
  :in-order-to ((test-op (test-op "cl-websocket-kit/test"))))

(asdf:defsystem "cl-websocket-kit/test"
  :description "Tests for cl-websocket-kit."
  :depends-on ("cl-websocket-kit" "cl-weave")
  :pathname "t"
  :serial t
  :components ((:file "package")
               (:file "tests-frame")
               (:file "tests-permessage-deflate")
               (:file "tests-http")
               (:file "tests-http2-3")
               (:file "tests-http2-3-session")
               (:file "tests-http2-3-connection")
               (:file "tests-network")
               (:file "tests-handshake")
               (:file "runner"))
  :perform (asdf:test-op (op c)
             (declare (ignore op c))
             (uiop:symbol-call "WEBSOCKET-KIT/TEST" "RUN-TESTS")))
