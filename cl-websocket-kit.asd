(in-package #:asdf-user)

(asdf:defsystem "cl-websocket-kit"
  :description "RFC 6455 WebSocket framing, handshake, and message assembly."
  :author "nerima-lisp"
  :license "MIT"
  :version "0.1.0"
  :depends-on ("cl-http-message-kit")
  :pathname "src"
  :serial t
  :components ((:file "package")
               (:file "conditions")
               (:file "frame")
               (:file "support")
               (:file "crypto")
               (:file "message")
               (:file "handshake"))
  :in-order-to ((test-op (test-op "cl-websocket-kit/test"))))

(asdf:defsystem "cl-websocket-kit/test"
  :description "Tests for cl-websocket-kit."
  :depends-on ("cl-websocket-kit" "cl-weave")
  :pathname "t"
  :serial t
  :components ((:file "package")
               (:file "tests-frame")
               (:file "tests-handshake")
               (:file "runner"))
  :perform (asdf:test-op (op c)
             (declare (ignore op c))
             (uiop:symbol-call "WEBSOCKET-KIT/TEST" "RUN-TESTS")))
