(defpackage #:websocket-kit/test
  (:use #:cl #:websocket-kit #:http-message-kit)
  (:shadowing-import-from #:cl-weave
                          #:describe)
  (:import-from #:cl-weave
                #:expect
                #:it
                #:run-all
                #:signals)
  (:export #:run-tests))

(in-package #:websocket-kit/test)

(defun octets (&rest values)
  (make-array (length values)
              :element-type '(unsigned-byte 8)
              :initial-contents values))

;; The Sec-WebSocket-Key from the RFC 6455 section 1.3 worked example. Real
;; clients must generate this from a cryptographically secure source; the kit
;; deliberately refuses to invent one.
(defparameter +sample-key+ "dGhlIHNhbXBsZSBub25jZQ==")

(defun upgrade-request (&optional (uri "http://example.test/socket"))
  (make-websocket-upgrade-request uri :key +sample-key+))
