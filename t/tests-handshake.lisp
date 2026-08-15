(in-package #:websocket-kit/test)

(describe "websocket-accept-key"
  ;; RFC 6455 section 1.3 worked example.
  (it "reproduces the RFC 6455 worked example"
    (expect (websocket-accept-key +sample-key+)
            :to-equalp "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")))

(describe "make-websocket-upgrade-request"
  (it "builds a GET request carrying the upgrade header"
    (let ((request (upgrade-request)))
      (expect (http-request-method request) :to-equalp "GET")
      (expect (http-header-values (http-request-headers request) "upgrade")
              :to-equalp (list "websocket"))))

  (it "recognises its own output as an upgrade request"
    (expect (and (websocket-upgrade-request-p (upgrade-request)) t)
            :to-equalp t))

  (it "does not mistake an ordinary request for an upgrade"
    (expect (and (websocket-upgrade-request-p
                  (make-http-request
                   :method "GET"
                   :uri (parse-http-uri "http://example.test/")))
                 t)
            :to-equalp nil))

  ;; Key generation belongs to the application's random source, so the kit
  ;; refuses to invent one rather than reaching for a weak default.
  (it "requires the caller to supply the Sec-WebSocket-Key"
    (signals websocket-error
      (make-websocket-upgrade-request "http://example.test/socket"))))

(describe "websocket-client-handshake"
  ;; The exchange is performed by a function the caller passes in, which is
  ;; what lets this kit ship without an HTTP/1.1 implementation.
  (it "requires a request-sending function"
    (signals websocket-error
      (websocket-client-handshake (make-string-input-stream "")
                                  (upgrade-request)
                                  :not-a-function)))

  (it "accepts a valid 101 response obtained through the injected sender"
    (let ((response
            (websocket-client-handshake
             (make-string-input-stream "")
             (upgrade-request)
             (lambda (request stream &rest ignored)
               (declare (ignore stream ignored))
               (values
                (make-http-response
                 :status 101
                 :headers
                 (list (make-http-header "Upgrade" "websocket")
                       (make-http-header "Connection" "Upgrade")
                       (make-http-header
                        "Sec-WebSocket-Accept"
                        (websocket-accept-key
                         (http-header-value (http-request-headers request)
                                            "sec-websocket-key")))))
                nil)))))
      (expect (http-response-status response) :to-equalp 101))))
