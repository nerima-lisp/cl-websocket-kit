(in-package #:websocket-kit/test)

(describe "websocket-accept-key"
  ;; RFC 6455 section 1.3 worked example.
  (it "reproduces the RFC 6455 worked example"
    (expect (websocket-accept-key +sample-key+)
            :to-equalp "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")))

  (it "rejects an oversized key before decoding it"
    (signals websocket-error
      (websocket-accept-key (make-string 100000 :initial-element #\A))))
(describe "make-websocket-upgrade-request"
  (it "builds a GET request carrying the upgrade header"
    (let ((request (upgrade-request)))
      (expect (http-request-method request) :to-equalp "GET")
      (expect (http-header-values (http-request-headers request) "upgrade")
              :to-equalp (list "websocket"))))

  (it "maps WebSocket URI schemes into the HTTP URI model"
    (let ((request (upgrade-request "wss://example.test/socket")))
      (expect (http-uri-scheme (http-request-uri request))
              :to-equalp "https")
      (expect (http-header-value (http-request-headers request) "host")
              :to-equalp "example.test")))

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

  (it "rejects bodies, trailers, and duplicate Host headers"
    (let* ((request (upgrade-request))
           (uri (http-request-uri request))
           (headers (http-request-headers request)))
      (expect (and (websocket-upgrade-request-p
                    (make-http-request :method "GET" :uri uri
                                       :headers headers
                                       :body (octets 1)))
                   t)
              :to-equalp nil)
      (expect (and (websocket-upgrade-request-p
                    (make-http-request
                     :method "GET" :uri uri :headers headers
                     :trailers (list (make-http-header "X-Trailer" "value"))))
                   t)
              :to-equalp nil)
      (expect (and (websocket-upgrade-request-p
                    (make-http-request
                     :method "GET" :uri uri
                     :headers (append headers
                                      (list (make-http-header
                                             "Host" "other.example")))))
                   t)
              :to-equalp nil)))

  (it "rejects malformed Host authorities"
    (let* ((request (upgrade-request))
           (uri (http-request-uri request))
           (headers (http-request-headers request)))
      (dolist (host '("example.test:65536"
                      "example.test/other"
                      "[::1"
                      "[1:2:3:4:5:6:7]"
                      "[1:2:3:4:5:6:7:8:9]"
                      "[1:2:3:4:5:6:7:192.0.2.1]"
                      "[1::2::3]"
                      "[:::]"
                      "[::ffff:192.0.2.999]"))
        (expect (and (websocket-upgrade-request-p
                      (make-http-request
                       :method "GET"
                       :uri uri
                       :headers
                       (append
                        (remove-if
                         (lambda (header)
                           (string-equal (http-header-name header) "host"))
                         headers)
                        (list (make-http-header "Host" host)))))
                   t)
                :to-equalp nil))))

  (it "accepts valid IPv6 and IPvFuture Host authorities"
    (let* ((request (upgrade-request))
           (uri (http-request-uri request))
           (headers (http-request-headers request)))
      (dolist (host '("[::]"
                      "[::1]"
                      "[2001:db8::1]"
                      "[::ffff:192.0.2.1]"
                      "[1:2:3:4:5:6:192.0.2.1]"
                      "[1:2:3:4:5:6:7:8]"
                      "[v1.fe80]"))
        (expect (and (websocket-upgrade-request-p
                      (make-http-request
                       :method "GET"
                       :uri uri
                       :headers
                       (append
                        (remove-if
                         (lambda (header)
                           (string-equal (http-header-name header) "host"))
                         headers)
                        (list (make-http-header "Host" host)))))
                     t)
                :to-equalp t))))

  (it "delegates Origin authorization to the configured policy"
    (let* ((request (upgrade-request))
           (request (make-http-request
                     :method "GET"
                     :uri (http-request-uri request)
                     :headers (append
                               (http-request-headers request)
                               (list (make-http-header
                                      "Origin" "https://app.example"))))))
      (expect (and (websocket-upgrade-request-p
                    request
                    :origin-policy
                    (lambda (origin ignored-request)
                      (declare (ignore ignored-request))
                      (string= origin "https://app.example")))
                   t)
              :to-equalp t)
      (expect (and (websocket-upgrade-request-p
                    request
                    :origin-policy
                    (lambda (origin ignored-request)
                      (declare (ignore origin ignored-request))
                      nil))
                   t)
              :to-equalp nil)))

  (it "creates an exact-match Origin allowlist policy"
    (let ((policy (make-websocket-origin-policy
                   '("https://app.example" "https://admin.example"))))
      (expect (funcall policy "https://app.example" nil)
              :to-equalp
              t)
      (expect (funcall policy "https://evil.example" nil)
              :to-equalp
              nil)
      (expect (funcall policy nil nil)
              :to-equalp
              nil)
      (expect (funcall (make-websocket-origin-policy
                        "https://app.example"
                        :require-origin-p nil)
                       nil
                       nil)
              :to-equalp
              t)))

  ;; Key generation belongs to the application's random source, so the kit
  ;; refuses to invent one rather than reaching for a weak default.
  (it "requires the caller to supply the Sec-WebSocket-Key"
    (signals websocket-error
      (make-websocket-upgrade-request "http://example.test/socket")))

  (it "rejects invalid quoted extension parameter bytes"
    (signals websocket-error
      (make-websocket-upgrade-request
       "http://example.test/socket"
       :key +sample-key+
       :extensions
       (concatenate 'string "x; p=\"bad"
                    (string (code-char 0))
                    "\""))))
  )

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
               (declare (ignore request stream ignored))
               (values
                (make-http-response
                  :status 101
                  :headers
                  (list (make-http-header "Upgrade" "websocket")
                        (make-http-header "Connection" "Upgrade")
                        (make-http-header
                         "Sec-WebSocket-Accept"
                         "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")))
                nil)))))
      (expect (http-response-status response) :to-equalp 101))))

  (it "forwards client response limits to the HTTP exchange"
    (let (options)
      (websocket-client-handshake
       (make-string-input-stream "")
       (upgrade-request)
       (lambda (request stream &rest received-options)
         (declare (ignore request stream))
         (setf options received-options)
         (values
          (make-http-response
           :status 101
           :headers
           (list (make-http-header "Upgrade" "websocket")
                 (make-http-header "Connection" "Upgrade")
                 (make-http-header
                  "Sec-WebSocket-Accept"
                  "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")))
          nil))
       :max-fields 17)
      (expect (getf options :max-fields) :to-equalp 17)))

  (it "rejects HTTP body framing headers on the 101 response"
    (dolist (header-name '("Content-Length" "Transfer-Encoding"))
      (signals websocket-protocol-error
        (websocket-client-handshake
         (make-string-input-stream "")
         (upgrade-request)
         (lambda (request stream &rest ignored)
           (declare (ignore request stream ignored))
           (values
            (make-http-response
             :status 101
             :headers
             (list (make-http-header "Upgrade" "websocket")
                   (make-http-header "Connection" "Upgrade")
                   (make-http-header
                    "Sec-WebSocket-Accept"
                    "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                   (make-http-header header-name "0")))
            nil))))))

  (it "rejects a response that is not a 101 upgrade"
    (signals websocket-protocol-error
      (websocket-client-handshake
       (make-string-input-stream "")
       (upgrade-request)
       (lambda (request stream &rest ignored)
         (declare (ignore request stream ignored))
         (values (make-http-response :status 200) nil)))))

  (it "rejects a response with a mismatched Sec-WebSocket-Accept"
    (signals websocket-protocol-error
      (websocket-client-handshake
       (make-string-input-stream "")
       (upgrade-request)
       (lambda (request stream &rest ignored)
         (declare (ignore request stream ignored))
         (values
          (make-http-response
           :status 101
           :headers
           (list (make-http-header "Upgrade" "websocket")
                 (make-http-header "Connection" "Upgrade")
                 (make-http-header "Sec-WebSocket-Accept" "wrong")))
          nil)))))

  (it "delegates client extension parameter negotiation to a policy"
    (let ((response
            (websocket-client-handshake
             (make-string-input-stream "")
             (make-websocket-upgrade-request
              "http://example.test/socket"
              :key +sample-key+
              :extensions "permessage-deflate; client_max_window_bits")
             (lambda (request stream &rest ignored)
               (declare (ignore request stream ignored))
               (values
                (make-http-response
                 :status 101
                 :headers
                 (list (make-http-header "Upgrade" "websocket")
                       (make-http-header "Connection" "Upgrade")
                       (make-http-header
                        "Sec-WebSocket-Accept"
                        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
                       (make-http-header
                        "Sec-WebSocket-Extensions"
                        "permessage-deflate")))
                nil))
             :extension-selection-policy
             (lambda (selected offered)
               (and (string= selected "permessage-deflate")
                    (string= offered
                             "permessage-deflate; client_max_window_bits"))))))
      (expect (http-response-status response) :to-equalp 101)))

(describe "websocket-upgrade-response"
  (it "returns only offered protocol and extension selections"
    (let* ((request (make-websocket-upgrade-request
                     "http://example.test/socket"
                     :key +sample-key+
                     :protocols '("chat")
                     :extensions "permessage-deflate"))
           (response (websocket-upgrade-response
                      request
                      :protocol "chat"
                      :extensions "permessage-deflate")))
      (expect (http-response-status response) :to-equalp 101)
      (expect (http-header-value (http-response-headers response)
                                 "sec-websocket-protocol")
              :to-equalp "chat")
      (expect (http-header-value (http-response-headers response)
                                 "sec-websocket-extensions")
              :to-equalp "permessage-deflate")))

  (it "rejects an unoffered subprotocol"
    (signals websocket-error
      (websocket-upgrade-response
       (upgrade-request)
       :protocol "chat")))

  (it "rejects an extension parameter that was not offered"
    (signals websocket-error
      (websocket-upgrade-response
       (make-websocket-upgrade-request
        "http://example.test/socket"
        :key +sample-key+
        :extensions "permessage-deflate")
       :extensions "permessage-deflate; server_no_context_takeover"))))

  (it "delegates extension parameter negotiation to an explicit policy"
    (let* ((request (make-websocket-upgrade-request
                     "http://example.test/socket"
                     :key +sample-key+
                     :extensions "permessage-deflate"))
           (seen nil)
           (response
             (websocket-upgrade-response
              request
              :extensions "permessage-deflate; server_no_context_takeover"
              :extension-selection-policy
              (lambda (selected offered)
                (setf seen (list selected offered))
                t))))
      (expect (http-response-status response) :to-equalp 101)
      (expect seen :to-equalp
              '("permessage-deflate; server_no_context_takeover"
                "permessage-deflate"))))

  (it "still rejects an unoffered extension name with a policy"
    (signals websocket-error
      (websocket-upgrade-response
       (upgrade-request)
       :extensions "x-example"
       :extension-selection-policy
       (lambda (selected offered)
         (declare (ignore selected offered))
         t))))

(describe "websocket-network-selection"
  (it "requires a selected protocol to be offered by the client"
    (let ((request
            (make-websocket-upgrade-request
             "http://example.test/socket"
             :key +sample-key+
             :protocols '("chat"))))
      (signals websocket-error
        (websocket-kit::%websocket-network-selection
         request
         '("superchat")
         nil
         nil
         (lambda (ignored-request)
           (declare (ignore ignored-request))
           "superchat")))))

  (it "accepts a protocol selected from both configured sets"
    (let* ((request
             (make-websocket-upgrade-request
              "http://example.test/socket"
              :key +sample-key+
              :protocols '("chat")))
           (selection
             (websocket-kit::%websocket-network-selection
              request
              '("chat" "superchat")
              nil
              nil
              (lambda (ignored-request)
                (declare (ignore ignored-request))
                "chat"))))
      (expect (getf selection :protocol) :to-equalp "chat"))))
