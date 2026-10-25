(in-package #:websocket-kit/test)

(describe "SOCKS5 credentials"
  (it "requires username and password together"
    (signals websocket-protocol-error
      (make-socks5-proxy :host "proxy.example" :username "user"))
    (signals websocket-protocol-error
      (make-socks5-proxy :host "proxy.example" :password "pass"))))

(describe "network host validation"
  (it "rejects C0 and DEL control characters"
    (dolist (character (list (code-char 0) (code-char #x1f) (code-char #x7f)))
      (signals websocket-protocol-error
        (websocket-kit::%websocket-network-validate-host
         (format nil "proxy~C.example" character))))
    (expect
     (websocket-kit::%websocket-network-validate-host "proxy.example")
     :to-equal
     "proxy.example")))

(describe "network informational response limit"
  (it "allows sixteen informational responses and rejects the seventeenth"
    (let ((request
            (make-http-request
             :method "GET"
             :uri "http://example.test/socket"
             :headers (list (make-http-header "Host" "example.test")))))
      (labels ((wire (count)
                 (apply #'concatenate
                        '(vector (unsigned-byte 8))
                        (append
                         (loop repeat count
                               collect (http-octets
                                        "HTTP/1.1 103 Early Hints"
                                        ""))
                         (list (http-octets
                                "HTTP/1.1 200 OK"
                                "Content-Length: 0"
                                "")))))
               (read-final (stream)
                 (websocket-kit::%websocket-network-read-final-http-response
                  stream
                  request
                  :max-header-bytes +websocket-default-max-header-bytes+
                  :max-fields +websocket-default-max-header-fields+
                  :max-body-bytes +websocket-default-max-body-bytes+
                  :clock-function (lambda () 1))))
        (multiple-value-bind (values output)
            (with-binary-two-way (wire 16) #'read-final)
          (declare (ignore output))
          (expect (http-response-status (first values)) :to-equalp 200)
          (expect (second values) :to-equalp (length (wire 16))))
        (signals websocket-http-error
          (with-binary-input (wire 17) #'read-final))))))

(describe "network client response field limit"
  (it "propagates the field budget to the final response reader"
    (let ((request
            (make-http-request
             :method "GET"
             :uri "http://example.test/socket"
             :headers (list (make-http-header "Host" "example.test")))))
      (flet ((read-final (stream)
               (websocket-kit::%websocket-network-read-final-http-response
                stream
                request
                :max-header-bytes +websocket-default-max-header-bytes+
                :max-fields 1
                :max-body-bytes +websocket-default-max-body-bytes+
                :clock-function (lambda () 1))))
        (signals websocket-size-limit-exceeded
          (with-binary-input
              (http-octets
               "HTTP/1.1 200 OK"
               "Host: example.test"
               "Content-Length: 0"
               "")
            #'read-final))))))

(describe "proxy TLS configuration"
  (it "stores a callable TLS upgrader"
    (let ((upgrader (lambda (stream uri &key &allow-other-keys)
                      (declare (ignore stream uri))
                      (values nil nil))))
      (dolist (proxy (list
                      (make-http-connect-proxy
                       :host "proxy.example"
                       :tls-upgrader upgrader)
                      (make-socks5-proxy
                       :host "proxy.example"
                       :tls-upgrader upgrader)))
        (expect (eq (websocket-proxy-tls-upgrader proxy) upgrader)
                :to-be
                t))))
  (it "rejects a non-callable TLS upgrader"
    (signals websocket-protocol-error
      (make-http-connect-proxy
       :host "proxy.example"
       :tls-upgrader :invalid))
    (signals websocket-protocol-error
      (make-socks5-proxy
       :host "proxy.example"
       :tls-upgrader :invalid))))

(describe "TLS ALPN validation"
  (it "accepts HTTP/1.1 and rejects other negotiated protocols"
    (expect
     (websocket-kit::%websocket-network-validate-tls-alpn-value
      "http/1.1")
     :to-equal
     "http/1.1")
    (expect
     (websocket-kit::%websocket-network-validate-tls-alpn-value nil)
     :to-be
     nil)
    (signals websocket-transport-error
      (websocket-kit::%websocket-network-validate-tls-alpn-value "h2"))))

(describe "listener safety defaults"
  (it "provides finite handshake and HTTP boundaries"
    (expect (plusp +websocket-default-handshake-timeout+) :to-be t)
    (expect (plusp +websocket-default-max-header-bytes+) :to-be t)
    (expect (plusp +websocket-default-max-header-fields+) :to-be t)
    (expect (plusp +websocket-default-max-body-bytes+) :to-be t)))

(describe "permessage-deflate extension safety"
  (it "rejects selection without a complete transformer"
    (signals websocket-protocol-error
      (websocket-kit::%websocket-network-validate-extension-transformer
       "permessage-deflate" nil nil #x40))
    (signals websocket-protocol-error
      (websocket-kit::%websocket-network-validate-extension-transformer
       "permessage-deflate"
       (lambda (&rest arguments)
         (declare (ignore arguments)))
       nil #x40))
    (signals websocket-protocol-error
      (websocket-kit::%websocket-network-validate-extension-transformer
       "permessage-deflate"
       (lambda (&rest arguments)
         (declare (ignore arguments)))
       (lambda (&rest arguments)
         (declare (ignore arguments)))
       0)))
  (it "accepts selection with both transformers and RSV1"
    (let ((encoder (lambda (&rest arguments)
                     (declare (ignore arguments))))
          (decoder (lambda (&rest arguments)
                     (declare (ignore arguments)))))
      (expect
       (websocket-kit::%websocket-network-validate-extension-transformer
        "permessage-deflate; client_no_context_takeover"
        encoder decoder #x40)
       :to-equal
       "permessage-deflate; client_no_context_takeover")))
  (it "does not impose PMD requirements on generic extensions"
    (expect
     (websocket-kit::%websocket-network-validate-extension-transformer
      "x-example" nil nil 0)
     :to-equal
     "x-example")))

(describe "permessage-deflate frame semantics"
  (it "allows RSV1 only on the first data frame"
    (let ((decoder (lambda (&rest arguments)
                     (declare (ignore arguments)))))
      (signals websocket-protocol-error
        (funcall
         (websocket-kit::%websocket-network-permessage-deflate-frame-validator
          "permessage-deflate" nil)
         (make-websocket-frame :fin-p t
                               :opcode 1
                               :reserved-bits #x40
                               :payload (octets 1))))
      (let ((validator
              (websocket-kit::%websocket-network-permessage-deflate-frame-validator
               "permessage-deflate" decoder)))
        (funcall validator
                 (make-websocket-frame :fin-p nil
                                       :opcode 1
                                       :reserved-bits #x40
                                       :payload (octets 1)))
        (signals websocket-protocol-error
          (funcall validator
                   (make-websocket-frame :fin-p t
                                         :opcode 0
                                         :reserved-bits #x40
                                         :payload (octets 2))))
        (funcall validator
                 (make-websocket-frame :fin-p t
                                       :opcode 0
                                       :payload (octets 3)))
        (funcall validator
                 (make-websocket-frame :fin-p t
                                       :opcode 2
                                       :reserved-bits #x40
                                       :payload (octets 4))))))
  (it "rejects RSV1 on control frames"
    (let ((validator
            (websocket-kit::%websocket-network-permessage-deflate-frame-validator
             "permessage-deflate"
             (lambda (&rest arguments)
               (declare (ignore arguments))))))
      (signals websocket-protocol-error
        (funcall validator
                 (make-websocket-frame :fin-p t
                                       :opcode 9
                                       :reserved-bits #x40
                                       :payload (octets 1)))))))

(describe "network receive callbacks"
  (it "runs control callbacks after releasing the receive lock"
    (let ((wire
            (concatenate
             '(vector (unsigned-byte 8))
             (serialize-websocket-frame
              (make-websocket-frame :opcode 9 :payload (octets 1)))
             (serialize-websocket-frame
              (make-websocket-frame :opcode 1 :payload (octets 65)))
             (serialize-websocket-frame
              (make-websocket-frame :opcode 1 :payload (octets 66))))))
      (multiple-value-bind (ignored output)
          (with-binary-two-way
           wire
           (lambda (stream)
             (let ((connection
                     (websocket-kit::%make-websocket-connection
                      stream nil nil nil nil nil nil nil nil nil nil 0))
                   (nested-result nil)
                   (control-opcodes nil))
               (multiple-value-bind (payload opcode)
                   (websocket-receive
                    connection
                    :on-control
                    (lambda (frame)
                      (push (websocket-frame-opcode frame) control-opcodes)
                      (setf nested-result
                            (multiple-value-list
                             (websocket-receive connection)))))
                 (expect payload :to-equalp (octets 65))
                 (expect opcode :to-equalp 1))
               (expect control-opcodes :to-equalp (list 9))
               (expect nested-result
                       :to-equalp
                       (list (octets 66) 1)))))
        (declare (ignore ignored))
        (let ((pong (parse-websocket-frame output)))
          (expect (websocket-frame-opcode pong) :to-equalp 10)
          (expect (websocket-frame-payload pong) :to-equalp (octets 1)))))))
#+sbcl
(progn
  (defun %network-test-read-http-line (stream)
    (with-output-to-string (line)
      (loop for octet = (read-byte stream nil nil)
            do (unless octet
                 (error "The test proxy stream ended during an HTTP line."))
               (if (= octet 13)
                   (progn
                     (unless (= (read-byte stream nil nil) 10)
                       (error "The test proxy received a malformed HTTP line."))
                     (return))
                   (write-char (code-char octet) line)))))

  (defun %network-test-read-http-headers (stream)
    (loop for line = (%network-test-read-http-line stream)
          until (string= line "")
          collect line))

  (defun %network-test-write-http-lines (stream &rest lines)
    (write-sequence (apply #'http-octets lines) stream)
    (finish-output stream))

  (defun %network-test-http-connect (uri &key tls-upgrader)
    (let* ((listener
             (http-kit/network:open-http-tcp-listener
              :host "127.0.0.1" :port 0))
           (proxy-port (http-kit/network:http-network-listener-port listener))
           (request-lines nil)
           (server-condition nil)
           (server-thread nil)
           (thread-joined-p nil)
           (connection nil))
      (unwind-protect
           (progn
             (setf server-thread
                   (sb-thread:make-thread
                    (lambda ()
                      (handler-case
                          (multiple-value-bind (stream peer-address peer-port)
                              (http-kit/network:accept-http-tcp-stream
                               listener :timeout 5)
                            (declare (ignore peer-address peer-port))
                            (unwind-protect
                                 (let ((connect-line
                                         (%network-test-read-http-line stream)))
                                   (%network-test-read-http-headers stream)
                                   (%network-test-write-http-lines
                                    stream
                                    "HTTP/1.1 200 Connection Established"
                                    "")
                                   (let ((request-line
                                           (%network-test-read-http-line stream)))
                                     (%network-test-read-http-headers stream)
                                     (%network-test-write-http-lines
                                      stream
                                      "HTTP/1.1 101 Switching Protocols"
                                      "Upgrade: websocket"
                                      "Connection: Upgrade"
                                      "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
                                      "")
                                     (setf request-lines
                                           (list connect-line request-line))))
                              (http-kit/network:close-http-tcp-stream stream)))
                        (error (condition)
                          (setf server-condition condition))))))
             (setf connection
                   (connect-websocket
                    uri
                    :key +sample-key+
                    :timeout 5
                    :proxy (make-http-connect-proxy
                            :host "127.0.0.1" :port proxy-port)
                    :tls-upgrader tls-upgrader))
             (close-websocket-connection connection :send-close-p nil)
             (setf connection nil)
             (sb-thread:join-thread server-thread)
             (setf thread-joined-p t)
             (values request-lines server-condition))
        (when connection
          (close-websocket-connection connection :send-close-p nil))
        (when (and server-thread (not thread-joined-p))
          (sb-thread:join-thread server-thread))
        (http-kit/network:close-http-tcp-listener listener))))

  (defun %wss-e2e-certificate-paths ()
    (let ((stem (format nil "cl-websocket-kit-wss-~A" (gensym))))
      (values
       (namestring
        (merge-pathnames (format nil "~A.crt" stem)
                         (uiop:temporary-directory)))
       (namestring
        (merge-pathnames (format nil "~A.key" stem)
                         (uiop:temporary-directory))))))

  (defun %wss-e2e-generate-certificate (certificate key)
    (let ((openssl (or (uiop:getenv "OPENSSL") "openssl")))
      (uiop:run-program
       (list openssl "req" "-x509" "-newkey" "rsa:2048" "-nodes"
             "-days" "1" "-subj" "/CN=127.0.0.1"
             "-addext" "subjectAltName=IP:127.0.0.1"
             "-keyout" key "-out" certificate)
       :output :string
       :error-output :string)
      certificate))

  (defun %wss-e2e-trust-anchor (certificate)
    (cl-tls-kit.x509:parse-certificate-der
     (cl-tls-kit:pem-block-der
      (first (cl-tls-kit:pem-decode
              (uiop:read-file-string certificate))))))

  (defun %wss-e2e-start-socat (tls-port certificate key plain-port)
    (let ((socat (or (uiop:getenv "SOCAT") "socat")))
      (uiop:launch-program
       (list socat
             (format nil
                     "OPENSSL-LISTEN:~D,bind=127.0.0.1,cert=~A,key=~A,verify=0,reuseaddr,fork"
                     tls-port certificate key)
             (format nil "TCP:127.0.0.1:~D" plain-port))
       :input nil
       :output *standard-output*
       :error-output *error-output*
       :wait nil)))

  (defun %wss-e2e-serve-plain (listener received received-masks)
    (handler-case
        (let ((accepted
                (accept-websocket-connection
                 listener
                 :acceptor
                 (lambda (request)
                   (declare (ignore request))
                   t)
                 :timeout 10)))
          (unless accepted
            (error "The WSS E2E server rejected its client."))
          (unwind-protect
               (loop
                 for frame =
                   (read-websocket-frame
                    (websocket-connection-stream accepted)
                    :require-mask-p nil
                    :allow-unmasked-p t)
                 do (progn
                      (push (websocket-frame-mask-p frame) received-masks)
                      (case (websocket-frame-opcode frame)
                        ((1 2)
                         (push (list
                                (websocket-frame-payload frame)
                                (websocket-frame-opcode frame))
                               received)
                         (websocket-send
                          accepted
                          (websocket-frame-payload frame)
                          :opcode
                          (websocket-frame-opcode frame))
                         (return))
                        (9
                         (websocket-pong
                          (websocket-connection-stream accepted)
                          :payload
                          (websocket-frame-payload frame)))
                        (8
                         (websocket-close
                          (websocket-connection-stream accepted)
                          :payload
                          (websocket-frame-payload frame))
                         (return)))))
            (close-websocket-connection accepted :send-close-p nil))
          (values nil received received-masks))
      (error (condition)
        (values condition nil nil))))

  (describe "WSS client TLS transport"
    (it "verifies a private trust anchor and completes an HTTP Upgrade and payload round-trip"
      (multiple-value-bind (certificate key)
          (%wss-e2e-certificate-paths)
        (let ((plain-listener nil)
              (tls-port-listener nil)
              (tls-port nil)
              (socat-process nil)
              (server-thread nil)
              (server-result nil)
              (received nil)
              (received-masks nil)
              (connection nil))
          (unwind-protect
               (progn
                 (%wss-e2e-generate-certificate certificate key)
                 (setf plain-listener
                       (open-websocket-listener :host "127.0.0.1" :port 0))
                 (setf tls-port-listener
                       (open-websocket-listener :host "127.0.0.1" :port 0))
                 (let ((plain-port (websocket-listener-port plain-listener))
                       (trust-anchor (%wss-e2e-trust-anchor certificate)))
                   (setf tls-port (websocket-listener-port tls-port-listener))
                   (close-websocket-listener tls-port-listener)
                   (setf tls-port-listener nil)
                   (setf server-thread
                         (sb-thread:make-thread
                          (lambda ()
                            (setf server-result
                                  (multiple-value-list
                                   (%wss-e2e-serve-plain
                                    plain-listener received received-masks))))))
                   (setf socat-process
                         (%wss-e2e-start-socat
                          tls-port certificate key plain-port))
                   (sleep 1)
                   (setf connection
                         (connect-websocket
                          (format nil "wss://127.0.0.1:~D/socket" tls-port)
                          :timeout 10
                          :local-mask-p t
                          :peer-mask-required-p nil
                          :tls-verify :required
                          :tls-trust-anchors (list trust-anchor)))
                   (let* ((request (websocket-connection-request connection))
                          (response (websocket-connection-response connection))
                          (request-key
                            (http-header-value
                             (http-request-headers request)
                             "Sec-WebSocket-Key")))
                     (expect (http-response-status response) :to-equalp 101)
                     (expect
                      (http-header-value
                       (http-response-headers response)
                       "Sec-WebSocket-Accept")
                      :to-equal
                      (websocket-accept-key request-key)))
                   (websocket-send connection "hello over wss" :opcode 1)
                   (multiple-value-bind (payload opcode)
                       (websocket-receive connection :timeout 10)
                     (expect payload :to-equalp (ascii-octets "hello over wss"))
                     (expect opcode :to-equalp 1))
                   (close-websocket-connection connection :send-close-p nil)
                   (setf connection nil)
                   (sb-thread:join-thread server-thread)
                   (setf server-thread nil)
                   (setf received (second server-result)
                         received-masks (third server-result))
                   (expect (first server-result) :to-be nil)
                   (expect received
                           :to-equalp
                           (list (list (ascii-octets "hello over wss") 1)))
                   (expect received-masks :to-equalp (list t)))
            (when connection
              (ignore-errors
                (close-websocket-connection connection :send-close-p nil)))
            (when server-thread
              (ignore-errors (close-websocket-listener plain-listener))
              (ignore-errors (sb-thread:join-thread server-thread)))
            (when plain-listener
              (ignore-errors (close-websocket-listener plain-listener)))
            (when tls-port-listener
              (ignore-errors (close-websocket-listener tls-port-listener)))
            (when socat-process
              (ignore-errors (uiop:terminate-process socat-process))
              (ignore-errors (uiop:wait-process socat-process)))
            (ignore-errors (delete-file certificate))
            (ignore-errors (delete-file key))))))))

  (describe "HTTP CONNECT proxy transport"
    (it "uses CONNECT for ws and preserves the explicit target port"
      (multiple-value-bind (request-lines server-condition)
          (%network-test-http-connect "ws://example.test:8080/socket")
        (expect server-condition :to-be nil)
        (expect (first request-lines)
                :to-equal
                "CONNECT example.test:8080 HTTP/1.1")
        (expect (second request-lines)
                :to-equal
                "GET /socket HTTP/1.1")))
    (it "uses CONNECT before origin TLS for wss"
      (let ((tls-uri nil))
        (multiple-value-bind (request-lines server-condition)
            (%network-test-http-connect
             "wss://example.test:8443/socket"
             :tls-upgrader
             (lambda (stream uri &key &allow-other-keys)
               (setf tls-uri uri)
               (values stream "http/1.1")))
          (expect server-condition :to-be nil)
          (expect (first request-lines)
                  :to-equal
                  "CONNECT example.test:8443 HTTP/1.1")
          (expect (second request-lines)
                  :to-equal
                  "GET /socket HTTP/1.1")
          (expect (http-uri-scheme tls-uri) :to-equal "https")
          (expect (http-uri-port tls-uri) :to-equalp 8443)))))

  (describe "unsupported HTTP transport options"
    (it "rejects custom CONNECT headers explicitly"
      (signals websocket-transport-error
        (connect-websocket
         "ws://example.test/socket"
         :proxy
         (make-http-connect-proxy
          :host "127.0.0.1"
          :headers (list (make-http-header "X-Proxy-Test" "value"))))))
    (it "rejects default TLS credentials, passwords, and unwrapping explicitly"
      (signals websocket-transport-error
        (connect-websocket
         "wss://example.test/socket"
         :key +sample-key+
         :tls-certificate "client-certificate"
         :tls-key "client-key"))
      (signals websocket-transport-error
        (connect-websocket
         "wss://example.test/socket"
         :key +sample-key+
         :tls-password "unused"))
      (signals websocket-transport-error
        (make-websocket-tls-upgrader :unwrap-stream-p t)))))
