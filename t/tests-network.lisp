(in-package #:websocket-kit/test)

(describe "SOCKS5 address encoding"
  (it "encodes IPv4 literals with address type 1"
    (multiple-value-bind (address-type octets)
        (websocket-kit::%websocket-network-socks5-address "192.0.2.1")
      (expect address-type :to-equalp 1)
      (expect octets :to-equalp (octets 192 0 2 1))))

  (it "encodes compressed IPv6 literals with address type 4"
    (multiple-value-bind (address-type octets)
        (websocket-kit::%websocket-network-socks5-address "2001:db8::1")
      (expect address-type :to-equalp 4)
      (expect octets
              :to-equalp
              (octets #x20 #x01 #x0d #xb8
                      0 0 0 0 0 0 0 0 0 0 0 1)))
    (multiple-value-bind (address-type octets)
        (websocket-kit::%websocket-network-socks5-address
         "[::ffff:192.0.2.1]")
      (expect address-type :to-equalp 4)
      (expect octets
              :to-equalp
              (octets 0 0 0 0 0 0 0 0 0 0 #xff #xff 192 0 2 1))))

  (it "handles compression at either IPv6 boundary"
    (dolist (case (list
                   (list "::"
                         (octets 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0))
                   (list "::1"
                         (octets 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1))
                   (list "1::"
                         (octets 0 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0))))
      (destructuring-bind (host expected) case
        (multiple-value-bind (address-type actual)
            (websocket-kit::%websocket-network-socks5-address host)
          (expect address-type :to-equalp 4)
          (expect actual :to-equalp expected)))))

  (it "uses address type 3 for domain names"
    (multiple-value-bind (address-type octets)
        (websocket-kit::%websocket-network-socks5-address "example.test")
      (expect address-type :to-equalp 3)
      (expect octets :to-equalp (ascii-octets "example.test"))))

  (it "rejects malformed IPv6 literals"
    (signals websocket-protocol-error
      (websocket-kit::%websocket-network-socks5-address "2001:::1"))))

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
