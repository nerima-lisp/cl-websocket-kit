(in-package #:websocket-kit/test)

#+sbcl
(progn
  (defun %tls-test-path (kind &optional (type "pem"))
    (merge-pathnames
     (format nil "cl-websocket-kit-tls-~A-~A.~A"
             (symbol-name (gensym)) kind type)
     (uiop:temporary-directory)))

  (defun %tls-test-run-openssl (&rest arguments)
    (multiple-value-bind (output error-output exit-code)
        (uiop:run-program
         (cons (or (uiop:getenv "OPENSSL") "openssl") arguments)
         :output :string :error-output :string :ignore-error-status t)
      (unless (zerop exit-code)
        (error "OpenSSL could not create TLS test credentials: ~A~%~A"
               output error-output))))

  (defun %tls-test-read-octets (path)
    (with-open-file (stream path :direction :input
                                 :element-type '(unsigned-byte 8))
      (let ((octets (make-array (file-length stream)
                                :element-type '(unsigned-byte 8))))
        (unless (= (read-sequence octets stream) (length octets))
          (error "OpenSSL returned a truncated TLS test key."))
        octets)))

  (defun %tls-test-with-certificate (function)
    (let ((certificate (%tls-test-path "certificate"))
          (key (%tls-test-path "key"))
          (key-der (%tls-test-path "key" "der")))
      (unwind-protect
           (progn
             (%tls-test-run-openssl
              "req" "-x509" "-newkey" "ec"
              "-pkeyopt" "ec_paramgen_curve:P-256" "-nodes"
              "-keyout" (namestring key) "-out" (namestring certificate)
              "-days" "1" "-subj" "/CN=localhost"
              "-addext" "subjectAltName=DNS:localhost,IP:127.0.0.1"
              "-addext" "basicConstraints=critical,CA:FALSE"
              "-addext" "keyUsage=critical,digitalSignature"
              "-addext" "extendedKeyUsage=serverAuth")
             (%tls-test-run-openssl
              "ec" "-in" (namestring key) "-outform" "DER"
              "-out" (namestring key-der))
             (let* ((pem-block
                      (first
                       (cl-tls-kit:pem-decode
                        (uiop:read-file-string certificate))))
                    (certificate-der (cl-tls-kit:pem-block-der pem-block))
                    (trust-anchor
                      (cl-tls-kit.x509:parse-certificate-der certificate-der))
                    (key-node (cl-tls-kit:der-decode
                               (%tls-test-read-octets key-der)))
                    (scalar-node
                      (second (cl-tls-kit:der-node-children key-node)))
                    (scalar (and scalar-node
                                 (= (cl-tls-kit:der-node-tag scalar-node) 4)
                                 (cl-tls-kit:der-node-value scalar-node)))
                    (crypto-package (find-package "CRYPTO-KIT"))
                    (constructor
                      (and crypto-package
                           (find-symbol "MAKE-EC-PRIVATE-KEY" crypto-package))))
               (unless (and (= (cl-tls-kit:der-node-tag key-node) 16)
                            scalar (= (length scalar) 32)
                            constructor (fboundp constructor))
                 (error "OpenSSL returned an invalid P-256 TLS test key."))
               (funcall function (list certificate-der)
                        (funcall constructor :p256 scalar) trust-anchor)))
        (dolist (path (list certificate key key-der))
          (when (probe-file path)
            (delete-file path))))))

  (defun %tls-test-client-driver (listener trust-anchor alpn &key ticket-store)
    (cl-tls-kit:make-tls13-client-driver-over-tcp
     "127.0.0.1" (websocket-listener-port listener)
     :provider (cl-tls-kit:make-cl-crypto-kit-provider)
     :trust-anchors (list trust-anchor)
     :alpn alpn :ticket-store ticket-store))

  (defun %tls-test-read-application-data (driver)
    (multiple-value-bind (status octets)
        (cl-tls-kit:tls13-client-driver-read-application-data driver)
      (unless (eq status :data)
        (error "Expected TLS application data, received ~S." status))
      octets))

  (defun %tls-test-read-http-response (driver)
    (loop with octets = (make-array 0 :element-type '(unsigned-byte 8))
          repeat 8
          for fragment = (%tls-test-read-application-data driver)
          do (setf octets
                   (concatenate '(vector (unsigned-byte 8)) octets fragment))
          when (search (octets 13 10 13 10) octets)
            return (parse-http-response octets
                                        :request-method "GET"
                                        :collect-body-p t)
          finally
            (error "The TLS server did not complete its HTTP upgrade response.")))

  (defun %tls-test-websocket-upgrade (driver)
    (with-open-stream (dummy (make-string-input-stream ""))
      (websocket-client-handshake
       dummy
       (make-websocket-upgrade-request "wss://localhost/socket"
                                       :key +sample-key+)
       (lambda (request stream &rest options)
         (declare (ignore stream options))
         (cl-tls-kit:tls13-client-driver-write
          driver (serialize-http-request request))
         (values (%tls-test-read-http-response driver) nil)))))

  (defun %tls-test-write-websocket-frame (driver opcode payload masking-key)
    (cl-tls-kit:tls13-client-driver-write
     driver
     (serialize-websocket-frame
      (make-websocket-frame :opcode opcode :mask-p t
                            :masking-key masking-key :payload payload))))

  (defun %tls-test-read-websocket-frame (driver)
    (let ((octets (%tls-test-read-application-data driver)))
      (multiple-value-bind (frame consumed)
          (parse-websocket-frame octets)
        (unless (= consumed (length octets))
          (error "The TLS server returned extra WebSocket data."))
        frame)))

  (describe "TLS 1.3 WebSocket listener"
    (it "completes a WSS handshake and exchanges text and binary messages"
      (%tls-test-with-certificate
       (lambda (certificate-chain private-key trust-anchor)
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate-chain certificate-chain
                    :private-key private-key)))
                (server-error nil)
                (server-thread nil)
                (driver nil))
           (unwind-protect
                (progn
                  (setf server-thread
                        (sb-thread:make-thread
                         (lambda ()
                           (handler-case
                               (let ((connection
                                       (accept-websocket-connection
                                        listener :timeout 30
                                        :on-error
                                        (lambda (condition)
                                          (setf server-error condition)))))
                                 (when connection
                                   (unwind-protect
                                        (dotimes (index 2)
                                          (declare (ignore index))
                                          (multiple-value-bind (payload opcode)
                                              (websocket-receive
                                               connection :timeout 10)
                                            (websocket-send
                                             connection payload :opcode opcode
                                             :timeout 10)))
                                     (close-websocket-connection
                                      connection :send-close-p nil))))
                             (error (condition)
                               (setf server-error condition))))))
                  (setf driver
                        (%tls-test-client-driver
                         listener trust-anchor '("http/1.1")))
                  (cl-tls-kit:tls13-client-driver-connect driver)
                  (let ((response (%tls-test-websocket-upgrade driver)))
                    (expect (http-response-status response) :to-equal 101))
                  (%tls-test-write-websocket-frame
                   driver 1 (map '(vector (unsigned-byte 8)) #'char-code "wss text")
                   (octets 1 2 3 4))
                  (let ((frame (%tls-test-read-websocket-frame driver)))
                    (expect (websocket-frame-opcode frame) :to-equal 1)
                    (expect (websocket-frame-payload frame)
                            :to-equalp
                            (map '(vector (unsigned-byte 8)) #'char-code "wss text")))
                  (%tls-test-write-websocket-frame
                   driver 2 (octets 0 1 127 128 255) (octets 5 6 7 8))
                  (let ((frame (%tls-test-read-websocket-frame driver)))
                    (expect (websocket-frame-opcode frame) :to-equal 2)
                    (expect (websocket-frame-payload frame)
                            :to-equalp (octets 0 1 127 128 255)))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect server-error :to-be nil))
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread))))))))
)
