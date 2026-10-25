(in-package #:websocket-kit/test)

#+sbcl
(progn
  (defun %tls-test-path (kind)
    (merge-pathnames
     (format nil "cl-websocket-kit-tls-~A-~A.pem"
             (symbol-name (gensym)) kind)
     (uiop:temporary-directory)))

  (defun %tls-test-run-openssl (&rest arguments)
    (multiple-value-bind (output error-output exit-code)
        (uiop:run-program
         (cons (or (uiop:getenv "OPENSSL") "openssl") arguments)
         :output :string :error-output :string :ignore-error-status t)
      (unless (zerop exit-code)
        (error "OpenSSL could not create TLS test credentials: ~A~%~A"
               output error-output))))

  (defun %tls-test-with-certificate
      (function &key (subject-alt-name "DNS:localhost,IP:127.0.0.1"))
    (let ((certificate (%tls-test-path "certificate"))
          (key (%tls-test-path "key")))
      (unwind-protect
           (progn
             (%tls-test-run-openssl
              "req" "-x509" "-newkey" "ec"
              "-pkeyopt" "ec_paramgen_curve:P-256" "-nodes"
              "-keyout" (namestring key) "-out" (namestring certificate)
              "-days" "1" "-subj" "/CN=localhost"
              "-addext" (format nil "subjectAltName=~A" subject-alt-name)
              "-addext" "basicConstraints=critical,CA:FALSE"
              "-addext" "keyUsage=critical,digitalSignature"
              "-addext" "extendedKeyUsage=serverAuth")
             (let* ((pem-block
                      (first
                       (cl-tls-kit:pem-decode
                        (uiop:read-file-string certificate))))
                    (trust-anchor
                      (cl-tls-kit.x509:parse-certificate-der
                       (cl-tls-kit:pem-block-der pem-block))))
               (funcall function certificate key trust-anchor)))
        (dolist (path (list certificate key))
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

  (defun %tls-test-write-oversized-record (port)
    (require :sb-bsd-sockets)
    (let* ((package (find-package "SB-BSD-SOCKETS"))
           (make-socket (symbol-function (find-symbol "MAKE-INET-SOCKET" package)))
           (connect (symbol-function (find-symbol "SOCKET-CONNECT" package)))
           (make-stream (symbol-function (find-symbol "SOCKET-MAKE-STREAM" package)))
           (close-socket (symbol-function (find-symbol "SOCKET-CLOSE" package)))
           (socket (funcall make-socket :stream :tcp))
           (stream nil))
      (unwind-protect
           (progn
             (funcall connect socket #(127 0 0 1) port)
             (setf stream
                   (funcall make-stream socket :input t :output t
                            :element-type '(unsigned-byte 8) :buffering :full))
             (write-sequence (octets #x16 #x03 #x03 #x40 #x01) stream)
             (finish-output stream))
        (when stream
          (ignore-errors (close stream :abort t)))
        (when socket
          (ignore-errors (funcall close-socket socket))))))

  (describe "TLS 1.3 WebSocket listener"
    (it "echoes text and binary messages over WSS"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
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
               (sb-thread:join-thread server-thread)))))))

    (it "closes the TLS driver and TCP transport after peer close_notify"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
                (server-error nil)
                (server-transport nil)
                (server-driver nil)
                (server-thread nil)
                (driver nil))
           (unwind-protect
                (progn
                  (setf server-thread
                        (sb-thread:make-thread
                         (lambda ()
                           (handler-case
                               (let* ((connection
                                        (accept-websocket-connection
                                         listener :timeout 30))
                                      (stream
                                        (websocket-connection-stream
                                         connection)))
                                 (setf server-transport
                                       (websocket-kit::websocket-tls-stream-transport
                                        stream)
                                       server-driver
                                       (websocket-kit::websocket-tls-context-driver
                                        (websocket-kit::websocket-tls-stream-context
                                         stream)))
                                 (unless (eq (read-byte stream nil :eof) :eof)
                                   (error "The TLS peer did not send close_notify."))
                                 (close-websocket-connection
                                  connection :send-close-p nil))
                             (error (condition)
                               (setf server-error condition))))))
                  (setf driver
                        (%tls-test-client-driver
                         listener trust-anchor '("http/1.1")))
                  (cl-tls-kit:tls13-client-driver-connect driver)
                  (let ((response (%tls-test-websocket-upgrade driver)))
                    (expect (http-response-status response) :to-equal 101))
                  (cl-tls-kit:tls13-client-driver-close driver)
                  (setf driver nil)
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect server-error :to-be nil)
                  (expect (open-stream-p server-transport) :to-be nil)
                  (multiple-value-bind (closed-driver events)
                      (cl-tls-kit:tls13-server-driver-step
                       server-driver #() :level :application)
                    (declare (ignore closed-driver))
                    (expect events :to-be nil)))
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))

    (it "reports an oversized TLS handshake record as a handshake failure"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (declare (ignore trust-anchor))
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
                (server-error nil)
                (server-thread
                  (sb-thread:make-thread
                   (lambda ()
                     (accept-websocket-connection
                      listener :timeout 10
                      :on-error (lambda (condition)
                                  (setf server-error condition)))))))
           (unwind-protect
                (progn
                  (%tls-test-write-oversized-record
                   (websocket-listener-port listener))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect (typep server-error 'websocket-transport-error)
                          :to-be t)
                  (expect (websocket-error-detail server-error)
                          :to-equal 16385))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))

    (it "rejects a TLS handshake when ALPN does not include HTTP/1.1"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
                (server-error nil)
                (server-thread
                  (sb-thread:make-thread
                   (lambda ()
                     (accept-websocket-connection
                      listener :timeout 10
                      :on-error (lambda (condition)
                                  (setf server-error condition))))))
                (driver nil)
                (client-error nil))
           (unwind-protect
                (progn
                  (setf driver
                        (%tls-test-client-driver listener trust-anchor '("h2")))
                  (handler-case
                      (cl-tls-kit:tls13-client-driver-connect driver)
                    (error (condition)
                      (setf client-error condition)))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect (not (null client-error)) :to-be t)
                  (expect (not (null server-error)) :to-be t)
                  (expect
                   (cl-tls-kit:tls13-client-driver-closed-p driver)
                   :to-be t))
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread))))))))

    (it "defaults TLS hostname verification to the TCP host"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (let* ((listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
                (server-error nil)
                (server-thread nil)
                (driver nil)
                (client-error nil))
           (unwind-protect
                (progn
                  (setf server-thread
                        (sb-thread:make-thread
                         (lambda ()
                           (handler-case
                               (accept-websocket-connection
                                listener :timeout 30
                                :on-error
                                (lambda (condition)
                                  (setf server-error condition)))
                             (error (condition)
                               (setf server-error condition))))))
                  (setf driver
                        (%tls-test-client-driver
                         listener trust-anchor '("http/1.1")))
                  (handler-case
                      (cl-tls-kit:tls13-client-driver-connect driver)
                    (error (condition)
                      (setf client-error condition)))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect (not (null client-error)) :to-be t)
                  (expect
                   (typep client-error 'cl-tls-kit:tls13-client-driver-error)
                   :to-be t)
                  (expect
                   (eq (first
                        (cl-tls-kit:tls13-client-driver-error-reason
                         client-error))
                       :certificate-verification-failed)
                   :to-be t)
                  (expect
                   (cl-tls-kit:tls13-client-driver-closed-p driver)
                   :to-be t)
                  (expect (not (null server-error)) :to-be t))
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))
       :subject-alt-name "DNS:localhost")))

#+sbcl
(describe "TLS 1.3 WSS ticket policy"
  (it "does not deliver NewSessionTicket to a WSS client"
    (%tls-test-with-certificate
     (lambda (certificate key trust-anchor)
       (let* ((listener
                (open-websocket-listener
                 :host "127.0.0.1" :port 0
                 :tls-wrapper
                 (make-websocket-tls-server-wrapper
                  :certificate certificate :key key)))
              (server-error nil)
              (server-thread nil)
              (ticket-store-clock-calls 0)
              (driver nil))
         (unwind-protect
              (progn
                (setf server-thread
                      (sb-thread:make-thread
                       (lambda ()
                         (handler-case
                             (let ((connection
                                     (accept-websocket-connection
                                      listener :timeout 15
                                      :on-error
                                      (lambda (condition)
                                        (setf server-error condition)))))
                               (unless connection
                                 (error "The WSS client did not upgrade."))
                               (close-websocket-connection
                                connection :send-close-p nil))
                           (error (condition)
                             (setf server-error condition))))))
                (setf driver
                      (%tls-test-client-driver
                       listener trust-anchor '("http/1.1")
                       :ticket-store
                       (cl-tls-kit:make-tls13-ticket-store
                        :clock (lambda ()
                                 (incf ticket-store-clock-calls)))))
                (cl-tls-kit:tls13-client-driver-connect driver)
                (let ((response (%tls-test-websocket-upgrade driver)))
                  (expect (http-response-status response) :to-equal 101))
                (multiple-value-bind (status octets)
                    (cl-tls-kit:tls13-client-driver-read-application-data driver)
                  (declare (ignore octets))
                  (expect status :to-equal :eof))
                (sb-thread:join-thread server-thread)
                (setf server-thread nil)
                ;; ClientHello performs one empty-store lookup; each received ticket adds one.
                (expect ticket-store-clock-calls :to-equal 1)
                (expect server-error :to-be nil))
           (when driver
             (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
           (when server-thread
             (ignore-errors (close-websocket-listener listener))
             (sb-thread:join-thread server-thread))
           (close-websocket-listener listener)))))))
