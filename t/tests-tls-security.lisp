(in-package #:websocket-kit/test)

#+sbcl
(progn
  (defun %tls-security-with-ticket-store-capture (function)
    (let* ((symbol 'cl-tls-kit:make-tls13-server-ticket-key-store)
           (original (symbol-function symbol))
           (stores nil))
      (unwind-protect
           (progn
             (sb-ext:without-package-locks
               (setf (symbol-function symbol)
                     (lambda (&rest arguments)
                       (let ((store (apply original arguments)))
                         (push store stores)
                         store))))
             (funcall function (lambda () (copy-list stores))))
        (sb-ext:without-package-locks
          (setf (symbol-function symbol) original)))))

  (defun %tls-security-ticket-store-destroyed-p (store)
    (handler-case
        (progn
          (cl-tls-kit:rotate-tls13-server-ticket-key-store store)
          nil)
      (cl-tls-kit:tls13-server-driver-error (condition)
        (eq (cl-tls-kit:tls13-server-driver-error-reason condition)
            :ticket-key-store-destroyed))))

  (defun %tls-security-read-record (stream)
    (let ((header (make-array 5 :element-type '(unsigned-byte 8))))
      (let ((header-count (read-sequence header stream)))
        (cond
          ((zerop header-count) nil)
          ((/= header-count 5)
           (error "The TLS peer returned a truncated record header."))
          (t
           (let* ((length (+ (ash (aref header 3) 8) (aref header 4)))
                  (fragment
                    (make-array length :element-type '(unsigned-byte 8))))
             (unless (= (read-sequence fragment stream) length)
               (error "The TLS peer returned a truncated record."))
             (concatenate '(vector (unsigned-byte 8)) header fragment)))))))

  (defun %tls-security-client-driver-with-legacy-version
      (listener trust-anchor)
    (require :sb-bsd-sockets)
    (let* ((package (find-package "SB-BSD-SOCKETS"))
           (make-socket (symbol-function (find-symbol "MAKE-INET-SOCKET" package)))
           (connect (symbol-function (find-symbol "SOCKET-CONNECT" package)))
           (make-stream (symbol-function (find-symbol "SOCKET-MAKE-STREAM" package)))
           (close-socket (symbol-function (find-symbol "SOCKET-CLOSE" package)))
           (socket (funcall make-socket :stream :tcp))
           (stream nil)
           (closed-p nil)
           (returned-p nil)
           (version-rewritten-p nil)
           (driver nil))
      (unwind-protect
           (progn
             (funcall connect socket #(127 0 0 1)
                      (websocket-listener-port listener))
             (setf stream
                   (funcall make-stream socket :input t :output t
                            :element-type '(unsigned-byte 8) :buffering :full))
             (setf driver
                   (cl-tls-kit:make-tls13-client-driver
                    :provider (cl-tls-kit:make-cl-crypto-kit-provider)
                    :trust-anchors (list trust-anchor)
                    :hostname "localhost"
                    :alpn '("http/1.1")
                    :transport-read
                    (lambda (client)
                      (declare (ignore client))
                      (%tls-security-read-record stream))
                    :transport-write
                    (lambda (client bytes)
                      (declare (ignore client))
                      (let ((wire (copy-seq bytes)))
                        (unless version-rewritten-p
                          (unless (and (>= (length wire) 5)
                                       (= (aref wire 0) #x16))
                            (error "The TLS client did not start with ClientHello."))
                          (setf (aref wire 1) #x2a
                                (aref wire 2) #x2a
                                version-rewritten-p t))
                        (write-sequence wire stream)
                        (finish-output stream)))
                    :transport-close
                    (lambda (client)
                      (declare (ignore client))
                      (unless closed-p
                        (setf closed-p t)
                        (when stream
                          (ignore-errors (close stream :abort t)))
                        (when socket
                          (ignore-errors (funcall close-socket socket)))))))
             (setf returned-p t)
             (values driver (lambda () version-rewritten-p)))
        (unless returned-p
          (when stream
            (ignore-errors (close stream :abort t)))
          (when socket
            (ignore-errors (funcall close-socket socket)))))))

  (defun %tls-security-send-oversized-record-and-read-alert (port)
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
             (finish-output stream)
             (let ((alert (make-array 7 :element-type '(unsigned-byte 8))))
               (unless (= (read-sequence alert stream) 7)
                 (error "The TLS server returned a truncated fatal alert."))
               alert))
        (when stream
          (ignore-errors (close stream :abort t)))
        (when socket
          (ignore-errors (funcall close-socket socket))))))

  (describe "TLS security review fixes"
    (it "sends close_notify and destroys ticket keys when a WSS connection closes"
      (%tls-security-with-ticket-store-capture
       (lambda (ticket-stores)
         (%tls-test-with-certificate
          (lambda (certificate key trust-anchor)
            (let* ((close-semaphore (sb-thread:make-semaphore))
                   (listener
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
                                      (sb-thread:wait-on-semaphore close-semaphore)
                                      (close-websocket-connection
                                       connection :send-close-p nil)))
                                (error (condition)
                                  (setf server-error condition)))))
                     (setf driver
                           (%tls-test-client-driver
                            listener trust-anchor '("http/1.1")))
                     (cl-tls-kit:tls13-client-driver-connect driver)
                     (let ((response (%tls-test-websocket-upgrade driver)))
                       (expect (http-response-status response) :to-equal 101))
                     (let ((stores (funcall ticket-stores)))
                       (expect (length stores) :to-equal 2)
                       (expect
                        (eq (cl-tls-kit:rotate-tls13-server-ticket-key-store
                             (first stores))
                            (first stores))
                        :to-be t))
                     (sb-thread:signal-semaphore close-semaphore)
                     (multiple-value-bind (status octets)
                         (cl-tls-kit:tls13-client-driver-read-application-data
                          driver)
                       (declare (ignore octets))
                       (expect status :to-equal :eof))
                     (sb-thread:join-thread server-thread)
                     (setf server-thread nil)
                     (expect server-error :to-be nil)
                     (expect
                      (every #'%tls-security-ticket-store-destroyed-p
                             (funcall ticket-stores))
                      :to-be t))
                (sb-thread:signal-semaphore close-semaphore)
                (when driver
                  (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
                (close-websocket-listener listener)
                (when server-thread
                  (sb-thread:join-thread server-thread)))))))))

    (it "sends a peer-observable record_overflow alert and destroys failed-handshake keys"
      (%tls-security-with-ticket-store-capture
       (lambda (ticket-stores)
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
                         :on-error
                         (lambda (condition)
                           (setf server-error condition)))))))
              (unwind-protect
                   (let ((alert
                           (%tls-security-send-oversized-record-and-read-alert
                            (websocket-listener-port listener))))
                     (sb-thread:join-thread server-thread)
                     (setf server-thread nil)
                     (expect (subseq alert 0 5)
                             :to-equalp (octets #x15 #x03 #x03 0 2))
                     (expect (subseq alert 5)
                             :to-equalp (octets 2 22))
                     (expect (typep server-error 'websocket-transport-error)
                             :to-be t)
                     (expect (websocket-error-detail server-error)
                             :to-equal 16385)
                     (expect (length (funcall ticket-stores))
                             :to-equal 2)
                     (expect
                      (every #'%tls-security-ticket-store-destroyed-p
                             (funcall ticket-stores))
                      :to-be t))
                (close-websocket-listener listener)
                (when server-thread
                  (sb-thread:join-thread server-thread)))))))))

    (it "ignores the legacy_record_version field in the ClientHello record"
      (%tls-test-with-certificate
       (lambda (certificate key trust-anchor)
         (let* ((close-semaphore (sb-thread:make-semaphore))
                (listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate certificate :key key)))
                (server-error nil)
                (server-thread nil)
                (driver nil)
                (version-rewritten-p nil))
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
                                   (sb-thread:wait-on-semaphore close-semaphore)
                                   (close-websocket-connection
                                    connection :send-close-p nil)))
                             (error (condition)
                               (setf server-error condition)))))
                  (multiple-value-setq (driver version-rewritten-p)
                    (%tls-security-client-driver-with-legacy-version
                     listener trust-anchor))
                  (cl-tls-kit:tls13-client-driver-connect driver)
                  (expect (funcall version-rewritten-p) :to-be t)
                  (let ((response (%tls-test-websocket-upgrade driver)))
                    (expect (http-response-status response) :to-equal 101))
                  (sb-thread:signal-semaphore close-semaphore)
                  (multiple-value-bind (status octets)
                      (cl-tls-kit:tls13-client-driver-read-application-data
                       driver)
                    (declare (ignore octets))
                    (expect status :to-equal :eof))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect server-error :to-be nil))
             (sb-thread:signal-semaphore close-semaphore)
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))

    (it "sends the exact no_application_protocol alert for an ALPN mismatch"
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
                      :on-error
                      (lambda (condition)
                        (setf server-error condition))))))
                (driver nil)
                (client-error nil))
           (unwind-protect
                (progn
                  (setf driver
                        (%tls-test-client-driver
                         listener trust-anchor '("h2")))
                  (handler-case
                      (cl-tls-kit:tls13-client-driver-connect driver)
                    (error (condition)
                      (setf client-error condition)))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect
                   (typep client-error
                          'cl-tls-kit:tls13-client-driver-error)
                   :to-be t)
                  (expect
                   (cl-tls-kit:tls13-client-driver-error-reason client-error)
                   :to-equalp '(:peer-alert 2 120))
                  (expect (not (null server-error)) :to-be t)
                  (expect
                   (cl-tls-kit:tls13-client-driver-closed-p driver)
                   :to-be t))
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))))))
