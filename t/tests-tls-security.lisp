(in-package #:websocket-kit/test)

#+sbcl
(progn
  (defun %tls-test-open-tcp-stream (port)
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
             (values stream socket))
        (unless stream
          (ignore-errors (funcall close-socket socket))))))

  (defun %tls-test-close-tcp-stream (stream socket)
    (when stream
      (ignore-errors (close stream :abort t)))
    (when socket
      (ignore-errors
        (funcall (symbol-function
                  (find-symbol "SOCKET-CLOSE" (find-package "SB-BSD-SOCKETS")))
                 socket))))

  (describe "Delegated TLS 1.3 WebSocket server"
    (it "expires a stalled handshake without writing TLS bytes"
      (%tls-test-with-certificate
       (lambda (certificate-chain private-key trust-anchor)
         (declare (ignore trust-anchor))
         (let* ((clock-calls 0)
                ;; Let accept establish its deadline and take the queued socket.
                (clock-function
                  (lambda ()
                    (if (<= (incf clock-calls) 2) 0 1)))
                (listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :clock-function clock-function
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate-chain certificate-chain
                    :private-key private-key
                    :clock-function clock-function)))
                (client-stream nil)
                (client-socket nil)
                (server-error nil)
                (server-thread nil))
           (unwind-protect
                (progn
                  (multiple-value-setq (client-stream client-socket)
                    (%tls-test-open-tcp-stream
                     (websocket-listener-port listener)))
                  (setf server-thread
                        (sb-thread:make-thread
                         (lambda ()
                           (accept-websocket-connection
                            listener :timeout 0.5
                            :clock-function clock-function
                            :on-error
                            (lambda (condition)
                              (setf server-error condition))))))
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect (typep server-error 'http-kit:http-timeout) :to-be t)
                  (expect (read-byte client-stream nil :eof) :to-be :eof))
             (%tls-test-close-tcp-stream client-stream client-socket)
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))

    (it "rejects a client that does not offer the server ALPN protocol"
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
                (driver nil)
                (client-error nil))
           (unwind-protect
                (progn
                  (setf server-thread
                        (sb-thread:make-thread
                         (lambda ()
                           (accept-websocket-connection
                            listener :timeout 10
                            :on-error
                            (lambda (condition)
                              (setf server-error condition))))))
                  (setf driver
                        (%tls-test-client-driver
                         listener trust-anchor '("h2")))
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
               (sb-thread:join-thread server-thread)))))))

    (it "closes the WSS stream with close_notify and issues no session ticket"
      (%tls-test-with-certificate
       (lambda (certificate-chain private-key trust-anchor)
         (let* ((ready (sb-thread:make-semaphore))
                (close-server (sb-thread:make-semaphore))
                (listener
                  (open-websocket-listener
                   :host "127.0.0.1" :port 0
                   :tls-wrapper
                   (make-websocket-tls-server-wrapper
                    :certificate-chain certificate-chain
                    :private-key private-key)))
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
                                        listener :timeout 30
                                        :on-error
                                        (lambda (condition)
                                          (setf server-error condition)))))
                                 (when connection
                                   (sb-thread:signal-semaphore ready)
                                   (sb-thread:wait-on-semaphore close-server)
                                   (close-websocket-connection connection)))
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
                  (sb-thread:wait-on-semaphore ready)
                  (sb-thread:signal-semaphore close-server)
                  (let ((close-frame (%tls-test-read-websocket-frame driver)))
                    (expect (websocket-frame-opcode close-frame) :to-equal 8))
                  (multiple-value-bind (status octets)
                      (cl-tls-kit:tls13-client-driver-read-application-data driver)
                    (declare (ignore octets))
                    (expect status :to-equal :eof))
                  (expect
                   (cl-tls-kit:tls13-client-driver-close-notify-received-p driver)
                   :to-be t)
                  (sb-thread:join-thread server-thread)
                  (setf server-thread nil)
                  (expect server-error :to-be nil)
                  (expect ticket-store-clock-calls :to-equal 1))
             (sb-thread:signal-semaphore close-server)
             (when driver
               (ignore-errors (cl-tls-kit:tls13-client-driver-close driver)))
             (close-websocket-listener listener)
             (when server-thread
               (sb-thread:join-thread server-thread)))))))
))
