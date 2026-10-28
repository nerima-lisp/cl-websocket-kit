(in-package #:websocket-kit)
(defun %websocket-make-tls-server-wrapper
    (&key certificate-chain private-key alpn-protocols
          (clock-function (function %websocket-monotonic-time)))
  (let ((http-wrapper
          (http-kit/tls:make-http-tls-server-wrapper
           :certificate-chain certificate-chain
           :private-key private-key
           :alpn-protocols alpn-protocols
           :session-tickets-p nil
           :clock-function clock-function)))
    (lambda (stream &key timeout deadline &allow-other-keys)
      (let ((tls-stream
              (funcall http-wrapper stream
                       :timeout timeout
                       :deadline deadline)))
        (values tls-stream
                (http-kit/tls:http-tls-selected-alpn-protocol
                 tls-stream))))))

