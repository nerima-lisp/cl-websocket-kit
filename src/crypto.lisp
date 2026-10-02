(in-package #:websocket-kit)

(defparameter +websocket-close-guid+
  "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")

(defparameter +websocket-base64-alphabet+
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

(defun %websocket-base64-encode (octets)
  (unless (%websocket-octet-vector-p octets)
    (%websocket-protocol-error "Base64 input must be a vector of octets." octets))
  (let* ((length (length octets))
         (result (make-string (* 4 (ceiling length 3)))))
    (loop for input from 0 below length by 3
          for output from 0 by 4
          for first = (aref octets input)
          for second-present = (< (1+ input) length)
          for third-present = (< (+ input 2) length)
          for second = (if second-present (aref octets (1+ input)) 0)
          for third = (if third-present (aref octets (+ input 2)) 0)
          for value = (logior (ash first 16) (ash second 8) third)
          do (setf (char result output)
                   (char +websocket-base64-alphabet+ (ldb (byte 6 18) value))
                   (char result (1+ output))
                   (char +websocket-base64-alphabet+ (ldb (byte 6 12) value))
                   (char result (+ output 2))
                   (if second-present
                       (char +websocket-base64-alphabet+ (ldb (byte 6 6) value))
                       #\=)
                   (char result (+ output 3))
                   (if third-present
                       (char +websocket-base64-alphabet+ (ldb (byte 6 0) value))
                       #\=)))
    result))

(defun %websocket-base64-value (character)
  (position character +websocket-base64-alphabet+ :test #'char=))

(defun %websocket-base64-decode (string)
  (unless (and (stringp string) (zerop (mod (length string) 4)))
    (%websocket-protocol-error
     "A WebSocket Sec-WebSocket-Key must be valid Base64." string))
  (let ((result (make-array 0
                            :element-type '(unsigned-byte 8)
                            :adjustable t
                            :fill-pointer 0)))
    (loop for offset from 0 below (length string) by 4
          for first = (char string offset)
          for second = (char string (1+ offset))
          for third = (char string (+ offset 2))
          for fourth = (char string (+ offset 3))
          for first-value = (%websocket-base64-value first)
          for second-value = (%websocket-base64-value second)
          for third-value = (unless (char= third #\=)
                             (%websocket-base64-value third))
          for fourth-value = (unless (char= fourth #\=)
                              (%websocket-base64-value fourth))
          do (unless (and first-value second-value
                          (or (char= third #\=) third-value)
                          (or (char= fourth #\=) fourth-value)
                          (or (not (char= third #\=))
                              (char= fourth #\=))
                          (or (not (char= fourth #\=))
                              (= offset (- (length string) 4))))
               (%websocket-protocol-error
                "A WebSocket Sec-WebSocket-Key has invalid Base64 padding."
                string))
             (let ((value (logior (ash first-value 18)
                                  (ash second-value 12)
                                  (ash (or third-value 0) 6)
                                  (or fourth-value 0))))
               (when (and (char= third #\=)
                          (not (zerop (logand second-value #x0f))))
                 (%websocket-protocol-error
                  "A Base64 value has non-zero unused bits."
                  string))
               (when (and (char= fourth #\=)
                          (not (zerop (logand (or third-value 0) #x03))))
                 (%websocket-protocol-error
                  "A Base64 value has non-zero unused bits."
                  string))
               (vector-push-extend (ldb (byte 8 16) value) result)
               (unless (char= third #\=)
                 (vector-push-extend (ldb (byte 8 8) value) result))
               (unless (char= fourth #\=)
                 (vector-push-extend (ldb (byte 8 0) value) result))))
    (let ((copy (make-array (length result)
                            :element-type '(unsigned-byte 8))))
      (replace copy result)
      copy)))

(defun websocket-accept-key (sec-websocket-key)
  "Return the RFC 6455 Sec-WebSocket-Accept value for a client key."
  (unless (stringp sec-websocket-key)
    (%websocket-protocol-error
     "Sec-WebSocket-Key must be a Base64 string."
     sec-websocket-key))
  (unless (= (length sec-websocket-key) 24)
    (%websocket-protocol-error
     "Sec-WebSocket-Key must be the 24-character Base64 form of 16 octets."
     (length sec-websocket-key)))
  (let ((decoded (%websocket-base64-decode sec-websocket-key)))
    (unless (= (length decoded) 16)
      (%websocket-protocol-error
       "Sec-WebSocket-Key must decode to exactly 16 octets."
       (length decoded)))
    (%websocket-base64-encode
     (crypto-kit:digest
      :sha1
      (let* ((key (%websocket-utf8-octets sec-websocket-key))
             (guid (%websocket-utf8-octets +websocket-close-guid+))
             (input (make-array (+ (length key) (length guid))
                                :element-type '(unsigned-byte 8))))
        (replace input key)
        (replace input guid :start1 (length key))
        input)))))
