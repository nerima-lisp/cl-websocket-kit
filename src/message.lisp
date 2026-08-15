(in-package #:websocket-kit)

(defun websocket-valid-close-code-p (code)
  (and (integerp code)
       (or (member code '(1000 1001 1002 1003 1007 1008 1009 1010 1011)
                   :test #'=)
           (<= 3000 code 4999))))

(defun %websocket-utf8-continuation-p (byte)
  (<= #x80 byte #xbf))

(defun %websocket-utf8-string (octets)
  (unless (%websocket-octet-vector-p octets)
    (%websocket-protocol-error "A WebSocket reason must be UTF-8 octets." octets))
  (with-output-to-string (result)
    (loop with index = 0
          while (< index (length octets))
          do (let ((first (aref octets index)))
               (cond ((<= first #x7f)
                      (write-char (code-char first) result)
                      (incf index))
                     ((<= #xc2 first #xdf)
                      (when (> (1+ index) (1- (length octets)))
                        (%websocket-protocol-error
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index))))
                        (unless (%websocket-utf8-continuation-p second)
                          (%websocket-protocol-error
                           "A WebSocket close reason contains invalid UTF-8."
                           octets))
                        (write-char
                         (code-char (+ (ash (logand first #x1f) 6)
                                       (logand second #x3f)))
                         result)
                        (incf index 2)))
                     ((<= #xe0 first #xef)
                      (when (> (+ index 2) (1- (length octets)))
                        (%websocket-protocol-error
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index)))
                            (third (aref octets (+ index 2))))
                        (unless (and (%websocket-utf8-continuation-p second)
                                     (%websocket-utf8-continuation-p third)
                                     (or (/= first #xe0) (>= second #xa0))
                                     (or (/= first #xed) (<= second #x9f)))
                          (%websocket-protocol-error
                           "A WebSocket close reason contains invalid UTF-8."
                           octets))
                        (write-char
                         (code-char (+ (ash (logand first #x0f) 12)
                                       (ash (logand second #x3f) 6)
                                       (logand third #x3f)))
                         result)
                        (incf index 3)))
                     ((<= #xf0 first #xf4)
                      (when (> (+ index 3) (1- (length octets)))
                        (%websocket-protocol-error
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index)))
                            (third (aref octets (+ index 2)))
                            (fourth (aref octets (+ index 3))))
                        (unless (and (%websocket-utf8-continuation-p second)
                                     (%websocket-utf8-continuation-p third)
                                     (%websocket-utf8-continuation-p fourth)
                                     (or (/= first #xf0) (>= second #x90))
                                     (or (/= first #xf4) (<= second #x8f)))
                          (%websocket-protocol-error
                           "A WebSocket close reason contains invalid UTF-8."
                           octets))
                        (write-char
                         (code-char (+ (ash (logand first #x07) 18)
                                       (ash (logand second #x3f) 12)
                                       (ash (logand third #x3f) 6)
                                       (logand fourth #x3f)))
                         result)
                        (incf index 4)))
                     (t
                      (%websocket-protocol-error
                       "A WebSocket close reason contains invalid UTF-8."
                       octets)))))))

(defun make-websocket-close-payload (&key (code 1000) (reason ""))
  "Construct the payload for a WebSocket close control frame."
  (unless (websocket-valid-close-code-p code)
    (%websocket-protocol-error "The WebSocket close code is not permitted." code))
  (unless (stringp reason)
    (%websocket-protocol-error "The WebSocket close reason must be a string." reason))
  (let ((reason-octets (%websocket-utf8-octets reason)))
    (when (> (length reason-octets) 123)
      (%websocket-size-error
       "A WebSocket close reason exceeded its 123-octet limit."
       123 (length reason-octets)))
    (let ((payload (make-array (+ 2 (length reason-octets))
                               :element-type '(unsigned-byte 8))))
      (%websocket-store-integer payload 0 2 code)
      (replace payload reason-octets :start1 2)
      payload)))

(defun parse-websocket-close-payload (payload)
  "Parse a close payload and return its code and UTF-8 reason."
  (unless (%websocket-octet-vector-p payload)
    (%websocket-protocol-error "A WebSocket close payload must be octets." payload))
  (cond ((zerop (length payload))
         (values nil ""))
        ((= (length payload) 1)
         (%websocket-protocol-error
          "A WebSocket close payload cannot contain one octet."))
        (t
         (let ((code (%websocket-read-integer payload 0 2)))
           (unless (websocket-valid-close-code-p code)
             (%websocket-protocol-error
              "The WebSocket close code is not permitted."
              code))
           (values code (%websocket-utf8-string (subseq payload 2)))))))

(defun %websocket-append-octets (target source)
  (let* ((old-length (fill-pointer target))
         (new-length (+ old-length (length source))))
    (setf target (adjust-array target new-length :fill-pointer new-length))
    (replace target source :start1 old-length)
    target))

(defun read-websocket-message
    (stream &key (max-message-bytes +websocket-default-max-payload-bytes+)
                  (max-payload-bytes +websocket-default-max-payload-bytes+)
                  (require-mask-p nil) (allow-unmasked-p t) on-control)
  "Read one fragmented WebSocket data message.

Returns the message payload octets and its data opcode (1 for text or 2 for
binary).  Control frames are delivered to ON-CONTROL, when supplied, and are
otherwise consumed while the data message is assembled."
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (when (and on-control (not (functionp on-control)))
    (%websocket-protocol-error "ON-CONTROL must be a function or NIL." on-control))
  (let ((message-opcode nil)
        (message (make-array 0
                             :element-type '(unsigned-byte 8)
                             :adjustable t
                             :fill-pointer 0)))
    (loop
      (let ((frame (read-websocket-frame
                    stream
                    :max-payload-bytes max-payload-bytes
                    :require-mask-p require-mask-p
                    :allow-unmasked-p allow-unmasked-p)))
        (let ((opcode (websocket-frame-opcode frame))
              (payload (websocket-frame-payload frame)))
          (cond ((%websocket-control-opcode-p opcode)
                 (when on-control
                   (funcall on-control frame)))
                ((zerop opcode)
                 (unless message-opcode
                   (%websocket-protocol-error
                    "A WebSocket continuation frame has no initial data frame."))
                 (when (> (+ (fill-pointer message) (length payload))
                          max-message-bytes)
                   (%websocket-size-error
                    "A WebSocket message exceeded its size limit."
                    max-message-bytes
                    (+ (fill-pointer message) (length payload))))
                 (setf message (%websocket-append-octets message payload))
                 (when (websocket-frame-fin-p frame)
                   (return
                     (values (subseq message 0 (fill-pointer message))
                             message-opcode))))
                ((member opcode '(1 2) :test #'=)
                 (when message-opcode
                   (%websocket-protocol-error
                    "A WebSocket data frame arrived before the prior message ended."
                    opcode))
                 (setf message-opcode opcode)
                 (when (> (length payload) max-message-bytes)
                   (%websocket-size-error
                    "A WebSocket message exceeded its size limit."
                    max-message-bytes (length payload)))
                 (setf message (%websocket-append-octets message payload))
                 (when (websocket-frame-fin-p frame)
                   (return
                     (values (subseq message 0 (fill-pointer message))
                             message-opcode))))
                (t
                 (%websocket-protocol-error
                 "A WebSocket message encountered an invalid data opcode."
                  opcode))))))))

(defun %websocket-message-octets (payload opcode)
  (cond ((%websocket-octet-vector-p payload)
         (%websocket-copy-octets payload))
        ((and (= opcode 1) (stringp payload))
         (%websocket-utf8-octets payload))
        (t
         (%websocket-protocol-error
          "A WebSocket data message must be octets, or a text string for opcode 1."
          payload))))

(defun %websocket-positive-limit (limit name)
  (unless (and (integerp limit) (plusp limit))
    (%websocket-protocol-error
     (format nil "~A must be a positive integer." name)
     limit))
  limit)

(defun %websocket-masking-options
    (mask-p masking-key masking-key-function)
  (when (and masking-key masking-key-function)
    (%websocket-protocol-error
     "A WebSocket masking key and masking-key function are mutually exclusive."))
  (when (and (not mask-p) (or masking-key masking-key-function))
    (%websocket-protocol-error
     "An unmasked WebSocket frame cannot specify a masking key."))
  (when (and mask-p masking-key-function (not (functionp masking-key-function)))
    (%websocket-protocol-error
     "A WebSocket masking-key function must be callable."
     masking-key-function))
  (when (and mask-p (not (or masking-key masking-key-function)))
    (%websocket-protocol-error
     "Masked WebSocket output requires an explicit masking key or key function."))
  t)

(defun %websocket-next-masking-key
    (mask-p masking-key masking-key-function)
  (when mask-p
    (%websocket-copy-octets
     (if masking-key-function
         (funcall masking-key-function)
         masking-key))))

(defun write-websocket-message
    (stream payload &key (opcode 2) (max-frame-payload-bytes 65535)
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t))
  "Write one text or binary WebSocket message.

PAYLOAD may be an octet vector, or a string when OPCODE is 1.  Large payloads
are fragmented into frames no larger than MAX-FRAME-PAYLOAD-BYTES.  When
MASK-P is true, MASKING-KEY-FUNCTION is called once per frame and must return
four octets; a single MASKING-KEY is accepted only when one frame is emitted.
Returns the number of frames and the payload length."
  (unless (member opcode '(1 2) :test #'=)
    (%websocket-protocol-error
     "A WebSocket message opcode must be 1 (text) or 2 (binary)."
     opcode))
  (%websocket-positive-limit max-frame-payload-bytes
                              "MAX-FRAME-PAYLOAD-BYTES")
  (let* ((octets (%websocket-message-octets payload opcode))
         (payload-length (length octets))
         (frame-count (max 1 (ceiling payload-length
                                      max-frame-payload-bytes))))
    (%websocket-masking-options mask-p masking-key masking-key-function)
    (when (and mask-p (> frame-count 1) masking-key)
      (%websocket-protocol-error
       "Fragmented masked output requires a masking-key function so each frame has a fresh key."))
    (unless (streamp stream)
      (%websocket-protocol-error "WebSocket message output must be a stream." stream))
    (let ((position 0)
          (frame-index 0)
          (first-p t))
      (loop while (or first-p (< position payload-length))
            do (let* ((remaining (- payload-length position))
                      (chunk-length (min max-frame-payload-bytes remaining))
                      (last-p (= (+ position chunk-length) payload-length))
                      (frame (make-websocket-frame
                              :fin-p last-p
                              :opcode (if (zerop frame-index) opcode 0)
                              :mask-p mask-p
                              :masking-key
                              (%websocket-next-masking-key
                               mask-p masking-key masking-key-function)
                              :payload (subseq octets position
                                               (+ position chunk-length)))))
                 (write-websocket-frame stream frame :finish-output-p nil)
                 (incf frame-index)
                 (setf position (+ position chunk-length)
                       first-p nil)))
      (when finish-output-p
        (finish-output stream))
      (values frame-count payload-length))))

(defun %write-websocket-control-frame
    (stream opcode payload &key (mask-p nil) masking-key masking-key-function
                         (finish-output-p t))
  (%websocket-masking-options mask-p masking-key masking-key-function)
  (let ((frame
          (make-websocket-frame
           :fin-p t
           :opcode opcode
           :mask-p mask-p
           :masking-key
           (%websocket-next-masking-key
            mask-p masking-key masking-key-function)
           :payload
           (cond ((%websocket-octet-vector-p payload)
                  payload)
                 ((stringp payload)
                  (%websocket-utf8-octets payload))
                 (t
                  (%websocket-protocol-error
                   "A WebSocket control payload must be octets or a string."
                   payload))))))
    (write-websocket-frame stream frame :finish-output-p finish-output-p)))

(defun websocket-ping
    (stream &key (payload (make-array 0 :element-type '(unsigned-byte 8)))
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t))
  "Write a final WebSocket Ping control frame."
  (%write-websocket-control-frame
   stream 9 payload
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p))

(defun websocket-pong
    (stream &key (payload (make-array 0 :element-type '(unsigned-byte 8)))
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t))
  "Write a final WebSocket Pong control frame."
  (%write-websocket-control-frame
   stream 10 payload
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p))

(defun websocket-close
    (stream &key payload code reason
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t))
  "Write a WebSocket Close control frame.

When PAYLOAD is supplied it is used as the already encoded close payload and
CODE and REASON must be NIL.  Otherwise CODE defaults to 1000 and REASON to
the empty string."
  (when (and payload (or code reason))
    (%websocket-protocol-error
     "A raw WebSocket close payload cannot be combined with CODE or REASON."))
  (%write-websocket-control-frame
   stream 8
   (or payload (make-websocket-close-payload :code (or code 1000)
                                     :reason (or reason "")))
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p))

(defun %websocket-session-close-code (condition)
  (cond ((typep condition 'websocket-size-limit-exceeded) 1009)
        ((typep condition 'websocket-error) 1002)
        (t 1011)))

(defun serve-websocket-session
    (stream handler &key
                     (max-message-bytes +websocket-default-max-payload-bytes+)
                     (max-payload-bytes +websocket-default-max-payload-bytes+)
                     (max-messages nil)
                     (require-mask-p t)
                     (allow-unmasked-p nil)
                     on-control
                     on-error
                     (close-on-error-p t)
                     (close-stream #'close))
  "Serve messages on an already-upgraded WebSocket STREAM.

HANDLER is called as (STREAM PAYLOAD OPCODE) for every complete text or
binary message.  It may return :CLOSE to start a normal close handshake.
The server automatically replies to Ping frames and echoes a valid peer
Close frame.  Client frames are required to be masked by default.

The function returns two values: the number of messages delivered and a
termination keyword (:PEER-CLOSE, :HANDLER-CLOSE, or :MAX-MESSAGES).  On a
protocol, size, or handler error it sends an appropriate Close frame when
CLOSE-ON-ERROR-P is true, invokes ON-ERROR with the condition, and re-signals
the condition.  CLOSE-STREAM is called at the end unless it is NIL, which is
useful when the caller owns the upgraded stream lifecycle."
  (unless (streamp stream)
    (%websocket-protocol-error
     "A WebSocket session requires a stream." stream))
  (unless (functionp handler)
    (%websocket-protocol-error
     "A WebSocket session handler must be callable." handler))
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (when (and max-messages
             (or (not (integerp max-messages)) (minusp max-messages)))
    (%websocket-protocol-error
     "MAX-MESSAGES must be NIL or a non-negative integer."
     max-messages))
  (when (and on-control (not (functionp on-control)))
    (%websocket-protocol-error
     "ON-CONTROL must be a function or NIL." on-control))
  (when (and on-error (not (functionp on-error)))
    (%websocket-protocol-error
     "ON-ERROR must be a function or NIL." on-error))
  (when (and close-stream (not (functionp close-stream)))
    (%websocket-protocol-error
     "CLOSE-STREAM must be a function or NIL." close-stream))
  (let ((message-count 0)
        (close-sent-p nil)
        (close-tag (gensym "WEBSOCKET-CLOSE-")))
    (labels ((send-close (&key payload code reason)
               (unless close-sent-p
                 (setf close-sent-p t)
                 (if payload
                     (websocket-close stream :payload payload)
                     (websocket-close stream
                                      :code (or code 1000)
                                      :reason (or reason "")))))
             (handle-control (frame)
               (let ((opcode (websocket-frame-opcode frame))
                     (payload (websocket-frame-payload frame)))
                 (when on-control
                   (funcall on-control frame))
                 (case opcode
                   (9
                    (websocket-pong stream :payload payload))
                   (8
                    (parse-websocket-close-payload payload)
                    (send-close :payload payload)
                    (throw close-tag :peer-close))
                   (10 nil)))))
      (unwind-protect
           (handler-case
               (let ((termination
                       (if (and max-messages (zerop max-messages))
                           (progn
                             (send-close :code 1000)
                             :max-messages)
                           (catch close-tag
                             (loop
                               (multiple-value-bind (payload opcode)
                                   (read-websocket-message
                                    stream
                                    :max-message-bytes max-message-bytes
                                    :max-payload-bytes max-payload-bytes
                                    :require-mask-p require-mask-p
                                    :allow-unmasked-p allow-unmasked-p
                                    :on-control #'handle-control)
                                 (incf message-count)
                                 (when (eq :close
                                           (funcall handler
                                                    stream payload opcode))
                                   (send-close :code 1000)
                                   (return :handler-close))
                                 (when (and max-messages
                                            (>= message-count max-messages))
                                   (send-close :code 1000)
                                   (return :max-messages))))))))
                 (values message-count termination))
             (error (condition)
               (when close-on-error-p
                 (%websocket-with-cleanup
                   (send-close
                    :code (%websocket-session-close-code condition)
                    :reason "WebSocket session error")))
               (when on-error
                 (funcall on-error condition))
               (error condition)))
        (when close-stream
          (funcall close-stream stream))))))
