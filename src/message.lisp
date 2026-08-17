(in-package #:websocket-kit)

(defun websocket-valid-close-code-p (code)
  (and (integerp code)
       (or (member code '(1000 1001 1002 1003 1007 1008
                          1009 1010 1011 1012 1013 1014)
                       :test #'=)
           (<= 3000 code 4999))))

(defun %websocket-utf8-continuation-p (byte)
  (<= #x80 byte #xbf))

(defun %websocket-utf8-error (invalid-data-p message &optional detail)
  (if invalid-data-p
      (%websocket-invalid-data-error message detail)
      (%websocket-protocol-error message detail)))

(defun %websocket-utf8-string (octets &key invalid-data-p)
  (unless (%websocket-octet-vector-p octets)
    (%websocket-utf8-error invalid-data-p
                           "A WebSocket reason must be UTF-8 octets."
                           octets))
  (with-output-to-string (result)
    (loop with index = 0
          while (< index (length octets))
          do (let ((first (aref octets index)))
               (cond ((<= first #x7f)
                      (write-char (code-char first) result)
                      (incf index))
                     ((<= #xc2 first #xdf)
                      (when (> (1+ index) (1- (length octets)))
                        (%websocket-utf8-error
                         invalid-data-p
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index))))
                        (unless (%websocket-utf8-continuation-p second)
                          (%websocket-utf8-error
                           invalid-data-p
                           "A WebSocket close reason contains invalid UTF-8."
                           octets))
                        (write-char
                         (code-char (+ (ash (logand first #x1f) 6)
                                       (logand second #x3f)))
                         result)
                        (incf index 2)))
                     ((<= #xe0 first #xef)
                      (when (> (+ index 2) (1- (length octets)))
                        (%websocket-utf8-error
                         invalid-data-p
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index)))
                            (third (aref octets (+ index 2))))
                        (unless (and (%websocket-utf8-continuation-p second)
                                     (%websocket-utf8-continuation-p third)
                                     (or (/= first #xe0) (>= second #xa0))
                                     (or (/= first #xed) (<= second #x9f)))
                          (%websocket-utf8-error
                           invalid-data-p
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
                        (%websocket-utf8-error
                         invalid-data-p
                         "A WebSocket close reason ended in a partial UTF-8 sequence."))
                      (let ((second (aref octets (1+ index)))
                            (third (aref octets (+ index 2)))
                            (fourth (aref octets (+ index 3))))
                        (unless (and (%websocket-utf8-continuation-p second)
                                     (%websocket-utf8-continuation-p third)
                                     (%websocket-utf8-continuation-p fourth)
                                     (or (/= first #xf0) (>= second #x90))
                                     (or (/= first #xf4) (<= second #x8f)))
                          (%websocket-utf8-error
                           invalid-data-p
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
                      (%websocket-utf8-error
                       invalid-data-p
                       "A WebSocket close reason contains invalid UTF-8."
                       octets)))))))

(defun make-websocket-close-payload (&key (code 1000) (reason ""))
  "Construct the payload for a WebSocket close control frame."
  (unless (websocket-valid-close-code-p code)
    (%websocket-protocol-error "The WebSocket close code is not permitted." code))
  (unless (stringp reason)
    (%websocket-protocol-error "The WebSocket close reason must be a string." reason))
  (when (> (length reason) 123)
    (%websocket-size-error
     "A WebSocket close reason cannot fit within its 123-octet limit."
     123 (length reason)))
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
           (values code
                   (%websocket-utf8-string
                    (subseq payload 2)
                    :invalid-data-p t))))))

(defun %websocket-append-octets (target source)
  (let* ((old-length (fill-pointer target))
         (source-length (length source))
         (new-length (+ old-length source-length)))
    (when (plusp source-length)
      (when (> new-length (array-total-size target))
        (setf target
              (adjust-array
               target
               (max new-length
                    (max 1 (* 2 (array-total-size target))))
               :fill-pointer old-length)))
      (setf (fill-pointer target) new-length)
      (replace target source :start1 old-length))
    target))

(defun %websocket-validate-payload-transformer (transformer name)
  (when (and transformer (not (functionp transformer)))
    (%websocket-protocol-error
     (format nil "~A must be a function or NIL." name)
     transformer))
  transformer)

(defun %websocket-validate-frame-validator (validator)
  (when (and validator (not (functionp validator)))
    (%websocket-protocol-error
     "FRAME-VALIDATOR must be a function or NIL."
     validator))
  validator)

(defun %websocket-decode-payload
    (payload frame decoder max-message-bytes)
  (if decoder
      (let ((decoded
              (funcall decoder (%websocket-copy-octets payload) frame)))
        (unless (%websocket-octet-vector-p decoded)
          (%websocket-protocol-error
           "A WebSocket payload decoder must return an octet vector."
           decoded))
        (when (> (length decoded) max-message-bytes)
          (%websocket-size-error
           "A decoded WebSocket payload exceeded its message size limit."
           max-message-bytes (length decoded)))
        (%websocket-copy-octets decoded))
      payload))

(defun %websocket-read-message
    (stream &key max-message-bytes max-payload-bytes max-fragments
                  max-control-frames allowed-reserved-bits require-mask-p
                  allow-unmasked-p require-unmasked-p on-control
                  payload-decoder before-frame after-frame frame-validator)
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (%websocket-validate-limit max-fragments "MAX-FRAGMENTS")
  (%websocket-validate-limit max-control-frames "MAX-CONTROL-FRAMES")
  (%websocket-validate-reserved-bits
   allowed-reserved-bits "ALLOWED-RESERVED-BITS")
  (when (and on-control (not (functionp on-control)))
    (%websocket-protocol-error "ON-CONTROL must be a function or NIL." on-control))
  (%websocket-validate-payload-transformer
   payload-decoder "PAYLOAD-DECODER")
  (%websocket-validate-frame-validator frame-validator)
  (let ((message-opcode nil)
        (fragment-count 0)
        (control-frame-count 0)
        (message (make-array 0
                             :element-type '(unsigned-byte 8)
                             :adjustable t
                             :fill-pointer 0)))
    (loop
      (when before-frame
        (funcall before-frame))
      (let ((frame (read-websocket-frame
                    stream
                    :max-payload-bytes max-payload-bytes
                    :allowed-reserved-bits allowed-reserved-bits
                    :require-mask-p require-mask-p
                    :allow-unmasked-p allow-unmasked-p
                    :require-unmasked-p require-unmasked-p)))
        (when frame-validator
          (funcall frame-validator frame))
        (when after-frame
          (funcall after-frame frame))
        (let ((opcode (websocket-frame-opcode frame))
              (payload (websocket-frame-payload frame)))
          (when (and payload-decoder
                     (member opcode '(0 1 2) :test #'=))
            (setf payload (%websocket-decode-payload
                           payload frame payload-decoder
                           max-message-bytes)))
          (cond
            ((%websocket-control-opcode-p opcode)
             (incf control-frame-count)
             (when (> control-frame-count max-control-frames)
               (%websocket-size-error
                "A WebSocket message exceeded its control-frame limit."
                max-control-frames control-frame-count))
             (when (= opcode 8)
               (parse-websocket-close-payload payload))
             (cond
               ((= opcode 8)
                (when on-control
                  (funcall on-control frame))
                (return (values payload :close)))
               (on-control
                (funcall on-control frame))))
            ((zerop opcode)
             (unless message-opcode
               (%websocket-protocol-error
                "A WebSocket continuation frame has no initial data frame."))
             (incf fragment-count)
             (when (> fragment-count max-fragments)
               (%websocket-size-error
                "A WebSocket message exceeded its fragment limit."
                max-fragments fragment-count))
             (when (> (+ (fill-pointer message) (length payload))
                      max-message-bytes)
               (%websocket-size-error
                "A WebSocket message exceeded its size limit."
                max-message-bytes
                (+ (fill-pointer message) (length payload))))
             (setf message (%websocket-append-octets message payload))
             (when (websocket-frame-fin-p frame)
               (let ((result (subseq message 0 (fill-pointer message))))
                 (when (= message-opcode 1)
                   (%websocket-utf8-string result :invalid-data-p t))
                 (return (values result message-opcode)))))
            ((member opcode '(1 2) :test #'=)
             (when message-opcode
               (%websocket-protocol-error
                "A WebSocket data frame arrived before the prior message ended."
                opcode))
             (incf fragment-count)
             (when (> fragment-count max-fragments)
               (%websocket-size-error
                "A WebSocket message exceeded its fragment limit."
                max-fragments fragment-count))
             (setf message-opcode opcode)
             (when (> (length payload) max-message-bytes)
               (%websocket-size-error
                "A WebSocket message exceeded its size limit."
                max-message-bytes (length payload)))
             (setf message (%websocket-append-octets message payload))
             (when (websocket-frame-fin-p frame)
               (let ((result (subseq message 0 (fill-pointer message))))
                 (when (= message-opcode 1)
                   (%websocket-utf8-string result :invalid-data-p t))
                 (return (values result message-opcode)))))
            (t
             (%websocket-protocol-error
              "A WebSocket message encountered an invalid data opcode."
              opcode))))))))

(defun read-websocket-message
    (stream &key (max-message-bytes +websocket-default-max-payload-bytes+)
                  (max-payload-bytes +websocket-default-max-payload-bytes+)
                  (max-fragments +websocket-default-max-fragments+)
                  (max-control-frames +websocket-default-max-control-frames+)
                  (allowed-reserved-bits 0)
                  (require-mask-p nil) (allow-unmasked-p t)
                  (require-unmasked-p nil) on-control
                  payload-decoder
                  frame-validator
                  timeout deadline
                  (clock-function #'%websocket-monotonic-time))
  "Read one fragmented WebSocket data message.

Returns the message payload octets and its data opcode (1 for text or 2 for
binary).  Control frames are delivered to ON-CONTROL, when supplied.  Ping
and Pong frames are otherwise consumed while the data message is assembled;
a Close frame without ON-CONTROL returns its payload and the opcode :CLOSE.
MAX-FRAGMENTS limits data and continuation frames in this message, and
MAX-CONTROL-FRAMES limits Ping, Pong, and Close frames consumed while reading
it. PAYLOAD-DECODER receives each data-frame payload and frame, and must
return the application payload octets.  Each decoded payload is checked
against MAX-MESSAGE-BYTES before it is copied into the assembled message.
ALLOWED-RESERVED-BITS enables only
RSV bits already authorized by a negotiated extension. FRAME-VALIDATOR, when
supplied, is called with each parsed frame before payload decoding or message
assembly. TIMEOUT is relative to CLOCK-FUNCTION, while DEADLINE is an absolute
CLOCK-FUNCTION value."
  (let* ((clock (%websocket-network-clock clock-function))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock)))
    (%websocket-call-with-deadline
     (lambda ()
       (%websocket-read-message
        stream
        :max-message-bytes max-message-bytes
        :max-payload-bytes max-payload-bytes
        :max-fragments max-fragments
        :max-control-frames max-control-frames
        :allowed-reserved-bits allowed-reserved-bits
        :require-mask-p require-mask-p
        :allow-unmasked-p allow-unmasked-p
        :require-unmasked-p require-unmasked-p
        :on-control on-control
        :payload-decoder payload-decoder
        :frame-validator frame-validator))
     effective-deadline clock :websocket-receive)))

(defun %websocket-message-octets (payload opcode)
  (cond ((%websocket-octet-vector-p payload)
         (when (= opcode 1)
           (%websocket-utf8-string payload))
         (%websocket-copy-octets payload))
        ((and (= opcode 1) (stringp payload))
         (%websocket-utf8-octets payload))
        (t
         (%websocket-protocol-error
          "A WebSocket data message must be octets, or a text string for opcode 1."
          payload))))

(defun %websocket-encode-message-payload (payload opcode encoder)
  (let ((octets (%websocket-message-octets payload opcode)))
    (if encoder
        (let ((encoded
                (funcall encoder (%websocket-copy-octets octets) opcode)))
          (unless (%websocket-octet-vector-p encoded)
            (%websocket-protocol-error
             "A WebSocket payload encoder must return an octet vector."
             encoded))
          (%websocket-copy-octets encoded))
        octets)))

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

(defun %write-websocket-message
    (stream payload &key (opcode 2)
                   (max-message-bytes +websocket-default-max-payload-bytes+)
                   (max-frame-payload-bytes 65535)
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t) (reserved-bits 0) payload-encoder)
  (unless (member opcode '(1 2) :test #'=)
    (%websocket-protocol-error
     "A WebSocket message opcode must be 1 (text) or 2 (binary)."
     opcode))
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-positive-limit max-frame-payload-bytes
                              "MAX-FRAME-PAYLOAD-BYTES")
  (%websocket-validate-reserved-bits reserved-bits "RESERVED-BITS")
  (%websocket-validate-payload-transformer
   payload-encoder "PAYLOAD-ENCODER")
  (let* ((octets (%websocket-encode-message-payload
                  payload opcode payload-encoder))
         (payload-length (length octets))
         (frame-count (max 1 (ceiling payload-length
                                      max-frame-payload-bytes))))
    (when (> payload-length max-message-bytes)
      (%websocket-size-error
       "A WebSocket message exceeded its size limit."
       max-message-bytes payload-length))
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
                              :reserved-bits (if first-p reserved-bits 0)
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

(defun write-websocket-message
    (stream payload &key (opcode 2)
                   (max-message-bytes +websocket-default-max-payload-bytes+)
                   (max-frame-payload-bytes 65535)
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t) (reserved-bits 0) payload-encoder
                   timeout deadline
                   (clock-function #'%websocket-monotonic-time))
  "Write one text or binary WebSocket message.

PAYLOAD may be an octet vector, or a string when OPCODE is 1.  Large payloads
are fragmented into frames no larger than MAX-FRAME-PAYLOAD-BYTES.  When
MASK-P is true, MASKING-KEY-FUNCTION is called once per frame and must return
four octets; a single MASKING-KEY is accepted only when one frame is emitted.
PAYLOAD-ENCODER receives the complete normalized message octets and its data
opcode before fragmentation, and must return the encoded octets. The encoded
message must not exceed MAX-MESSAGE-BYTES. RESERVED-BITS are emitted only on
the first data frame. TIMEOUT is a relative limit and DEADLINE is an absolute
clock value. Returns the number of frames and the payload length."
  (let ((effective-deadline
          (%websocket-effective-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
       (%write-websocket-message
       stream payload
        :opcode opcode
        :max-message-bytes max-message-bytes
        :max-frame-payload-bytes max-frame-payload-bytes
        :mask-p mask-p
        :masking-key masking-key
        :masking-key-function masking-key-function
        :finish-output-p finish-output-p
        :reserved-bits reserved-bits
        :payload-encoder payload-encoder))
     effective-deadline clock-function :websocket-message)))

(defun %write-websocket-control-frame
    (stream opcode payload &key (mask-p nil) masking-key masking-key-function
                         (finish-output-p t) timeout deadline
                         (clock-function #'%websocket-monotonic-time))
  (let ((effective-deadline
          (%websocket-effective-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
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
     effective-deadline clock-function :websocket-control-frame)))

(defun websocket-ping
    (stream &key (payload (make-array 0 :element-type '(unsigned-byte 8)))
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t) timeout deadline
                   (clock-function #'%websocket-monotonic-time))
  "Write a final WebSocket Ping control frame."
  (%write-websocket-control-frame
   stream 9 payload
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-pong
    (stream &key (payload (make-array 0 :element-type '(unsigned-byte 8)))
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t) timeout deadline
                   (clock-function #'%websocket-monotonic-time))
  "Write a final WebSocket Pong control frame."
  (%write-websocket-control-frame
   stream 10 payload
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-close
    (stream &key payload code reason
                   (mask-p nil) masking-key masking-key-function
                   (finish-output-p t) timeout deadline
                   (clock-function #'%websocket-monotonic-time))
  "Write a WebSocket Close control frame.

When PAYLOAD is supplied it is used as the already encoded close payload and
CODE and REASON must be NIL.  Otherwise CODE defaults to 1000 and REASON to
the empty string."
  (when (and payload (or code reason))
    (%websocket-protocol-error
     "A raw WebSocket close payload cannot be combined with CODE or REASON."))
  (when payload
    (parse-websocket-close-payload payload))
  (%write-websocket-control-frame
   stream 8
   (or payload (make-websocket-close-payload :code (or code 1000)
                                     :reason (or reason "")))
   :mask-p mask-p
   :masking-key masking-key
   :masking-key-function masking-key-function
   :finish-output-p finish-output-p
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun %websocket-session-close-code (condition)
  (cond ((typep condition 'websocket-invalid-data) 1007)
        ((typep condition 'websocket-size-limit-exceeded) 1009)
        ((typep condition 'websocket-timeout) 1001)
        ((typep condition 'websocket-error) 1002)
        (t 1011)))

(defun serve-websocket-session
    (stream handler &key
                     (max-message-bytes +websocket-default-max-payload-bytes+)
                     (max-payload-bytes +websocket-default-max-payload-bytes+)
                     (max-fragments +websocket-default-max-fragments+)
                     (max-control-frames +websocket-default-max-control-frames+)
                     (allowed-reserved-bits 0)
                     payload-decoder
                     frame-validator
                     max-frames
                     (max-messages nil)
                     (require-mask-p t)
                     (allow-unmasked-p nil)
                     (require-unmasked-p nil)
                     on-control
                     on-error
                     (close-on-error-p t)
                     (close-stream #'close)
                     write-guard
                     timeout deadline
                     idle-timeout heartbeat-interval heartbeat-timeout
                     (clock-function #'%websocket-monotonic-time))
  "Serve messages on an already-upgraded WebSocket STREAM.

HANDLER is called as (STREAM PAYLOAD OPCODE) for every complete text or
binary message.  It may return :CLOSE to start a normal close handshake.
The server automatically replies to Ping frames and echoes a valid peer
Close frame.  Client frames are required to be masked by default.

The function returns two values: the number of messages delivered and a
termination keyword (:PEER-CLOSE, :HANDLER-CLOSE, :MAX-MESSAGES,
:MAX-FRAMES, :IDLE-TIMEOUT, or :HEARTBEAT-TIMEOUT).  MAX-FRAGMENTS and
MAX-CONTROL-FRAMES bound each message; MAX-FRAMES, when non-NIL, bounds all
frames read from the connection.  ALLOWED-RESERVED-BITS enables only RSV bits
already authorized by a negotiated extension.  IDLE-TIMEOUT closes a session
that receives no frame for the specified interval.  HEARTBEAT-INTERVAL sends
an application-independent Ping when the session is otherwise idle;
HEARTBEAT-TIMEOUT defaults to that interval and closes the session when its
matching Pong is not received in time.  A fragmented message remains in local
state while the heartbeat timer is serviced, so control frames can be handled
without discarding the message.  On a protocol, size, or handler error it sends
an appropriate Close frame when CLOSE-ON-ERROR-P is true, invokes ON-ERROR with
the condition, and re-signals the condition.  TIMEOUT is relative to
CLOCK-FUNCTION, while DEADLINE is an absolute CLOCK-FUNCTION value; either is
checked before each receive/control operation and signals WEBSOCKET-TIMEOUT
when exceeded.  Handler execution is not interrupted by this deadline.
PAYLOAD-DECODER receives each data-frame payload and frame, and must return the
application payload octets before message limits and HANDLER are applied.  A
decoded payload larger than MAX-MESSAGE-BYTES is rejected before message
assembly; the decoder remains responsible for bounding its own temporary
allocations.
FRAME-VALIDATOR, when supplied, is called with each parsed frame before
payload decoding or message assembly.
WRITE-GUARD, when non-NIL, is called as (WRITE-GUARD THUNK) around every
library-generated control-frame write.  It can coordinate automatic Pong,
Ping, and Close frames with application writes on the same connection.
CLOSE-STREAM is called at the end unless it is NIL, which is useful when the
caller owns the upgraded stream lifecycle."
  (unless (streamp stream)
    (%websocket-protocol-error
     "A WebSocket session requires a stream." stream))
  (unless (functionp handler)
    (%websocket-protocol-error
     "A WebSocket session handler must be callable." handler))
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (%websocket-validate-limit max-fragments "MAX-FRAGMENTS")
  (%websocket-validate-limit max-control-frames "MAX-CONTROL-FRAMES")
  (%websocket-validate-reserved-bits
   allowed-reserved-bits "ALLOWED-RESERVED-BITS")
  (%websocket-validate-payload-transformer
   payload-decoder "PAYLOAD-DECODER")
  (%websocket-validate-frame-validator frame-validator)
  (when max-frames
    (%websocket-validate-limit max-frames "MAX-FRAMES"))
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
  (when (and write-guard (not (functionp write-guard)))
    (%websocket-protocol-error
     "WRITE-GUARD must be a function or NIL." write-guard))
  (flet ((validate-duration (value name positive-p)
           (when (and value
                      (or (not (realp value))
                          (if positive-p
                              (not (plusp value))
                              (minusp value))))
             (%websocket-protocol-error
              (format nil "~A must be NIL or a ~A real number."
                      name (if positive-p "positive" "non-negative"))
              value))))
    (validate-duration idle-timeout "IDLE-TIMEOUT" nil)
    (validate-duration heartbeat-interval "HEARTBEAT-INTERVAL" t)
    (validate-duration heartbeat-timeout "HEARTBEAT-TIMEOUT" t))
  (when (and heartbeat-timeout (null heartbeat-interval))
    (%websocket-protocol-error
     "HEARTBEAT-TIMEOUT requires HEARTBEAT-INTERVAL."
     heartbeat-timeout))
  (let* ((clock (%websocket-network-clock clock-function))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock))
         (effective-heartbeat-timeout
           (or heartbeat-timeout heartbeat-interval))
         (started-at (funcall clock)))
    (let ((message-count 0)
          (frame-count 0)
          (close-sent-p nil)
          (close-tag (gensym "WEBSOCKET-CLOSE-"))
          (message-opcode nil)
          (fragment-count 0)
          (control-frame-count 0)
          (message (make-array 0
                               :element-type '(unsigned-byte 8)
                               :adjustable t
                               :fill-pointer 0))
          (last-activity started-at)
          (next-heartbeat-deadline
            (and heartbeat-interval
                 (+ started-at heartbeat-interval)))
          (heartbeat-deadline nil)
          (heartbeat-payload nil)
          (heartbeat-sequence 0)
          (operation-deadline nil))
    (labels ((earliest-deadline (&rest deadlines)
               (let ((result nil))
                 (dolist (candidate deadlines result)
                   (when (and candidate
                              (or (null result) (< candidate result)))
                     (setf result candidate)))))
             (guard-write (thunk)
               (if write-guard
                   (funcall write-guard thunk)
                   (funcall thunk)))
             (close-deadline (now)
               (when (and effective-deadline
                          (> effective-deadline now))
                 effective-deadline))
             (reset-message ()
               (setf message-opcode nil
                     fragment-count 0
                     control-frame-count 0
                     message (make-array 0
                                         :element-type '(unsigned-byte 8)
                                         :adjustable t
                                         :fill-pointer 0)))
             (next-heartbeat-payload ()
               (incf heartbeat-sequence)
               (let ((payload (make-array 8
                                          :element-type '(unsigned-byte 8))))
                 (loop for index from 0 below 8
                       for shift downfrom 56 by 8
                       do (setf (aref payload index)
                                (ldb (byte 8 shift)
                                     heartbeat-sequence)))
                 payload))
             (send-close (&key payload code reason deadline)
               (unless close-sent-p
                 (setf close-sent-p t)
                 (guard-write
                  (lambda ()
                    (if payload
                        (websocket-close stream
                                         :payload payload
                                         :deadline (or deadline
                                                        effective-deadline)
                                         :clock-function clock)
                        (websocket-close stream
                                         :code (or code 1000)
                                         :reason (or reason "")
                                         :deadline (or deadline
                                                        effective-deadline)
                                         :clock-function clock))))))
             (start-heartbeat (now)
               (setf heartbeat-payload (next-heartbeat-payload)
                     heartbeat-deadline (+ now effective-heartbeat-timeout)
                     next-heartbeat-deadline nil)
               (guard-write
                (lambda ()
                  (websocket-ping stream
                                  :payload heartbeat-payload
                                  :deadline
                                  (earliest-deadline effective-deadline
                                                      heartbeat-deadline)
                                  :clock-function clock))))
             (handle-control (frame)
              (let ((opcode (websocket-frame-opcode frame))
                     (payload (websocket-frame-payload frame)))
                 (when on-control
                   (funcall on-control frame))
                 (case opcode
                   (9
                    (guard-write
                     (lambda ()
                       (websocket-pong stream
                                       :payload payload
                                       :deadline operation-deadline
                                       :clock-function clock))))
                   (8
                    (parse-websocket-close-payload payload)
                    (send-close :payload payload
                                :deadline operation-deadline)
                    (throw close-tag :peer-close))
                   (10
                    (when (and heartbeat-deadline
                               heartbeat-payload
                               (equalp payload heartbeat-payload))
                      (setf heartbeat-deadline nil
                            heartbeat-payload nil
                            next-heartbeat-deadline
                            (+ (funcall clock) heartbeat-interval)))))))
             (process-timers ()
               (let ((now (funcall clock)))
                 (when (and effective-deadline
                            (>= now effective-deadline))
                   (error 'websocket-timeout
                          :kind :websocket-session
                          :operation :websocket-session
                          :message
                          "The WebSocket session exceeded its deadline."
                          :detail :websocket-session))
                 (cond
                   ((and idle-timeout
                         (>= now (+ last-activity idle-timeout)))
                    (send-close
                     :code 1001
                     :reason "Idle timeout"
                     :deadline (close-deadline now))
                    (values t :idle-timeout))
                   ((and heartbeat-deadline
                         (>= now heartbeat-deadline))
                    (send-close
                     :code 1001
                     :reason "Heartbeat timeout"
                     :deadline (close-deadline now))
                    (values t :heartbeat-timeout))
                   ((and next-heartbeat-deadline
                         (>= now next-heartbeat-deadline)
                         (null heartbeat-deadline))
                    (start-heartbeat now)
                    (values t nil))
                   (t
                    (values nil nil)))))
             (read-session-event ()
               (when (and max-frames (>= frame-count max-frames))
                 (%websocket-size-error
                  "A WebSocket session exceeded its frame limit."
                  max-frames frame-count))
               (let ((frame (read-websocket-frame
                             stream
                             :max-payload-bytes max-payload-bytes
                             :allowed-reserved-bits allowed-reserved-bits
                             :require-mask-p require-mask-p
                             :allow-unmasked-p allow-unmasked-p
                             :require-unmasked-p require-unmasked-p)))
                 (when frame-validator
                   (funcall frame-validator frame))
                 (incf frame-count)
                 (setf last-activity (funcall clock))
                 (let ((opcode (websocket-frame-opcode frame))
                       (payload (websocket-frame-payload frame)))
                   (when (and payload-decoder
                              (member opcode '(0 1 2) :test #'=))
                     (setf payload (%websocket-decode-payload
                                    payload frame payload-decoder
                                    max-message-bytes)))
                   (cond
                     ((%websocket-control-opcode-p opcode)
                      (incf control-frame-count)
                      (when (> control-frame-count max-control-frames)
                        (%websocket-size-error
                         "A WebSocket message exceeded its control-frame limit."
                         max-control-frames control-frame-count))
                      (when (= opcode 8)
                        (parse-websocket-close-payload payload))
                      (values :control frame nil))
                     ((zerop opcode)
                      (unless message-opcode
                        (%websocket-protocol-error
                         "A WebSocket continuation frame has no initial data frame."))
                      (incf fragment-count)
                      (when (> fragment-count max-fragments)
                        (%websocket-size-error
                         "A WebSocket message exceeded its fragment limit."
                         max-fragments fragment-count))
                      (when (> (+ (fill-pointer message) (length payload))
                               max-message-bytes)
                        (%websocket-size-error
                         "A WebSocket message exceeded its size limit."
                         max-message-bytes
                         (+ (fill-pointer message) (length payload))))
                      (setf message (%websocket-append-octets message payload))
                      (if (websocket-frame-fin-p frame)
                          (let ((result (subseq message 0
                                                (fill-pointer message)))
                                (result-opcode message-opcode))
                            (when (= result-opcode 1)
                              (%websocket-utf8-string result :invalid-data-p t))
                            (reset-message)
                            (values :message result result-opcode))
                          (values :partial nil nil)))
                     ((member opcode '(1 2) :test #'=)
                      (when message-opcode
                        (%websocket-protocol-error
                         "A WebSocket data frame arrived before the prior message ended."
                         opcode))
                      (incf fragment-count)
                      (when (> fragment-count max-fragments)
                        (%websocket-size-error
                         "A WebSocket message exceeded its fragment limit."
                         max-fragments fragment-count))
                      (setf message-opcode opcode)
                      (when (> (length payload) max-message-bytes)
                        (%websocket-size-error
                         "A WebSocket message exceeded its size limit."
                         max-message-bytes (length payload)))
                      (setf message (%websocket-append-octets message payload))
                      (if (websocket-frame-fin-p frame)
                          (let ((result (subseq message 0
                                                (fill-pointer message)))
                                (result-opcode message-opcode))
                            (when (= result-opcode 1)
                              (%websocket-utf8-string result :invalid-data-p t))
                            (reset-message)
                            (values :message result result-opcode))
                          (values :partial nil nil)))
                     (t
                      (%websocket-protocol-error
                       "A WebSocket message encountered an invalid data opcode."
                       opcode)))))))
      (unwind-protect
           (handler-case
               (let ((termination
                       (cond ((and max-frames (zerop max-frames))
                              (send-close :code 1009)
                              :max-frames)
                             ((and max-messages (zerop max-messages))
                             (send-close :code 1000)
                             :max-messages)
                             (t
                              (catch close-tag
                                (loop
                                  (multiple-value-bind (timer-handled timer-result)
                                      (process-timers)
                                    (declare (ignore timer-handled))
                                    (when timer-result
                                      (return timer-result)))
                                  (setf operation-deadline
                                        (earliest-deadline
                                         effective-deadline
                                         (and idle-timeout
                                              (+ last-activity idle-timeout))
                                         heartbeat-deadline
                                         next-heartbeat-deadline))
                                  (handler-case
                                      (multiple-value-bind (event payload opcode)
                                          (%websocket-call-with-deadline
                                           #'read-session-event
                                           operation-deadline clock
                                           :websocket-session)
                                        (case event
                                          (:control
                                           (handle-control payload))
                                          (:message
                                           (incf message-count)
                                           (when (eq :close
                                                     (funcall handler
                                                              stream payload
                                                              opcode))
                                             (send-close :code 1000)
                                             (return :handler-close))
                                           (when (and max-frames
                                                      (>= frame-count max-frames))
                                             (send-close :code 1009)
                                             (return :max-frames))
                                           (when (and max-messages
                                                      (>= message-count
                                                          max-messages))
                                             (send-close :code 1000)
                                             (return :max-messages)))))
                                    (websocket-timeout (condition)
                                      (multiple-value-bind
                                            (timer-handled timer-result)
                                          (process-timers)
                                        (cond
                                          (timer-result
                                           (return timer-result))
                                          (timer-handled nil)
                                          (t
                                           (error condition))))))))))))
                 (values message-count termination))
             (error (condition)
               (unless (typep condition 'websocket-transport-error)
                 (when close-on-error-p
                   (%websocket-with-cleanup
                     (send-close
                      :code (%websocket-session-close-code condition)
                      :reason "WebSocket session error"))))
               (when on-error
                 (funcall on-error condition))
               (error condition)))
        (when close-stream
          (funcall close-stream stream)))))))
