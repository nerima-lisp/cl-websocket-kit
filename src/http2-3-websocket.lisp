(in-package #:websocket-kit)

(defun %websocket-http2-3-message-frame-wire
    (payload &key (opcode 2) (max-frame-payload-bytes 65535)
                   (mask-p nil) masking-key masking-key-function
                   (reserved-bits 0) payload-encoder
                   (max-message-bytes
                    +websocket-default-max-payload-bytes+))
  (unless (member opcode '(1 2) :test #'=)
    (%websocket-protocol-error
     "A WebSocket message opcode must be 1 (text) or 2 (binary)."
     opcode))
  (%websocket-positive-limit max-frame-payload-bytes
                              "MAX-FRAME-PAYLOAD-BYTES")
  (%websocket-validate-reserved-bits reserved-bits "RESERVED-BITS")
  (%websocket-validate-payload-transformer
   payload-encoder "PAYLOAD-ENCODER")
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (let* ((octets (%websocket-encode-message-payload
                  payload opcode payload-encoder))
         (payload-length (length octets))
         (frame-count (max 1 (ceiling payload-length
                                      max-frame-payload-bytes)))
         (position 0)
         (frame-index 0)
         (first-p t)
         (frames nil))
    (when (> payload-length max-message-bytes)
      (%websocket-size-error
       "The encoded WebSocket message exceeds the selected size limit."
       max-message-bytes
       payload-length))
    (%websocket-masking-options mask-p masking-key masking-key-function)
    (when (and mask-p (> frame-count 1) masking-key)
      (%websocket-protocol-error
       "Fragmented masked output requires a masking-key function so each frame has a fresh key."))
    (loop while (or first-p (< position payload-length))
          do (let* ((remaining (- payload-length position))
                    (chunk-length (min max-frame-payload-bytes remaining))
                    (last-p (= (+ position chunk-length) payload-length))
                    (frame
                      (make-websocket-frame
                       :fin-p last-p
                       :opcode (if (zerop frame-index) opcode 0)
                       :reserved-bits (if first-p reserved-bits 0)
                       :mask-p mask-p
                       :masking-key
                       (%websocket-next-masking-key
                        mask-p masking-key masking-key-function)
                       :payload
                       (subseq octets position (+ position chunk-length)))))
               (push (serialize-websocket-frame frame) frames)
               (incf frame-index)
               (setf position (+ position chunk-length)
                     first-p nil)))
    (nreverse frames)))

(defun %websocket-http2-3-ensure-data-octets (octets)
  (unless (%websocket-octet-vector-p octets)
    (%websocket-http2-3-fail
     "HTTP/2 or HTTP/3 WebSocket DATA must be a vector of octets."
     :detail octets))
  octets)

(defun %websocket-http2-3-collect-http2-data
    (octets &key expected-stream-id
                  (max-data-bytes +websocket-default-max-payload-bytes+)
                  (max-data-frames +websocket-default-max-fragments+)
                  (max-frame-size +websocket-http2-default-max-frame-size+))
  (%websocket-http2-3-ensure-data-octets octets)
  (%websocket-validate-limit max-data-bytes "MAX-DATA-BYTES")
  (%websocket-positive-limit max-data-frames "MAX-DATA-FRAMES")
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (when (zerop (length octets))
    (%websocket-http2-3-fail
     "An HTTP/2 WebSocket DATA sequence cannot be empty."))
  (when expected-stream-id
    (%websocket-http2-3-check-http2-stream-id expected-stream-id))
  (let ((position 0)
        (stream-id nil)
        (parts nil)
        (end-stream-p nil)
        (data-frame-count 0)
        (data-bytes 0))
    (loop while (< position (length octets))
          do (when (>= data-frame-count max-data-frames)
               (%websocket-size-error
                "An HTTP/2 WebSocket DATA sequence exceeded its frame-count limit."
                max-data-frames
                (1+ data-frame-count)))
             (multiple-value-bind (payload used frame-stream-id frame-end-stream-p)
                 (decode-websocket-http2-data-frame
                  (subseq octets position)
                  :expected-stream-id
                  (if (null stream-id) expected-stream-id stream-id)
                  :max-frame-size max-frame-size)
               (when (and (not (null stream-id))
                          (/= stream-id frame-stream-id))
                 (%websocket-http2-3-fail
                  "An HTTP/2 WebSocket DATA sequence changed streams."))
               (setf stream-id frame-stream-id
                     end-stream-p frame-end-stream-p)
               (incf data-frame-count)
               (incf data-bytes (length payload))
               (when (> data-bytes max-data-bytes)
                 (%websocket-size-error
                  "An HTTP/2 WebSocket DATA sequence exceeded its byte limit."
                  max-data-bytes
                  data-bytes))
               (push payload parts)
               (incf position used)
               (when frame-end-stream-p
                 (unless (= position (length octets))
                   (%websocket-http2-3-fail
                    "An HTTP/2 END_STREAM DATA frame was followed by more data."))
                 (return))))
    (values (%websocket-http2-3-append-octets (nreverse parts))
            position
            stream-id
            end-stream-p)))

(defun %websocket-http2-3-collect-http3-data
    (octets expected-stream-id
     &key (max-data-bytes +websocket-default-max-payload-bytes+)
          (max-data-frames +websocket-default-max-fragments+)
          (max-frame-size +websocket-http3-default-max-frame-size+))
  (%websocket-http2-3-ensure-data-octets octets)
  (%websocket-validate-limit max-data-bytes "MAX-DATA-BYTES")
  (%websocket-positive-limit max-data-frames "MAX-DATA-FRAMES")
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (unless (integerp expected-stream-id)
    (%websocket-http2-3-fail
     "HTTP/3 WebSocket DATA decoding requires the caller's stream identifier."
     :detail expected-stream-id))
  (%websocket-http2-3-check-http3-stream-id expected-stream-id)
  (when (zerop (length octets))
    (%websocket-http2-3-fail
     "An HTTP/3 WebSocket DATA sequence cannot be empty."))
  (let ((position 0)
        (parts nil)
        (data-frame-count 0)
        (data-bytes 0))
    (loop while (< position (length octets))
          do (when (>= data-frame-count max-data-frames)
               (%websocket-size-error
                "An HTTP/3 WebSocket DATA sequence exceeded its frame-count limit."
                max-data-frames
                (1+ data-frame-count)))
             (multiple-value-bind (payload used stream-id)
                 (decode-websocket-http3-data-frame
                  (subseq octets position)
                  :expected-stream-id expected-stream-id
                  :max-frame-size max-frame-size)
               (declare (ignore stream-id))
               (incf data-frame-count)
               (incf data-bytes (length payload))
               (when (> data-bytes max-data-bytes)
                 (%websocket-size-error
                  "An HTTP/3 WebSocket DATA sequence exceeded its byte limit."
                  max-data-bytes
                  data-bytes))
               (push payload parts)
               (incf position used)))
    (values (%websocket-http2-3-append-octets (nreverse parts))
            position
            expected-stream-id)))

(defun %websocket-http2-3-decode-message-frame-wire
    (octets &key (max-payload-bytes +websocket-default-max-payload-bytes+)
                   (require-mask-p nil) (allow-unmasked-p t)
                   (require-unmasked-p nil) (allowed-reserved-bits 0)
                   (max-frames +websocket-default-max-fragments+))
  (%websocket-http2-3-ensure-data-octets octets)
  (%websocket-positive-limit max-frames "MAX-FRAMES")
  (let ((position 0)
        (frame-count 0)
        (frames nil))
    (loop while (< position (length octets))
          do (when (>= frame-count max-frames)
               (%websocket-size-error
                "A WebSocket DATA sequence exceeded its frame-count limit."
                max-frames
                (1+ frame-count)))
             (multiple-value-bind (frame used)
                 (parse-websocket-frame
                  (subseq octets position)
                  :max-payload-bytes max-payload-bytes
                  :require-mask-p require-mask-p
                  :allow-unmasked-p allow-unmasked-p
                  :require-unmasked-p require-unmasked-p
                  :allowed-reserved-bits allowed-reserved-bits)
               (push frame frames)
               (incf frame-count)
               (incf position used)))
    (nreverse frames)))

(defun %websocket-http2-3-validate-message-sequence
    (frames &key (initial-fragmented-p nil) (require-complete-p nil))
  (unless (member initial-fragmented-p '(nil t))
    (%websocket-protocol-error
     "INITIAL-FRAGMENTED-P must be a generalized boolean."
     initial-fragmented-p))
  (let ((fragmented-p initial-fragmented-p)
        (close-seen-p nil))
    (dolist (frame frames)
      (let ((opcode (websocket-frame-opcode frame)))
        (when close-seen-p
          (%websocket-protocol-error
           "A WebSocket Close frame must be followed by no additional frames."))
        (cond
          ((member opcode '(1 2) :test #'=)
           (when fragmented-p
             (%websocket-protocol-error
              "A new WebSocket data message cannot start before a fragmented message finishes."
              opcode))
           (setf fragmented-p (not (websocket-frame-fin-p frame))))
          ((zerop opcode)
           (unless fragmented-p
             (%websocket-protocol-error
              "A WebSocket continuation frame has no fragmented message to continue."))
           (when (websocket-frame-fin-p frame)
             (setf fragmented-p nil)))
          ((= opcode 8)
           (parse-websocket-close-payload
            (websocket-frame-payload frame))
           (setf close-seen-p t))
          ((member opcode '(9 10) :test #'=)
           nil)
          (t
           (%websocket-protocol-error
            "A WebSocket message sequence contains an unsupported opcode."
            opcode)))))
    (when (and require-complete-p fragmented-p (not close-seen-p))
      (%websocket-protocol-error
       "The HTTP/2 WebSocket stream ended in a fragmented message."))
    frames))

(defun encode-websocket-http2-message-data-frames
    (payload stream-id &key (opcode 2) (max-frame-payload-bytes 65535)
                            (mask-p nil) masking-key masking-key-function
                            end-stream-p
                            (reserved-bits 0) payload-encoder
                            (max-message-bytes
                             +websocket-default-max-payload-bytes+)
                            (max-frame-size +websocket-http2-default-max-frame-size+))
  "Encode one RFC 6455 message into HTTP/2 DATA frames.

The WebSocket message is fragmented before the resulting wire octets are
split into HTTP/2 DATA frames.  MASK-P follows the RFC 6455 direction rule;
the bridge does not infer client or server role from the HTTP/2 stream.
MAX-MESSAGE-BYTES limits the encoded WebSocket message payload.  PAYLOAD-ENCODER
transforms the normalized message before fragmentation.  RESERVED-BITS are
emitted only on the first WebSocket data frame."
  (let ((wire (%websocket-http2-3-append-octets
               (%websocket-http2-3-message-frame-wire
                payload
                :opcode opcode
                :max-frame-payload-bytes max-frame-payload-bytes
                :mask-p mask-p
                :masking-key masking-key
                :masking-key-function masking-key-function
                :reserved-bits reserved-bits
                :payload-encoder payload-encoder
                :max-message-bytes max-message-bytes))))
    (encode-websocket-http2-data-frames
     wire stream-id
     :end-stream-p end-stream-p
     :max-frame-size max-frame-size)))

(defun decode-websocket-http2-websocket-data-frames
    (octets &key expected-stream-id
                   (max-payload-bytes +websocket-default-max-payload-bytes+)
                   (require-mask-p nil) (allow-unmasked-p t)
                   (require-unmasked-p nil) (allowed-reserved-bits 0)
                   (max-frames +websocket-default-max-fragments+)
                   (initial-fragmented-p nil)
                   (require-complete-p nil)
                   (max-data-bytes +websocket-default-max-payload-bytes+)
                   (max-data-frames +websocket-default-max-fragments+)
                   (max-frame-size +websocket-http2-default-max-frame-size+))
  "Decode HTTP/2 DATA frames containing RFC 6455 WebSocket frames.

  Returns the WebSocket frames, consumed HTTP octets, stream identifier, and
  the END_STREAM flag from the final DATA frame.  MAX-DATA-BYTES and
  MAX-DATA-FRAMES bound the HTTP/2 DATA sequence before WebSocket frames are
  decoded; MAX-FRAME-SIZE bounds each HTTP/2 DATA payload.
  INITIAL-FRAGMENTED-P indicates that the preceding DATA sequence ended in an
  unfinished WebSocket message, allowing this call to begin with a continuation
  frame.  A sequence ending with END_STREAM must finish that message.  When
  REQUIRE-COMPLETE-P is true, the sequence must finish a message even without
  END_STREAM."
  (multiple-value-bind (wire consumed stream-id end-stream-p)
      (%websocket-http2-3-collect-http2-data
       octets
       :expected-stream-id expected-stream-id
       :max-data-bytes max-data-bytes
       :max-data-frames max-data-frames
       :max-frame-size max-frame-size)
    (values
     (%websocket-http2-3-validate-message-sequence
      (%websocket-http2-3-decode-message-frame-wire
       wire
       :max-payload-bytes max-payload-bytes
       :require-mask-p require-mask-p
       :allow-unmasked-p allow-unmasked-p
       :require-unmasked-p require-unmasked-p
       :allowed-reserved-bits allowed-reserved-bits
       :max-frames max-frames)
      :initial-fragmented-p initial-fragmented-p
      :require-complete-p (or end-stream-p require-complete-p))
     consumed
     stream-id
     end-stream-p)))

(defun encode-websocket-http3-message-data-frames
    (payload stream-id &key (opcode 2) (max-frame-payload-bytes 65535)
                            (mask-p nil) masking-key masking-key-function
                            (reserved-bits 0) payload-encoder
                            (max-message-bytes
                             +websocket-default-max-payload-bytes+)
                            (max-frame-size +websocket-http3-default-max-frame-size+))
  "Encode one RFC 6455 message into HTTP/3 DATA frames.

HTTP/3 stream termination is controlled by the enclosing QUIC stream, so
this function does not add an END_STREAM equivalent to the DATA frames.
MAX-MESSAGE-BYTES limits the encoded WebSocket message payload.  PAYLOAD-ENCODER
transforms the normalized message before fragmentation.  RESERVED-BITS are
emitted only on the first WebSocket data frame."
  (let ((wire (%websocket-http2-3-append-octets
               (%websocket-http2-3-message-frame-wire
                payload
                :opcode opcode
                :max-frame-payload-bytes max-frame-payload-bytes
                :mask-p mask-p
                :masking-key masking-key
                :masking-key-function masking-key-function
                :reserved-bits reserved-bits
                :payload-encoder payload-encoder
                :max-message-bytes max-message-bytes))))
    (encode-websocket-http3-data-frames
     wire stream-id :max-frame-size max-frame-size)))

(defun decode-websocket-http3-websocket-data-frames
    (octets &key expected-stream-id
                   (max-payload-bytes +websocket-default-max-payload-bytes+)
                   (require-mask-p nil) (allow-unmasked-p t)
                   (require-unmasked-p nil) (allowed-reserved-bits 0)
                   (max-frames +websocket-default-max-fragments+)
                   (initial-fragmented-p nil)
                   (require-complete-p nil)
                   (max-data-bytes +websocket-default-max-payload-bytes+)
                   (max-data-frames +websocket-default-max-fragments+)
                   (max-frame-size +websocket-http3-default-max-frame-size+))
  "Decode HTTP/3 DATA frames containing RFC 6455 WebSocket frames.

  Returns the WebSocket frames, consumed HTTP octets, and the caller-supplied
  QUIC stream identifier.  MAX-DATA-BYTES and MAX-DATA-FRAMES bound the HTTP/3
  DATA sequence before WebSocket frames are decoded; MAX-FRAME-SIZE bounds each
  HTTP/3 DATA payload.  INITIAL-FRAGMENTED-P indicates that the preceding DATA
  sequence ended in an unfinished WebSocket message.  When REQUIRE-COMPLETE-P
  is true, the sequence must finish a message."
  (multiple-value-bind (wire consumed stream-id)
      (%websocket-http2-3-collect-http3-data
       octets expected-stream-id
       :max-data-bytes max-data-bytes
       :max-data-frames max-data-frames
       :max-frame-size max-frame-size)
    (values
     (%websocket-http2-3-validate-message-sequence
      (%websocket-http2-3-decode-message-frame-wire
       wire
       :max-payload-bytes max-payload-bytes
       :require-mask-p require-mask-p
       :allow-unmasked-p allow-unmasked-p
       :require-unmasked-p require-unmasked-p
       :allowed-reserved-bits allowed-reserved-bits
       :max-frames max-frames)
      :initial-fragmented-p initial-fragmented-p
      :require-complete-p require-complete-p)
     consumed
     stream-id)))
