(in-package #:websocket-kit)

(defconstant +websocket-default-max-payload-bytes+ (* 16 1024 1024))
(defconstant +websocket-default-max-fragments+ 1024)
(defconstant +websocket-default-max-control-frames+ 1024)

(defun %websocket-protocol-error (message &optional detail)
  (error 'websocket-protocol-error
         :message message
         :operation :websocket
         :detail detail))

(defun %websocket-invalid-data-error (message &optional detail)
  (error 'websocket-invalid-data
         :message message
         :operation :websocket
         :detail detail))

(defun %websocket-size-error (message limit observed)
  (error 'websocket-size-limit-exceeded
         :message message
         :operation :websocket
         :kind :websocket
         :limit limit
         :observed observed))

(defun %websocket-octet-vector-p (value)
  (and (arrayp value)
       (= (array-rank value) 1)
       (not (stringp value))
       (loop for octet across value
             always (and (integerp octet)
                         (<= 0 octet #xff)))))

(defun %websocket-copy-octets (value)
  (unless (%websocket-octet-vector-p value)
    (%websocket-protocol-error
     "WebSocket data must be a one-dimensional vector of octets."
     value))
  (let ((copy (make-array (length value)
                          :element-type '(unsigned-byte 8))))
    (replace copy value)
    copy))

(defun %websocket-empty-octets ()
  (make-array 0 :element-type '(unsigned-byte 8)))

(defun %websocket-control-opcode-p (opcode)
  (member opcode '(8 9 10) :test #'=))

(defun %websocket-valid-opcode-p (opcode)
  (member opcode '(0 1 2 8 9 10) :test #'=))

(defun %websocket-validate-limit (limit name)
  (unless (and (integerp limit) (<= 0 limit))
    (%websocket-protocol-error
     (format nil "~A must be a non-negative integer." name)
     limit))
  limit)

(defun %websocket-validate-reserved-bits (reserved-bits name)
  (unless (and (integerp reserved-bits)
               (<= 0 reserved-bits #x70)
               (zerop (logand reserved-bits #x0f)))
    (%websocket-protocol-error
     (format nil "~A must contain only WebSocket RSV bits." name)
     reserved-bits))
  reserved-bits)

(defun %websocket-validate-frame-components
    (fin-p opcode reserved-bits mask-p masking-key payload)
  (%websocket-validate-reserved-bits reserved-bits "RESERVED-BITS")
  (unless (and (integerp opcode)
               (%websocket-valid-opcode-p opcode))
    (%websocket-protocol-error
     "A WebSocket frame has an unsupported opcode."
     opcode))
  (unless (%websocket-octet-vector-p payload)
    (%websocket-protocol-error
     "A WebSocket frame payload must be a vector of octets."
     payload))
  (when (and mask-p (not (%websocket-octet-vector-p masking-key)))
    (%websocket-protocol-error
     "A masked WebSocket frame must have a four-octet masking key."
     masking-key))
  (when (and mask-p (/= (length masking-key) 4))
    (%websocket-protocol-error
     "A WebSocket masking key must contain exactly four octets."
     (length masking-key)))
  (when (and (not mask-p) masking-key)
    (%websocket-protocol-error
     "An unmasked WebSocket frame cannot carry a masking key."))
  (when (and (%websocket-control-opcode-p opcode)
             (or (not fin-p) (> (length payload) 125)))
    (%websocket-protocol-error
     "WebSocket control frames must be final and no larger than 125 octets."
     (list :fin fin-p :length (length payload))))
  t)

(defstruct (websocket-frame
            (:constructor %make-websocket-frame
                (&key fin-p opcode reserved-bits mask-p masking-key payload)))
  fin-p
  opcode
  (reserved-bits 0)
  mask-p
  masking-key
  payload)

(defun make-websocket-frame
    (&key (fin-p t) (opcode 1) (reserved-bits 0) (mask-p nil)
          masking-key payload)
  "Construct a validated WebSocket frame.

MASKING-KEY is required for masked frames.  The library deliberately does not
generate masking keys implicitly, so callers must make the randomness policy
explicit at the client boundary.  RESERVED-BITS is a mask of RSV1, RSV2, and
RSV3 (values #x40, #x20, and #x10); extension code owns the semantics."
  (let ((final (not (null fin-p)))
        (masked (not (null mask-p)))
        (frame-payload (if payload
                           (%websocket-copy-octets payload)
                           (%websocket-empty-octets)))
        (frame-key (and masking-key (%websocket-copy-octets masking-key))))
    (%websocket-validate-frame-components
     final opcode reserved-bits masked frame-key frame-payload)
    (%make-websocket-frame :fin-p final
                           :opcode opcode
                           :reserved-bits reserved-bits
                           :mask-p masked
                           :masking-key frame-key
                           :payload frame-payload)))

(defun %websocket-store-integer (vector start width value)
  (loop for index below width
        for shift from (* 8 (1- width)) downto 0 by 8
        do (setf (aref vector (+ start index))
                 (ldb (byte 8 shift) value)))
  vector)

(defun %websocket-read-integer (vector start width)
  (loop with result = 0
        for index below width
        do (setf result
                 (+ (ash result 8)
                    (aref vector (+ start index))))
        finally (return result)))

(defun %websocket-validate-length-encoding (length-code payload-length)
  (when (and (= length-code 126) (< payload-length 126))
    (%websocket-protocol-error
     "A 16-bit WebSocket payload length must be at least 126."
     payload-length))
  (when (and (= length-code 127) (< payload-length #x10000))
    (%websocket-protocol-error
     "A 64-bit WebSocket payload length must be at least 65536."
     payload-length))
  payload-length)

(defun %websocket-mask-octets (payload masking-key)
  (let ((result (make-array (length payload)
                            :element-type '(unsigned-byte 8))))
    (loop for index below (length payload)
          do (setf (aref result index)
                   (logxor (aref payload index)
                           (aref masking-key (mod index 4)))))
    result))

(defun serialize-websocket-frame (frame)
  "Serialize FRAME to its wire representation as an octet vector."
  (unless (websocket-frame-p frame)
    (%websocket-protocol-error "Expected a WebSocket frame." frame))
  (let* ((fin-p (websocket-frame-fin-p frame))
         (opcode (websocket-frame-opcode frame))
         (reserved-bits (websocket-frame-reserved-bits frame))
         (mask-p (websocket-frame-mask-p frame))
         (masking-key (websocket-frame-masking-key frame))
         (payload (websocket-frame-payload frame)))
    (%websocket-validate-frame-components
     fin-p opcode reserved-bits mask-p masking-key payload)
    (let* ((payload-length (length payload))
           (extended-width (cond ((<= payload-length 125) 0)
                                 ((<= payload-length #xffff) 2)
                                 ((< payload-length (ash 1 63)) 8)
                                 (t
                                  (%websocket-protocol-error
                                   "A WebSocket payload length exceeds the 63-bit wire limit."
                                   payload-length))))
           (header-length (+ 2 extended-width (if mask-p 4 0)))
           (wire (make-array (+ header-length payload-length)
                             :element-type '(unsigned-byte 8)))
           (length-code (cond ((zerop extended-width) payload-length)
                              ((= extended-width 2) 126)
                              (t 127))))
      (setf (aref wire 0)
            (logior (if fin-p #x80 0) reserved-bits opcode)
            (aref wire 1)
            (logior (if mask-p #x80 0) length-code))
      (when (plusp extended-width)
        (%websocket-store-integer wire 2 extended-width payload-length))
      (let ((offset (+ 2 extended-width)))
        (when mask-p
          (replace wire masking-key :start1 offset)
          (incf offset 4))
        (replace wire (if mask-p
                         (%websocket-mask-octets payload masking-key)
                         payload)
                 :start1 offset))
      wire)))

(defun %websocket-parse-length (octets length-code offset)
  (cond ((< length-code 126)
         (values length-code offset))
        ((= length-code 126)
        (when (< (length octets) (+ offset 2))
           (%websocket-protocol-error
            "A WebSocket frame ended before its extended payload length."))
         (let ((payload-length (%websocket-read-integer octets offset 2)))
           (%websocket-validate-length-encoding length-code payload-length)
           (values payload-length
                 (+ offset 2))))
        (t
         (when (< (length octets) (+ offset 8))
           (%websocket-protocol-error
            "A WebSocket frame ended before its extended payload length."))
         (when (logbitp 63 (%websocket-read-integer octets offset 8))
           (%websocket-protocol-error
            "A WebSocket payload length must have its high bit clear."))
         (let ((payload-length (%websocket-read-integer octets offset 8)))
           (%websocket-validate-length-encoding length-code payload-length)
           (values payload-length
                 (+ offset 8))))))

(defun parse-websocket-frame
    (octets &key (max-payload-bytes +websocket-default-max-payload-bytes+)
                  (require-mask-p nil) (allow-unmasked-p t)
                  (require-unmasked-p nil)
                  (allowed-reserved-bits 0))
  "Parse one WebSocket frame from OCTETS.

Returns the frame and the number of consumed octets.  Additional octets are
left for the caller, which makes this function suitable for buffered input.
ALLOWED-RESERVED-BITS explicitly permits RSV bits claimed by a negotiated
extension; the default is zero."
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (%websocket-validate-reserved-bits
   allowed-reserved-bits "ALLOWED-RESERVED-BITS")
  (unless (%websocket-octet-vector-p octets)
    (%websocket-protocol-error
     "WebSocket wire data must be a one-dimensional vector of octets."
     octets))
  (when (< (length octets) 2)
    (%websocket-protocol-error
     "A WebSocket frame requires at least two header octets."))
  (let* ((first (aref octets 0))
         (second (aref octets 1))
         (fin-p (not (zerop (logand first #x80))))
         (reserved (logand first #x70))
         (opcode (logand first #x0f))
         (mask-p (not (zerop (logand second #x80))))
         (length-code (logand second #x7f)))
    (when (plusp reserved)
      (unless (zerop (logand reserved
                              (logxor #x70 allowed-reserved-bits)))
        (%websocket-protocol-error
         "WebSocket RSV bits were not enabled by a negotiated extension."
         reserved)))
    (unless (%websocket-valid-opcode-p opcode)
      (%websocket-protocol-error
       "A WebSocket frame has an unsupported opcode."
       opcode))
    (when (and (%websocket-control-opcode-p opcode)
               (or (not fin-p) (>= length-code 126)))
      (%websocket-protocol-error
       "A WebSocket control frame must be final and no larger than 125 octets."
       opcode))
    (when (and require-mask-p (not mask-p))
      (%websocket-protocol-error
       "A WebSocket frame was required to be masked."))
    (when (and require-unmasked-p mask-p)
      (%websocket-protocol-error
       "A WebSocket frame was required to be unmasked."))
    (unless (or allow-unmasked-p mask-p)
      (%websocket-protocol-error
       "An unmasked WebSocket frame is not allowed here."))
    (multiple-value-bind (payload-length header-end)
        (%websocket-parse-length octets length-code 2)
      (when (> payload-length max-payload-bytes)
        (%websocket-size-error
         "A WebSocket frame exceeded its payload-size limit."
         max-payload-bytes payload-length))
      (let* ((mask-end (+ header-end (if mask-p 4 0)))
             (frame-end (+ mask-end payload-length)))
        (when (> mask-end (length octets))
          (%websocket-protocol-error
           "A WebSocket frame ended before its masking key."))
        (when (> frame-end (length octets))
          (%websocket-protocol-error
           "A WebSocket frame ended before its payload."))
        (let* ((masking-key (and mask-p
                                 (subseq octets header-end mask-end)))
               (wire-payload (subseq octets mask-end frame-end))
               (payload (if mask-p
                            (%websocket-mask-octets wire-payload masking-key)
                            wire-payload)))
          (%websocket-validate-frame-components
           fin-p opcode reserved mask-p masking-key payload)
          (values (%make-websocket-frame :fin-p fin-p
                                         :opcode opcode
                                         :reserved-bits reserved
                                         :mask-p mask-p
                                         :masking-key masking-key
                                         :payload payload)
                  frame-end))))))

(defun %websocket-read-exact (stream count)
  (unless (and (integerp count) (<= 0 count))
    (%websocket-protocol-error
     "A WebSocket read requested an invalid octet count."
     count))
  (let ((result (make-array count :element-type '(unsigned-byte 8)))
        (position 0))
    (loop while (< position count)
          do (let ((new-position
                     (handler-case
                         (read-sequence result stream :start position :end count)
                       (end-of-file () position))))
               (if (<= new-position position)
                   (error 'websocket-transport-error
                          :message
                          "The WebSocket transport ended before a complete frame was received."
                          :operation :websocket-receive
                          :cause :eof
                          :detail (list :expected count :received position))
                   (setf position new-position))))
    result))

(defun read-websocket-frame
    (stream &key (max-payload-bytes +websocket-default-max-payload-bytes+)
                  (require-mask-p nil) (allow-unmasked-p t)
                  (require-unmasked-p nil)
                  (allowed-reserved-bits 0))
  "Read and parse one WebSocket frame from STREAM.

ALLOWED-RESERVED-BITS explicitly permits RSV bits claimed by a negotiated
extension; the default is zero."
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (%websocket-validate-reserved-bits
   allowed-reserved-bits "ALLOWED-RESERVED-BITS")
  (unless (streamp stream)
    (%websocket-protocol-error "WebSocket frame input must be a stream." stream))
  (let* ((first-two (%websocket-read-exact stream 2))
         (first (aref first-two 0))
         (fin-p (not (zerop (logand first #x80))))
         (reserved (logand first #x70))
         (opcode (logand first #x0f))
         (mask-p (not (zerop (logand (aref first-two 1) #x80))))
         (length-code (logand (aref first-two 1) #x7f))
         (extended-width (cond ((< length-code 126) 0)
                               ((= length-code 126) 2)
                               (t 8))))
    (when (plusp reserved)
      (unless (zerop (logand reserved
                              (logxor #x70 allowed-reserved-bits)))
        (%websocket-protocol-error
         "WebSocket RSV bits were not enabled by a negotiated extension."
         reserved)))
    (unless (%websocket-valid-opcode-p opcode)
      (%websocket-protocol-error
       "A WebSocket frame has an unsupported opcode."
       opcode))
    (when (and (%websocket-control-opcode-p opcode)
               (or (not fin-p) (>= length-code 126)))
      (%websocket-protocol-error
       "A WebSocket control frame must be final and no larger than 125 octets."
       opcode))
    (when (and require-mask-p (not mask-p))
      (%websocket-protocol-error
       "A WebSocket frame was required to be masked."))
    (when (and require-unmasked-p mask-p)
      (%websocket-protocol-error
       "A WebSocket frame was required to be unmasked."))
    (unless (or allow-unmasked-p mask-p)
      (%websocket-protocol-error
       "An unmasked WebSocket frame is not allowed here."))
    (let* ((extension (%websocket-read-exact stream extended-width))
           (payload-length (if (zerop extended-width)
                               length-code
                               (%websocket-read-integer
                                extension 0 extended-width))))
      (when (and (= extended-width 8)
                 (logbitp 63 payload-length))
        (%websocket-protocol-error
         "A WebSocket payload length must have its high bit clear."))
      (%websocket-validate-length-encoding length-code payload-length)
      (when (> payload-length max-payload-bytes)
        (%websocket-size-error
         "A WebSocket frame exceeded its payload-size limit."
         max-payload-bytes payload-length))
      (let* ((masking-key (when mask-p (%websocket-read-exact stream 4)))
             (payload (%websocket-read-exact stream payload-length))
             (wire (make-array (+ 2 extended-width (if mask-p 4 0)
                                  payload-length)
                               :element-type '(unsigned-byte 8))))
        (replace wire first-two)
        (replace wire extension :start1 2)
        (let ((offset (+ 2 extended-width)))
          (when mask-p
            (replace wire masking-key :start1 offset)
            (incf offset 4))
          (replace wire payload :start1 offset))
        (parse-websocket-frame wire
                               :max-payload-bytes max-payload-bytes
                               :require-mask-p require-mask-p
                               :allow-unmasked-p allow-unmasked-p
                               :require-unmasked-p require-unmasked-p
                               :allowed-reserved-bits allowed-reserved-bits)))))

(defun write-websocket-frame (stream frame &key (finish-output-p t))
  "Write FRAME to STREAM and optionally flush the stream."
  (unless (streamp stream)
    (%websocket-protocol-error "WebSocket frame output must be a stream." stream))
  (write-sequence (serialize-websocket-frame frame) stream)
  (when finish-output-p
    (finish-output stream))
  frame)
