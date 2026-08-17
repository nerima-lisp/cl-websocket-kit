(in-package #:websocket-kit)

(defconstant +websocket-http2-3-connection-default-max-concurrent-streams+
  100)

(defstruct (websocket-http2-3-stream
            (:constructor %make-websocket-http2-3-stream))
  connection
  id
  session
  headers
  trailers
  local-end-p
  remote-end-p
  send-window
  receive-window
  unconsumed-receive-bytes
  inbound-frames
  inbound-frame-tail
  wire-buffer
  headers-seen-p
  established-p
  request-p)

(defstruct (websocket-http2-3-connection
            (:constructor %make-websocket-http2-3-connection))
  protocol
  role
  read-function
  write-function
  close-function
  stream-open-function
  stream-close-function
  max-concurrent-streams
  max-frame-size
  initial-window-size
  max-header-block-bytes
  max-continuation-frames
  hpack-encoder-context
  hpack-decoder-context
  hpack-huffman-p
  h3-qpack-huffman-p
  h3-qpack-encoder-table
  h3-qpack-decoder-table
  h3-qpack-encoder-stream-id
  h3-qpack-decoder-stream-id
  h3-qpack-peer-encoder-stream-id
  h3-qpack-peer-decoder-stream-id
  h3-qpack-encoder-wire-buffer
  h3-qpack-decoder-wire-buffer
  h3-qpack-encoder-events
  h3-qpack-decoder-events
  h3-qpack-max-table-capacity
  h3-qpack-blocked-streams
  h3-max-field-section-size
  h3-peer-max-field-section-size
  h3-peer-qpack-max-table-capacity
  h3-peer-qpack-blocked-streams
  max-buffered-wire-bytes
  max-data-bytes
  max-data-frames
  send-window
  receive-window
  unconsumed-receive-bytes
  peer-settings
  peer-settings-seen-p
  peer-connect-enabled-p
  peer-max-concurrent-streams
  peer-initial-window-size
  peer-max-frame-size
  local-settings
  local-settings-ack-pending-p
  h3-control-stream-id
  h3-peer-control-stream-id
  streams
  next-stream-id
  last-peer-stream-id
  closed-p
  local-end-p
  remote-end-p
  started-p
  preface-received-p
  preface-buffer
  wire-buffer
  pending-header-wire
  pending-header-stream-id
  pending-header-request-p
  pending-header-trailers-p
  h3-control-wire-buffer
  h3-control-settings-seen-p
  goaway-last-stream-id
  #+sbcl (lock (sb-thread:make-mutex
                :name "websocket-kit-http2-3-connection"))
  #-sbcl (lock nil)
  #+sbcl (read-lock (sb-thread:make-mutex
                    :name "websocket-kit-http2-3-connection-read"))
  #-sbcl (read-lock nil))

(defmacro %websocket-http2-3-connection-with-lock ((connection) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-http2-3-connection-lock ,connection))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defmacro %websocket-http2-3-connection-with-read-lock
    ((connection) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-http2-3-connection-read-lock ,connection))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defun %websocket-http2-3-connection-empty-buffer ()
  (make-array 0
              :element-type '(unsigned-byte 8)
              :adjustable t
              :fill-pointer 0))

(defun %websocket-http2-3-connection-copy-octets (octets)
  (unless (%websocket-http2-3-octet-vector-p octets)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 connection callback requires octets."
     :detail octets))
  (%websocket-http2-3-copy-octets octets))

(defun %websocket-http2-3-connection-append
    (buffer octets limit message)
  (unless (%websocket-http2-3-octet-vector-p octets)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 connection callback requires octets."
     :detail octets))
  (let ((observed (+ (fill-pointer buffer) (length octets))))
    (when (> observed limit)
      (%websocket-size-error message limit observed))
    (%websocket-append-octets
     buffer (%websocket-http2-3-connection-copy-octets octets))))

(defun %websocket-http2-3-connection-drop-prefix (buffer count)
  (let* ((length (fill-pointer buffer))
         (remaining (- length count))
         (result (make-array remaining
                             :element-type '(unsigned-byte 8)
                             :adjustable t
                             :fill-pointer remaining)))
    (replace result buffer :start2 count)
    result))

(defun %websocket-http2-3-connection-u16 (value)
  (unless (<= 0 value #xffff)
    (%websocket-http2-3-fail
     "An HTTP/2 setting identifier is outside its unsigned 16-bit range."
     :detail value))
  (let ((octets (make-array 2 :element-type '(unsigned-byte 8))))
    (setf (aref octets 0) (ldb (byte 8 8) value)
          (aref octets 1) (ldb (byte 8 0) value))
    octets))

(defun %websocket-http2-3-connection-u32 (value)
  (unless (<= 0 value #xffffffff)
    (%websocket-http2-3-fail
     "An HTTP/2 control value is outside its unsigned 32-bit range."
     :detail value))
  (let ((octets (make-array 4 :element-type '(unsigned-byte 8))))
    (setf (aref octets 0) (ldb (byte 8 24) value)
          (aref octets 1) (ldb (byte 8 16) value)
          (aref octets 2) (ldb (byte 8 8) value)
          (aref octets 3) (ldb (byte 8 0) value))
    octets))

(defun %websocket-http2-3-connection-u24 (value)
  (unless (<= 0 value #xffffff)
    (%websocket-http2-3-fail
     "An HTTP/2 frame length is outside its unsigned 24-bit range."
     :detail value))
  (let ((octets (make-array 3 :element-type '(unsigned-byte 8))))
    (setf (aref octets 0) (ldb (byte 8 16) value)
          (aref octets 1) (ldb (byte 8 8) value)
          (aref octets 2) (ldb (byte 8 0) value))
    octets))

(defun %websocket-http2-3-connection-http2-frame-length (buffer)
  (when (>= (fill-pointer buffer) 9)
    (+ 9 (logior (ash (aref buffer 0) 16)
                 (ash (aref buffer 1) 8)
                 (aref buffer 2)))))

(defun %websocket-http2-3-connection-http2-frame-type (buffer)
  (aref buffer 3))

(defun %websocket-http2-3-connection-http2-frame-flags (buffer)
  (aref buffer 4))

(defun %websocket-http2-3-connection-http2-frame-stream-id (buffer)
  (logand #x7fffffff
          (logior (ash (aref buffer 5) 24)
                  (ash (aref buffer 6) 16)
                  (ash (aref buffer 7) 8)
                  (aref buffer 8))))

(defun %websocket-http2-3-connection-h3-frame-header (buffer)
  (let ((length (fill-pointer buffer)))
    (when (plusp length)
      (multiple-value-bind (type after-type)
          (http-kit/http3:http3-varint-decode
           buffer :position 0 :allow-incomplete-p t)
        (when type
          (multiple-value-bind (payload-length after-length)
              (http-kit/http3:http3-varint-decode
               buffer :position after-type :allow-incomplete-p t)
            (when payload-length
              (values type payload-length after-length))))))))

(defun %websocket-http2-3-connection-transport-error
    (message operation cause &key detail)
  (error 'websocket-transport-error
         :message message
         :operation operation
         :cause cause
         :detail detail))

(defun %websocket-http2-3-connection-ensure
    (connection)
  (unless (websocket-http2-3-connection-p connection)
    (%websocket-http2-3-fail
     "Expected an HTTP/2 or HTTP/3 WebSocket connection."
     :detail connection))
  connection)

(defun %websocket-http2-3-connection-ensure-protocol
    (connection protocol)
  (%websocket-http2-3-connection-ensure connection)
  (unless (eq protocol (websocket-http2-3-connection-protocol connection))
    (%websocket-http2-3-fail
     "The WebSocket connection protocol does not match the requested operation."
     :detail (list :expected protocol
                   :actual (websocket-http2-3-connection-protocol connection))))
  connection)

(defun %websocket-http2-3-connection-role-p (role)
  (member role '(:client :server) :test #'eq))

(defun %websocket-http2-3-connection-check-role (role)
  (unless (%websocket-http2-3-connection-role-p role)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 WebSocket connection role must be :CLIENT or :SERVER."
     :detail role))
  role)

(defun %websocket-http2-3-connection-check-connection-options
    (protocol role max-concurrent-streams max-frame-size initial-window-size
             max-header-block-bytes max-continuation-frames
             max-buffered-wire-bytes max-data-bytes max-data-frames)
  (%websocket-http2-3-connection-check-role role)
  (%websocket-validate-limit
   max-concurrent-streams "MAX-CONCURRENT-STREAMS")
  (%websocket-positive-limit max-concurrent-streams "MAX-CONCURRENT-STREAMS")
  (%websocket-validate-limit initial-window-size "INITIAL-WINDOW-SIZE")
  (when (> initial-window-size #x7fffffff)
    (%websocket-http2-3-fail
     "An HTTP/2 initial window exceeds the signed 31-bit limit."
     :detail initial-window-size))
  (%websocket-validate-limit
   max-header-block-bytes "MAX-HEADER-BLOCK-BYTES")
  (%websocket-validate-limit
   max-continuation-frames "MAX-CONTINUATION-FRAMES")
  (%websocket-validate-limit
   max-buffered-wire-bytes "MAX-BUFFERED-WIRE-BYTES")
  (%websocket-validate-limit max-data-bytes "MAX-DATA-BYTES")
  (%websocket-positive-limit max-data-frames "MAX-DATA-FRAMES")
  (if (eq protocol :http2)
      (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
      (%websocket-http2-3-check-http3-max-frame-size max-frame-size))
  t)

(defun %websocket-http2-3-connection-peer-bidi-stream-p
    (connection stream-id)
  (if (eq (websocket-http2-3-connection-protocol connection) :http2)
      (let ((peer-parity (if (eq (websocket-http2-3-connection-role connection)
                                 :client)
                            0
                            1)))
        (and (plusp stream-id)
             (= (mod stream-id 2) peer-parity)))
      (let ((peer-initiator-bit
              (if (eq (websocket-http2-3-connection-role connection) :client)
                  1
                  0)))
        (and (zerop (logand stream-id 2))
             (= (logand stream-id 1) peer-initiator-bit)))))

(defun %websocket-http2-3-connection-local-stream-id-p
    (connection stream-id)
  (if (eq (websocket-http2-3-connection-protocol connection) :http2)
      (let ((local-parity (if (eq (websocket-http2-3-connection-role connection)
                                  :client)
                             1
                             0)))
        (= (mod stream-id 2) local-parity))
      (let ((local-initiator-bit
              (if (eq (websocket-http2-3-connection-role connection) :client)
                  0
                  1)))
        (and (zerop (logand stream-id 2))
             (= (logand stream-id 1) local-initiator-bit)))))

(defun %websocket-http2-3-connection-effective-frame-size (connection)
  (if (eq (websocket-http2-3-connection-protocol connection) :http2)
      (min (websocket-http2-3-connection-max-frame-size connection)
           (websocket-http2-3-connection-peer-max-frame-size connection))
      (websocket-http2-3-connection-max-frame-size connection)))

(defun %websocket-http2-3-connection-local-http3-field-section-size
    (connection)
  (min (websocket-http2-3-connection-max-header-block-bytes connection)
       (websocket-http2-3-connection-h3-max-field-section-size connection)))

(defun %websocket-http2-3-connection-peer-http3-field-section-size
    (connection)
  (let ((setting
          (assoc http-kit/http3:+http3-setting-max-field-section-size+
                 (websocket-http2-3-connection-peer-settings connection))))
    (if setting
        (min (websocket-http2-3-connection-max-header-block-bytes connection)
             (cdr setting))
        (websocket-http2-3-connection-max-header-block-bytes connection))))

(defun %websocket-http2-3-connection-write
    (connection octets &key stream-id end-stream-p deadline)
  (let ((function (websocket-http2-3-connection-write-function connection)))
    (unless (functionp function)
      (%websocket-http2-3-connection-transport-error
       "The WebSocket connection has no write callback."
       :write nil))
    (let ((octets (%websocket-http2-3-connection-copy-octets octets)))
      (handler-case
          (let ((accepted
                  (if deadline
                      (funcall function octets
                               :stream-id stream-id
                               :end-stream-p (not (null end-stream-p))
                               :deadline deadline)
                      (funcall function octets
                               :stream-id stream-id
                               :end-stream-p (not (null end-stream-p))))))
            (unless (or (null accepted)
                        (eq accepted t)
                        (and (integerp accepted)
                             (= accepted (length octets))))
              (%websocket-http2-3-connection-transport-error
               "A WebSocket connection write callback did not accept the complete batch."
               :write nil
               :detail (list :accepted accepted
                             :expected (length octets)
                             :stream-id stream-id)))
            accepted)
        (websocket-error (condition)
          (error condition))
        (error (condition)
          (%websocket-http2-3-connection-transport-error
           "A WebSocket connection write callback failed."
           :write condition
           :detail (list :stream-id stream-id
                         :end-stream-p (not (null end-stream-p)))))))))

(defun %websocket-http2-3-connection-call-close
    (connection abort-p)
  (let ((function (websocket-http2-3-connection-close-function connection)))
    (when function
      (handler-case
          (funcall function :abort-p (not (null abort-p)))
        (websocket-error (condition)
          (error condition))
        (error (condition)
          (%websocket-http2-3-connection-transport-error
           "A WebSocket connection close callback failed."
           :close condition))))))

(defun %websocket-http2-3-connection-make-settings-payload
    (settings)
  (%websocket-http2-3-append-octets
   (mapcar (lambda (entry)
             (%websocket-http2-3-append-octets
              (list (%websocket-http2-3-connection-u16 (car entry))
                    (%websocket-http2-3-connection-u32 (cdr entry)))))
           settings)))

(defun %websocket-http2-3-connection-encode-settings
    (settings &key (ack-p nil))
  (%websocket-http2-3-encode-http2-frame
   :settings
   (if ack-p #x1 0)
   0
   (if ack-p
       (make-array 0 :element-type '(unsigned-byte 8))
       (%websocket-http2-3-connection-make-settings-payload settings))))

(defun %websocket-http2-3-connection-local-http2-settings (connection)
  (list (cons 1 (if (websocket-http2-3-connection-hpack-decoder-context connection)
                    (websocket-http2-hpack-context-maximum-size
                     (websocket-http2-3-connection-hpack-decoder-context connection))
                    0))
        (cons 3 (websocket-http2-3-connection-max-concurrent-streams connection))
        (cons 4 (websocket-http2-3-connection-initial-window-size connection))
        (cons 5 (websocket-http2-3-connection-max-frame-size connection))
        (cons +websocket-http2-enable-connect-protocol-setting+ 1)))

(defun %websocket-http2-3-connection-local-http3-settings (connection)
  (list (cons http-kit/http3:+http3-setting-qpack-max-table-capacity+
              (websocket-http2-3-connection-h3-qpack-max-table-capacity
               connection))
        (cons http-kit/http3:+http3-setting-max-field-section-size+
              (websocket-http2-3-connection-h3-max-field-section-size
               connection))
        (cons http-kit/http3:+http3-setting-qpack-blocked-streams+
              (websocket-http2-3-connection-h3-qpack-blocked-streams
               connection))
        (cons +websocket-http3-enable-connect-protocol-setting+ 1)))

(defun %websocket-http2-3-connection-setting
    (settings identifier)
  (cdr (assoc identifier settings)))

(defun %websocket-http2-3-connection-parse-settings
    (payload)
  (unless (zerop (mod (length payload) 6))
    (%websocket-http2-3-fail
     "An HTTP/2 SETTINGS payload must contain six-byte entries."))
  (let ((position 0)
        (settings nil))
    (loop while (< position (length payload))
          do (let ((identifier
                     (logior (ash (aref payload position) 8)
                             (aref payload (1+ position))))
                   (value
                     (logior (ash (aref payload (+ position 2)) 24)
                             (ash (aref payload (+ position 3)) 16)
                             (ash (aref payload (+ position 4)) 8)
                             (aref payload (+ position 5)))))
               (when (assoc identifier settings)
                 (%websocket-http2-3-fail
                  "An HTTP/2 SETTINGS payload contains a duplicate identifier."
                  :detail identifier))
               (case identifier
                 (1
                  (unless (%websocket-http2-hpack-size-p value)
                    (%websocket-http2-3-fail
                     "HTTP/2 SETTINGS_HEADER_TABLE_SIZE is outside the unsigned range."
                     :detail value)))
                 (2
                  (unless (member value '(0 1) :test #'=)
                    (%websocket-http2-3-fail
                     "HTTP/2 ENABLE_PUSH must be zero or one."
                     :detail value)))
                 (3
                  (unless (<= value #x7fffffff)
                    (%websocket-http2-3-fail
                     "HTTP/2 MAX_CONCURRENT_STREAMS exceeds the signed range."
                     :detail value)))
                 (4
                  (unless (<= value #x7fffffff)
                    (%websocket-http2-3-fail
                     "HTTP/2 INITIAL_WINDOW_SIZE exceeds the signed range."
                     :detail value)))
                 (5
                  (unless (<= #x4000 value #xffffff)
                    (%websocket-http2-3-fail
                     "HTTP/2 MAX_FRAME_SIZE is outside the RFC range."
                     :detail value)))
                 (8
                  (unless (member value '(0 1) :test #'=)
                    (%websocket-http2-3-fail
                     "HTTP/2 ENABLE_CONNECT_PROTOCOL must be zero or one."
                     :detail value))))
               (push (cons identifier value) settings)
               (incf position 6)))
    (nreverse settings)))

(defun %websocket-http2-3-connection-apply-settings
    (connection settings)
  (let ((old-window
          (websocket-http2-3-connection-peer-initial-window-size connection))
        (new-window (%websocket-http2-3-connection-setting settings 4)))
    (when new-window
      (let ((delta (- new-window old-window)))
        (maphash
         (lambda (stream-id stream)
           (declare (ignore stream-id))
           (let ((window (+ (websocket-http2-3-stream-send-window stream)
                            delta)))
             (when (< window 0)
               (error 'websocket-flow-control-error
                      :message "An HTTP/2 SETTINGS initial-window update made a stream window negative."
                      :operation :settings
                      :window window
                      :required 0
                      :kind :stream))
             (setf (websocket-http2-3-stream-send-window stream) window)))
         (websocket-http2-3-connection-streams connection))
        (setf (websocket-http2-3-connection-peer-initial-window-size connection)
              new-window)))
    (let ((max-concurrent
            (%websocket-http2-3-connection-setting settings 3))
          (max-frame (%websocket-http2-3-connection-setting settings 5))
          (connect
            (%websocket-http2-3-connection-setting
             settings +websocket-http2-enable-connect-protocol-setting+)))
      (when max-concurrent
        (setf (websocket-http2-3-connection-peer-max-concurrent-streams connection)
              max-concurrent))
      (when max-frame
        (setf (websocket-http2-3-connection-peer-max-frame-size connection)
              max-frame))
      (when connect
        (setf (websocket-http2-3-connection-peer-connect-enabled-p connection)
              (= connect 1))))
    (let ((peer-table-size (%websocket-http2-3-connection-setting settings 1))
          (encoder-context
            (websocket-http2-3-connection-hpack-encoder-context connection)))
      (when (and peer-table-size encoder-context)
        (set-websocket-http2-hpack-context-maximum-size
         encoder-context peer-table-size)
        (set-websocket-http2-hpack-context-max-size
         encoder-context peer-table-size)))
    (setf (websocket-http2-3-connection-peer-settings connection) settings
          (websocket-http2-3-connection-peer-settings-seen-p connection) t)
    settings))

(defun %websocket-http2-3-connection-stream-count (connection)
  (let ((count 0))
    (maphash
     (lambda (id stream)
       (declare (ignore id))
       (unless (and (websocket-http2-3-stream-local-end-p stream)
                    (websocket-http2-3-stream-remote-end-p stream))
         (incf count)))
     (websocket-http2-3-connection-streams connection))
    count))

(defun %websocket-http2-3-connection-check-open-capacity (connection)
  (let ((peer-limit
          (websocket-http2-3-connection-peer-max-concurrent-streams connection)))
    (when (>= (%websocket-http2-3-connection-stream-count connection)
              (min (websocket-http2-3-connection-max-concurrent-streams connection)
                   peer-limit))
      (%websocket-http2-3-fail
       "The HTTP/2 or HTTP/3 peer stream concurrency limit has been reached.
"
       :detail peer-limit))))

(defun %websocket-http2-3-connection-new-stream-id (connection)
  (let ((stream-id (websocket-http2-3-connection-next-stream-id connection)))
    (if (eq (websocket-http2-3-connection-protocol connection) :http2)
        (%websocket-http2-3-check-http2-stream-id stream-id)
        (%websocket-http2-3-check-http3-stream-id stream-id))
    (setf (websocket-http2-3-connection-next-stream-id connection)
          (if (eq (websocket-http2-3-connection-protocol connection) :http2)
              (+ stream-id 2)
              (+ stream-id 4)))
    stream-id))

(defun %websocket-http2-3-connection-make-stream
    (connection stream-id &key headers request-p)
  (let ((stream
          (%make-websocket-http2-3-stream
           :connection connection
           :id stream-id
           :headers headers
           :local-end-p nil
           :remote-end-p nil
           :send-window
           (websocket-http2-3-connection-peer-initial-window-size connection)
           :receive-window
           (websocket-http2-3-connection-initial-window-size connection)
           :unconsumed-receive-bytes 0
           :inbound-frames nil
           :wire-buffer (%websocket-http2-3-connection-empty-buffer)
           :headers-seen-p nil
           :established-p nil
           :request-p request-p)))
    (setf (gethash stream-id (websocket-http2-3-connection-streams connection))
          stream)
    stream))

(defun %websocket-http2-3-connection-call-stream-open
    (connection stream)
  (let ((function
          (websocket-http2-3-connection-stream-open-function connection)))
    (when function
      (handler-case
          (funcall function stream)
        (websocket-error (condition)
          (error condition))
        (error (condition)
          (%websocket-http2-3-connection-transport-error
           "The WebSocket stream-open callback failed."
           :stream-open condition
           :detail stream))))))

(defun %websocket-http2-3-connection-call-stream-close
    (connection stream abort-p)
  (let ((function
          (websocket-http2-3-connection-stream-close-function connection)))
    (when function
      (handler-case
          (funcall function stream :abort-p (not (null abort-p)))
        (websocket-error (condition)
          (error condition))
        (error (condition)
          (%websocket-http2-3-connection-transport-error
           "The WebSocket stream-close callback failed."
           :stream-close condition
           :detail stream))))))

(defun %websocket-http2-3-connection-session-initargs
    (connection initargs)
  (let ((initargs (or initargs nil)))
    (if (getf initargs :max-frame-size)
        initargs
        (append initargs
                (list :max-frame-size
                      (%websocket-http2-3-connection-effective-frame-size
                       connection))))))

(defun %websocket-http2-3-connection-enqueue
    (stream octets end-stream-p &optional (received-bytes (length octets)))
  (let ((connection (websocket-http2-3-stream-connection stream)))
    (unless (and (integerp received-bytes) (<= 0 received-bytes))
      (%websocket-http2-3-fail
       "A received HTTP/2 or HTTP/3 DATA byte count must be non-negative."
       :detail received-bytes))
    (when (>= (length (websocket-http2-3-stream-inbound-frames stream))
              (websocket-http2-3-connection-max-data-frames connection))
      (%websocket-size-error
       "The HTTP/2 or HTTP/3 inbound DATA frame queue is full."
       (websocket-http2-3-connection-max-data-frames connection)
       (1+ (length (websocket-http2-3-stream-inbound-frames stream)))))
    (when (> (+ (websocket-http2-3-connection-unconsumed-receive-bytes
                 connection)
                received-bytes)
             (websocket-http2-3-connection-max-data-bytes connection))
      (%websocket-size-error
       "The HTTP/2 or HTTP/3 inbound DATA byte budget is exhausted."
       (websocket-http2-3-connection-max-data-bytes connection)
       (+ (websocket-http2-3-connection-unconsumed-receive-bytes connection)
          received-bytes)))
    (let* ((entry (cons (%websocket-http2-3-connection-copy-octets octets)
                        (not (null end-stream-p))))
           (cell (list entry))
           (tail (websocket-http2-3-stream-inbound-frame-tail stream)))
      (if tail
          (setf (cdr tail) cell
                (websocket-http2-3-stream-inbound-frame-tail stream) cell)
          (setf (websocket-http2-3-stream-inbound-frames stream) cell
                (websocket-http2-3-stream-inbound-frame-tail stream) cell)))
    (incf (websocket-http2-3-stream-unconsumed-receive-bytes stream)
          received-bytes)
    (incf (websocket-http2-3-connection-unconsumed-receive-bytes connection)
          received-bytes)
    (when end-stream-p
      (setf (websocket-http2-3-stream-remote-end-p stream) t))))

(defun %websocket-http2-3-connection-stream-read
    (stream &optional deadline)
  (let ((connection (websocket-http2-3-stream-connection stream)))
    (%websocket-http2-3-connection-with-read-lock (connection)
      (labels ((read-one ()
                 (let ((frames
                         (websocket-http2-3-stream-inbound-frames stream)))
                   (if frames
                       (let ((entry (car frames)))
                         (setf
                          (websocket-http2-3-stream-inbound-frames stream)
                          (cdr frames))
                         (when (null
                                (websocket-http2-3-stream-inbound-frames
                                 stream))
                           (setf
                            (websocket-http2-3-stream-inbound-frame-tail
                             stream)
                            nil))
                         (values (car entry) (cdr entry)))
                       (if (websocket-http2-3-stream-remote-end-p stream)
                           (values nil t)
                           (values nil nil))))))
        (let ((connection-ended-p nil))
          (loop
            (multiple-value-bind (octets endp) (read-one)
              (cond
                (octets
                 (return (values octets endp)))
                (endp
                 (return (values nil t)))
                (connection-ended-p
                 (%websocket-http2-3-connection-transport-error
                  "The HTTP/2 connection ended before its WebSocket stream did."
                  :read nil
                  :detail (websocket-http2-3-stream-id stream)))
                ((not
                  (functionp
                   (websocket-http2-3-connection-read-function connection)))
                 (%websocket-http2-3-connection-transport-error
                  "The WebSocket stream has no connection read callback."
                  :read nil
                  :detail (websocket-http2-3-stream-id stream)))
                (t
                 (multiple-value-bind (ignored endp)
                     (%websocket-http2-3-connection-pump-once
                      connection deadline)
                   (declare (ignore ignored))
                   (when (and
                          (eq
                           (websocket-http2-3-connection-protocol connection)
                           :http2)
                          endp)
                     (setf connection-ended-p t))))))))))))

(defun %websocket-http2-3-connection-check-send-window
    (connection stream amount)
  (when (eq (websocket-http2-3-connection-protocol connection) :http2)
    (let ((connection-window
            (websocket-http2-3-connection-send-window connection))
          (stream-window (websocket-http2-3-stream-send-window stream)))
      (when (< connection-window amount)
        (error 'websocket-flow-control-error
               :message "The HTTP/2 connection send window is insufficient."
               :operation :write
               :window connection-window
               :required amount
               :kind :connection))
      (when (< stream-window amount)
        (error 'websocket-flow-control-error
               :message "The HTTP/2 stream send window is insufficient."
               :operation :write
               :window stream-window
               :required amount
               :kind :stream)))))

(defun %websocket-http2-3-connection-write-stream-wire
    (stream octets end-stream-p &optional deadline)
  (let* ((connection (websocket-http2-3-stream-connection stream))
         (position 0)
         (frames 0)
         (wire (%websocket-http2-3-connection-copy-octets octets)))
    (when (websocket-http2-3-stream-local-end-p stream)
      (%websocket-http2-3-fail
       "A WebSocket stream write followed its local END_STREAM."
       :detail stream))
    (if (eq (websocket-http2-3-connection-protocol connection) :http2)
        (loop while (< position (length wire))
              do (multiple-value-bind (frame used)
                     (%websocket-http2-3-decode-http2-frame
                      (subseq wire position)
                      :max-payload-bytes
                      (%websocket-http2-3-connection-effective-frame-size
                       connection))
                   (unless (= (%websocket-http2-frame-type frame) 0)
                     (%websocket-http2-3-fail
                      "A WebSocket stream write contained a non-DATA HTTP/2 frame."
                      :detail stream))
                   (unless (= (%websocket-http2-frame-stream-id frame)
                              (websocket-http2-3-stream-id stream))
                     (%websocket-http2-3-fail
                      "A WebSocket stream write used the wrong HTTP/2 stream."
                      :detail stream))
                   (let* ((payload (%websocket-http2-3-data-payload frame))
                          (amount (length (%websocket-http2-3-connection-frame-payload
                                           frame))))
                     (declare (ignore payload))
                     (%websocket-http2-3-connection-check-send-window
                      connection stream amount)
                     (decf (websocket-http2-3-connection-send-window connection)
                           amount)
                     (decf (websocket-http2-3-stream-send-window stream)
                           amount))
                   (incf frames)
                   (incf position used)))
        (loop while (< position (length wire))
              do (multiple-value-bind (type payload used)
                     (%websocket-http2-3-decode-http3-frame
                      (subseq wire position)
                      :max-payload-bytes
                      (%websocket-http2-3-connection-effective-frame-size
                       connection))
                   (declare (ignore payload))
                   (unless (= type http-kit/http3:+http3-data-type+)
                     (%websocket-http2-3-fail
                      "A WebSocket stream write contained a non-DATA HTTP/3 frame."
                      :detail stream))
                   (incf frames)
                   (incf position used))))
    (when (zerop frames)
      (%websocket-http2-3-fail
       "A WebSocket stream write contained no DATA frames."))
    (%websocket-http2-3-connection-write
     connection wire
     :stream-id (websocket-http2-3-stream-id stream)
     :end-stream-p end-stream-p
     :deadline deadline)
    (when end-stream-p
      (setf (websocket-http2-3-stream-local-end-p stream) t))
    wire))

(defun %websocket-http2-3-connection-stream-write
    (stream octets &key end-stream-p deadline)
  (%websocket-http2-3-connection-write-stream-wire
   stream octets end-stream-p deadline))

(defun %websocket-http2-3-connection-stream-close
    (stream &key abort-p)
  (let ((connection (websocket-http2-3-stream-connection stream)))
    (unless (websocket-http2-3-stream-local-end-p stream)
      (if abort-p
          (if (eq (websocket-http2-3-connection-protocol connection) :http2)
              (progn
                (%websocket-http2-3-connection-write
                 connection
                 (%websocket-http2-3-encode-http2-frame
                  :rst-stream 0
                  (websocket-http2-3-stream-id stream)
                  (%websocket-http2-3-connection-u32 8))
                 :stream-id (websocket-http2-3-stream-id stream))
                (setf (websocket-http2-3-stream-local-end-p stream) t))
              (setf (websocket-http2-3-stream-local-end-p stream) t))
          (setf (websocket-http2-3-stream-local-end-p stream) t)))
    (%websocket-http2-3-connection-call-stream-close
     connection stream abort-p)
    stream))

(defun %websocket-http2-3-connection-create-session
    (stream &key (initargs nil))
  (let* ((connection (websocket-http2-3-stream-connection stream))
         (stream-id (websocket-http2-3-stream-id stream))
         (read-function
           (lambda (&key deadline)
             (%websocket-http2-3-connection-stream-read stream deadline)))
         (write-function
           (lambda (octets &key end-stream-p deadline)
             (%websocket-http2-3-connection-stream-write
              stream octets
              :end-stream-p end-stream-p
              :deadline deadline)))
         (close-function
           (lambda (&key abort-p)
             (%websocket-http2-3-connection-stream-close
              stream :abort-p abort-p)))
         (initargs
           (%websocket-http2-3-connection-session-initargs
            connection initargs))
         (session
           (if (eq (websocket-http2-3-connection-protocol connection) :http2)
               (apply #'make-websocket-http2-session
                      stream-id read-function write-function
                      :close-function close-function initargs)
               (apply #'make-websocket-http3-session
                      stream-id read-function write-function
                      :close-function close-function initargs))))
    (setf (websocket-http2-3-stream-session stream) session)
    session))

(defun %websocket-http2-3-connection-open-stream-headers
    (connection headers stream-id request-p end-stream-p)
  (if (eq (websocket-http2-3-connection-protocol connection) :http2)
      (encode-websocket-http2-headers-frames
       headers stream-id
       :request-p request-p
       :end-stream-p end-stream-p
       :context
       (websocket-http2-3-connection-hpack-encoder-context connection)
       :huffman-p
       (websocket-http2-3-connection-hpack-huffman-p connection)
       :max-frame-size
       (%websocket-http2-3-connection-effective-frame-size connection)
       :max-header-block-bytes
       (websocket-http2-3-connection-max-header-block-bytes connection)
       :max-continuation-frames
       (websocket-http2-3-connection-max-continuation-frames connection))
      (encode-websocket-http3-headers-frame
       headers stream-id
       :request-p request-p
       :context
       (websocket-http2-3-connection-h3-qpack-encoder-table connection)
       :huffman-p
       (websocket-http2-3-connection-h3-qpack-huffman-p connection)
       :max-frame-size
       (%websocket-http2-3-connection-effective-frame-size connection)
       :max-header-block-bytes
       (%websocket-http2-3-connection-peer-http3-field-section-size
        connection))))

(defun %websocket-http2-3-connection-parse-header-arguments
    (connection args)
  (let ((headers nil)
        (authority nil)
        (scheme "https")
        (path "/")
        (session-initargs nil)
        (end-stream-p nil)
        (headers-supplied-p nil))
    (when (and args
               (or (null (car args))
                   (%websocket-http2-3-header-list-p (car args))))
      (setf headers (car args)
            headers-supplied-p t
            args (cdr args)))
    (when (and args (http-header-p (car args)))
      (let ((collected nil))
        (loop while (and args (http-header-p (car args)))
              do (push (car args) collected)
                 (setf args (cdr args)))
        (setf headers (nreverse collected)
              headers-supplied-p t)))
    (setf authority (getf args :authority authority)
          scheme (getf args :scheme scheme)
          path (getf args :path path)
          session-initargs (or (getf args :session-initargs)
                               (getf args :initargs))
          end-stream-p (getf args :end-stream-p end-stream-p))
    (when (member :headers args :test #'eq)
      (setf headers (getf args :headers)
            headers-supplied-p t))
    (unless headers-supplied-p
      (unless authority
        (%websocket-http2-3-fail
         "Opening a WebSocket HTTP/2 or HTTP/3 stream requires HEADERS or AUTHORITY."))
      (setf headers
            (if (eq (getf args :protocol :websocket) :websocket)
                (if (eq (websocket-http2-3-connection-protocol connection) :http3)
                    (make-websocket-http3-connect-headers
                     authority :scheme scheme :path path
                     :headers (getf args :headers))
                    (make-websocket-http2-connect-headers
                     authority :scheme scheme :path path
                     :headers (getf args :headers)))
                (getf args :headers))))
    (unless headers
      (%websocket-http2-3-fail
       "Opening a WebSocket HTTP/2 or HTTP/3 stream requires non-NIL HEADERS."))
    (values headers session-initargs end-stream-p)))

(defun %websocket-http2-3-header-list-p (value)
  (and (listp value)
       (or (null value)
           (http-header-p (car value)))))

(defun %websocket-http2-3-connection-validate-open-headers
    (connection headers request-p)
  (unless (if (eq (websocket-http2-3-connection-protocol connection) :http2)
              (if request-p
                  (websocket-http2-extended-connect-p headers)
                  (websocket-http2-connect-response-p headers))
              (if request-p
                  (websocket-http3-extended-connect-p headers)
                  (websocket-http3-connect-response-p headers)))
    (%websocket-http2-3-fail
     "The HTTP/2 or HTTP/3 stream headers are not a valid WebSocket extended CONNECT section."
     :detail headers))
  headers)

(defun %websocket-http2-3-connection-accept-header-section
    (connection stream headers request-p trailers-p end-stream-p)
  (when (websocket-http2-3-stream-remote-end-p stream)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 stream received headers after END_STREAM."
     :detail stream))
  (when (and trailers-p
             (or (not (websocket-http2-3-stream-headers-seen-p stream))
                 (websocket-http2-3-stream-trailers stream)))
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 stream received an invalid duplicate trailer section."
     :detail stream))
  (unless trailers-p
    (%websocket-http2-3-connection-validate-open-headers
     connection headers request-p))
  (if trailers-p
      (setf (websocket-http2-3-stream-trailers stream) headers)
      (setf (websocket-http2-3-stream-headers stream) headers
            (websocket-http2-3-stream-headers-seen-p stream) t))
  (when end-stream-p
    (setf (websocket-http2-3-stream-remote-end-p stream) t))
  (when (and (not trailers-p)
             (not (websocket-http2-3-stream-established-p stream)))
    (setf (websocket-http2-3-stream-established-p stream) t)
    (%websocket-http2-3-connection-call-stream-open connection stream))
  stream)

(defun %websocket-http2-3-connection-frame-payload
    (frame)
  (subseq frame 9))

(defun %websocket-http2-3-connection-h2-process-settings
    (connection frame)
  (let ((flags (%websocket-http2-3-connection-http2-frame-flags frame))
        (stream-id (%websocket-http2-3-connection-http2-frame-stream-id frame))
        (payload (%websocket-http2-3-connection-frame-payload frame)))
    (unless (zerop stream-id)
      (%websocket-http2-3-fail
       "An HTTP/2 SETTINGS frame must use stream zero."))
    (if (logtest 1 flags)
        (progn
          (unless (websocket-http2-3-connection-local-settings-ack-pending-p
                   connection)
            (%websocket-http2-3-fail
             "An HTTP/2 SETTINGS ACK was not requested."))
          (unless (zerop (length payload))
            (%websocket-http2-3-fail
             "An HTTP/2 SETTINGS ACK must have an empty payload."))
          (setf (websocket-http2-3-connection-local-settings-ack-pending-p
                 connection)
                nil))
        (progn
          (%websocket-http2-3-connection-apply-settings
           connection (%websocket-http2-3-connection-parse-settings payload))
          (%websocket-http2-3-connection-write
           connection (%websocket-http2-3-connection-encode-settings nil
                                                                       :ack-p t)
           :stream-id 0)))
    t))

(defun %websocket-http2-3-connection-h2-process-window-update
    (connection frame)
  (let ((stream-id (%websocket-http2-3-connection-http2-frame-stream-id frame))
        (payload (%websocket-http2-3-connection-frame-payload frame)))
    (unless (= (length payload) 4)
      (%websocket-http2-3-fail
       "An HTTP/2 WINDOW_UPDATE frame must contain four octets."))
    (let ((increment
            (logand #x7fffffff
                    (logior (ash (aref payload 0) 24)
                            (ash (aref payload 1) 16)
                            (ash (aref payload 2) 8)
                            (aref payload 3)))))
      (when (zerop increment)
        (%websocket-http2-3-fail
         "An HTTP/2 WINDOW_UPDATE increment must be non-zero."))
      (if (zerop stream-id)
          (let ((window (+ (websocket-http2-3-connection-send-window connection)
                           increment)))
            (when (> window #x7fffffff)
              (error 'websocket-flow-control-error
                     :message "The HTTP/2 connection send window overflowed."
                     :operation :window-update
                     :window window
                     :required increment
                     :kind :connection))
            (setf (websocket-http2-3-connection-send-window connection) window))
          (let ((stream (gethash stream-id
                                 (websocket-http2-3-connection-streams connection))))
            (unless stream
              (%websocket-http2-3-fail
               "An HTTP/2 WINDOW_UPDATE referenced an unknown stream."
               :detail stream-id))
            (let ((window (+ (websocket-http2-3-stream-send-window stream)
                             increment)))
              (when (> window #x7fffffff)
                (error 'websocket-flow-control-error
                       :message "The HTTP/2 stream send window overflowed."
                       :operation :window-update
                       :window window
                       :required increment
                       :kind :stream))
              (setf (websocket-http2-3-stream-send-window stream) window)))))
    t))

(defun %websocket-http2-3-connection-h2-process-data
    (connection frame)
  (let* ((stream-id (%websocket-http2-3-connection-http2-frame-stream-id frame))
         (stream (gethash stream-id
                          (websocket-http2-3-connection-streams connection)))
         (raw-payload (%websocket-http2-3-connection-frame-payload frame))
         (payload (%websocket-http2-3-data-payload
                   (multiple-value-bind (decoded used)
                       (%websocket-http2-3-decode-http2-frame
                        frame
                        :max-payload-bytes
                        (websocket-http2-3-connection-max-frame-size connection))
                     (declare (ignore used))
                     decoded)))
         (end-stream-p
           (logtest 1 (%websocket-http2-3-connection-http2-frame-flags frame))))
    (declare (ignore payload))
    (unless stream
      (%websocket-http2-3-fail
       "An HTTP/2 DATA frame referenced an unknown stream."
       :detail stream-id))
    (unless (websocket-http2-3-stream-headers-seen-p stream)
      (%websocket-http2-3-fail
       "An HTTP/2 DATA frame arrived before the stream HEADERS."))
    (when (websocket-http2-3-stream-remote-end-p stream)
      (%websocket-http2-3-fail
       "An HTTP/2 DATA frame arrived after the stream ended."
       :detail stream-id))
    (let ((amount (length raw-payload)))
      (when (< (websocket-http2-3-connection-receive-window connection)
               amount)
        (error 'websocket-flow-control-error
               :message "The HTTP/2 connection receive window is insufficient."
               :operation :read
               :window (websocket-http2-3-connection-receive-window connection)
               :required amount
               :kind :connection))
      (when (< (websocket-http2-3-stream-receive-window stream) amount)
        (error 'websocket-flow-control-error
               :message "The HTTP/2 stream receive window is insufficient."
               :operation :read
               :window (websocket-http2-3-stream-receive-window stream)
               :required amount
               :kind :stream))
      (decf (websocket-http2-3-connection-receive-window connection) amount)
      (decf (websocket-http2-3-stream-receive-window stream) amount))
    (%websocket-http2-3-connection-enqueue
     stream frame end-stream-p (length raw-payload))
    t))

(defun %websocket-http2-3-connection-h2-process-rst
    (connection frame)
  (let* ((stream-id (%websocket-http2-3-connection-http2-frame-stream-id frame))
         (stream (gethash stream-id
                          (websocket-http2-3-connection-streams connection)))
         (payload (%websocket-http2-3-connection-frame-payload frame)))
    (unless (= (length payload) 4)
      (%websocket-http2-3-fail
       "An HTTP/2 RST_STREAM frame must contain four octets."))
    (unless stream
      (%websocket-http2-3-fail
       "An HTTP/2 RST_STREAM frame referenced an unknown stream."
       :detail stream-id))
    (decf (websocket-http2-3-connection-unconsumed-receive-bytes connection)
          (websocket-http2-3-stream-unconsumed-receive-bytes stream))
    (setf (websocket-http2-3-stream-inbound-frames stream) nil
          (websocket-http2-3-stream-inbound-frame-tail stream) nil
          (websocket-http2-3-stream-unconsumed-receive-bytes stream) 0
          (websocket-http2-3-stream-remote-end-p stream) t
          (websocket-http2-3-stream-local-end-p stream) t)
    (when (websocket-http2-3-stream-session stream)
      (setf (websocket-http2-3-session-closed-p
             (websocket-http2-3-stream-session stream)) t))
    (%websocket-http2-3-connection-call-stream-close connection stream t)
    t))

(defun %websocket-http2-3-connection-h2-process-goaway
    (connection frame)
  (let ((payload (%websocket-http2-3-connection-frame-payload frame)))
    (when (< (length payload) 8)
      (%websocket-http2-3-fail
       "An HTTP/2 GOAWAY frame must contain at least eight octets."))
    (let ((last-stream-id
            (logand #x7fffffff
                    (logior (ash (aref payload 0) 24)
                            (ash (aref payload 1) 16)
                            (ash (aref payload 2) 8)
                            (aref payload 3)))))
      (when (and (websocket-http2-3-connection-goaway-last-stream-id connection)
                 (> last-stream-id
                    (websocket-http2-3-connection-goaway-last-stream-id
                     connection)))
        (%websocket-http2-3-fail
         "An HTTP/2 GOAWAY last-stream identifier increased."))
      (setf (websocket-http2-3-connection-goaway-last-stream-id connection)
            last-stream-id))
    t))

(defun %websocket-http2-3-connection-h2-process-ping
    (connection frame)
  (let ((flags (%websocket-http2-3-connection-http2-frame-flags frame))
        (payload (%websocket-http2-3-connection-frame-payload frame)))
    (unless (= (length payload) 8)
      (%websocket-http2-3-fail "An HTTP/2 PING frame must contain eight octets."))
    (unless (logtest 1 flags)
      (%websocket-http2-3-connection-write
       connection
       (%websocket-http2-3-encode-http2-frame :ping 1 0 payload)
       :stream-id 0))
    t))

(defun %websocket-http2-3-connection-h2-accept-header-wire
    (connection wire)
  (multiple-value-bind (headers used stream-id end-stream-p)
      (decode-websocket-http2-headers-frames
       wire
       :request-p (eq (websocket-http2-3-connection-role connection) :server)
       :context
       (websocket-http2-3-connection-hpack-decoder-context connection)
       :max-frame-size
       (websocket-http2-3-connection-max-frame-size connection)
       :max-header-block-bytes
       (websocket-http2-3-connection-max-header-block-bytes connection)
       :max-continuation-frames
       (websocket-http2-3-connection-max-continuation-frames connection))
    (unless (= used (length wire))
      (%websocket-http2-3-fail
       "An HTTP/2 header sequence contained trailing bytes."))
    (let* ((stream (gethash stream-id
                            (websocket-http2-3-connection-streams connection)))
           (trailers-p (and stream
                            (websocket-http2-3-stream-established-p stream))))
      (unless stream
        (unless (%websocket-http2-3-connection-peer-bidi-stream-p
                 connection stream-id)
          (%websocket-http2-3-fail
           "An HTTP/2 peer opened a stream with the wrong initiator parity."
           :detail stream-id))
        (when (and (websocket-http2-3-connection-last-peer-stream-id connection)
                   (<= stream-id
                       (websocket-http2-3-connection-last-peer-stream-id connection)))
          (%websocket-http2-3-fail
           "An HTTP/2 peer opened a stream out of order."
           :detail stream-id))
        (setf (websocket-http2-3-connection-last-peer-stream-id connection)
              stream-id)
        (setf stream
              (%websocket-http2-3-connection-make-stream
               connection stream-id
               :request-p
               (eq (websocket-http2-3-connection-role connection) :server))))
      (%websocket-http2-3-connection-accept-header-section
       connection stream headers
       (eq (websocket-http2-3-connection-role connection) :server)
       trailers-p end-stream-p))))

(defun %websocket-http2-3-connection-h2-process-frame
    (connection frame)
  (let ((type (%websocket-http2-3-connection-http2-frame-type frame))
        (flags (%websocket-http2-3-connection-http2-frame-flags frame))
        (stream-id (%websocket-http2-3-connection-http2-frame-stream-id frame)))
    (when (and (websocket-http2-3-connection-pending-header-wire connection)
               (/= type 9))
      (%websocket-http2-3-fail
       "An HTTP/2 header block was interrupted by a non-CONTINUATION frame."))
    (case type
      (0
       (unless (plusp stream-id)
         (%websocket-http2-3-fail "An HTTP/2 DATA frame requires a stream."))
       (%websocket-http2-3-connection-h2-process-data connection frame))
      (1
       (unless (plusp stream-id)
         (%websocket-http2-3-fail "An HTTP/2 HEADERS frame requires a stream."))
       (when (logtest #x20 flags)
         (let ((minimum (if (logtest #x8 flags) 6 5)))
           (when (< (length (%websocket-http2-3-connection-frame-payload frame))
                    minimum)
             (%websocket-http2-3-fail
              "An HTTP/2 PRIORITY HEADERS frame is too short."))))
       (if (logtest #x4 flags)
           (%websocket-http2-3-connection-h2-accept-header-wire connection frame)
           (setf (websocket-http2-3-connection-pending-header-wire connection)
                 (%websocket-http2-3-connection-append
                  (%websocket-http2-3-connection-empty-buffer)
                  frame
                  (websocket-http2-3-connection-max-buffered-wire-bytes connection)
                  "An HTTP/2 header sequence exceeded the connection buffer limit.")
                 (websocket-http2-3-connection-pending-header-stream-id connection)
                 stream-id
                 (websocket-http2-3-connection-pending-header-request-p connection)
                 (eq (websocket-http2-3-connection-role connection) :server)
                 (websocket-http2-3-connection-pending-header-trailers-p connection)
                 nil)))
      (3
       (unless (plusp stream-id)
         (%websocket-http2-3-fail "An HTTP/2 RST_STREAM frame requires a stream."))
       (%websocket-http2-3-connection-h2-process-rst connection frame))
      (4
       (unless (zerop stream-id)
         (%websocket-http2-3-fail
          "An HTTP/2 SETTINGS frame must use stream zero."))
       (%websocket-http2-3-connection-h2-process-settings connection frame))
      (6
       (unless (zerop stream-id)
         (%websocket-http2-3-fail "An HTTP/2 PING frame must use stream zero."))
       (%websocket-http2-3-connection-h2-process-ping connection frame))
      (7
       (unless (zerop stream-id)
         (%websocket-http2-3-fail "An HTTP/2 GOAWAY frame must use stream zero."))
       (%websocket-http2-3-connection-h2-process-goaway connection frame))
      (8
       (%websocket-http2-3-connection-h2-process-window-update connection frame))
      (9
       (unless (plusp stream-id)
         (%websocket-http2-3-fail
          "An HTTP/2 CONTINUATION frame requires a stream."))
       (unless (and (websocket-http2-3-connection-pending-header-wire connection)
                    (= stream-id
                       (websocket-http2-3-connection-pending-header-stream-id
                        connection)))
         (%websocket-http2-3-fail
          "An HTTP/2 CONTINUATION frame arrived without a matching HEADERS frame."))
       (let ((wire
               (%websocket-http2-3-connection-append
                (websocket-http2-3-connection-pending-header-wire connection)
                frame
                (websocket-http2-3-connection-max-buffered-wire-bytes connection)
                "An HTTP/2 header sequence exceeded the connection buffer limit.")))
         (if (logtest #x4 flags)
             (progn
               (setf (websocket-http2-3-connection-pending-header-wire connection) nil)
               (%websocket-http2-3-connection-h2-accept-header-wire connection wire))
             (setf (websocket-http2-3-connection-pending-header-wire connection)
                   wire))))
      (otherwise nil))
    t))

(defun %websocket-http2-3-connection-feed-http2-legacy
    (connection octets &key end-stream-p)
  (when end-stream-p
    (setf (websocket-http2-3-connection-remote-end-p connection) t))
  (let ((input (%websocket-http2-3-connection-copy-octets octets)))
    (unless (websocket-http2-3-connection-preface-received-p connection)
      (if (eq (websocket-http2-3-connection-role connection) :server)
          (progn
            (setf (websocket-http2-3-connection-preface-buffer connection)
                  (%websocket-http2-3-connection-append
                   (websocket-http2-3-connection-preface-buffer connection)
                   input 24
                   "The HTTP/2 connection preface exceeded 24 octets."))
            (let ((prefix
                    (websocket-http2-3-connection-preface-buffer connection))
                  (expected (websocket-http2-connection-preface)))
              (loop for index below (fill-pointer prefix)
                    unless (= (aref prefix index) (aref expected index))
                    do (%websocket-http2-3-fail
                        "The HTTP/2 client connection preface is invalid."))
              (when (= (fill-pointer prefix) 24)
                (setf (websocket-http2-3-connection-preface-received-p connection) t
                      (websocket-http2-3-connection-preface-buffer connection)
                      (%websocket-http2-3-connection-empty-buffer)))))
          (setf (websocket-http2-3-connection-preface-received-p connection) t)))
    (when (and (eq (websocket-http2-3-connection-role connection) :server)
               (not (websocket-http2-3-connection-preface-received-p connection)))
      (return-from %websocket-http2-3-connection-feed-http2-legacy connection))
    (when (and (eq (websocket-http2-3-connection-role connection) :server)
               (fill-pointer
                (websocket-http2-3-connection-preface-buffer connection)))
      (setf input nil))
    (when (and (eq (websocket-http2-3-connection-role connection) :server)
               (= (fill-pointer
                   (websocket-http2-3-connection-preface-buffer connection)) 0)
               (not (equal input octets)))
      (setf input (%websocket-http2-3-connection-drop-prefix
                   (%websocket-http2-3-connection-copy-octets octets) 24)))
    (when (and (eq (websocket-http2-3-connection-role connection) :server)
               (= (length input) (length octets))
               (not (zerop (length octets)))
               (= (fill-pointer
                   (websocket-http2-3-connection-preface-buffer connection)) 0)
               (not (websocket-http2-3-connection-peer-settings-seen-p connection))
               (< (length octets) 24))
      (return-from %websocket-http2-3-connection-feed-http2-legacy connection))
    (when (plusp (length input))
      (setf (websocket-http2-3-connection-wire-buffer connection)
            (%websocket-http2-3-connection-append
             (websocket-http2-3-connection-wire-buffer connection)
             input
             (websocket-http2-3-connection-max-buffered-wire-bytes connection)
             "The HTTP/2 connection exceeded its buffered-wire limit.")))
    (loop for length =
            (%websocket-http2-3-connection-http2-frame-length
             (websocket-http2-3-connection-wire-buffer connection))
          while (and length
                      (<= length
                          (fill-pointer
                           (websocket-http2-3-connection-wire-buffer connection))))
          do (let* ((buffer (websocket-http2-3-connection-wire-buffer connection))
                    (frame (subseq buffer 0 length))
                    (type (%websocket-http2-3-connection-http2-frame-type frame)))
               (when (> (- length 9)
                        (websocket-http2-3-connection-max-frame-size connection))
                 (%websocket-http2-3-fail
                  "An HTTP/2 peer exceeded the configured frame-size limit."
                  :detail (- length 9)))
               (setf (websocket-http2-3-connection-wire-buffer connection)
                     (%websocket-http2-3-connection-drop-prefix buffer length))
               (unless (websocket-http2-3-connection-peer-settings-seen-p connection)
                 (unless (= type 4)
                   (%websocket-http2-3-fail
                    "The first HTTP/2 peer frame must be SETTINGS.")))
               (%websocket-http2-3-connection-h2-process-frame connection frame)))
    connection))

(defun %websocket-http2-3-connection-feed-http2
    (connection octets &key end-stream-p)
  (let* ((input (%websocket-http2-3-connection-copy-octets octets))
         (offset 0)
         (server-p (eq (websocket-http2-3-connection-role connection)
                       :server)))
    (when (and server-p
               (not (websocket-http2-3-connection-preface-received-p
                     connection)))
      (let ((expected (websocket-http2-connection-preface))
            (prefix
              (websocket-http2-3-connection-preface-buffer connection)))
        (loop while (and (< offset (length input))
                         (< (fill-pointer prefix) 24))
              do (let ((index (fill-pointer prefix)))
                   (unless (= (aref input offset) (aref expected index))
                     (%websocket-http2-3-fail
                      "The HTTP/2 client connection preface is invalid."))
                   (vector-push-extend (aref input offset) prefix)
                   (incf offset)))
        (when (= (fill-pointer prefix) 24)
          (setf (websocket-http2-3-connection-preface-received-p connection) t
                (websocket-http2-3-connection-preface-buffer connection)
                (%websocket-http2-3-connection-empty-buffer)))))
    (unless (or (not server-p)
                (websocket-http2-3-connection-preface-received-p connection))
      (when end-stream-p
        (%websocket-http2-3-fail
         "The HTTP/2 connection ended before its client preface completed."))
      (return-from %websocket-http2-3-connection-feed-http2 connection))
    (when (< offset (length input))
      (setf (websocket-http2-3-connection-wire-buffer connection)
            (%websocket-http2-3-connection-append
             (websocket-http2-3-connection-wire-buffer connection)
             (subseq input offset)
             (websocket-http2-3-connection-max-buffered-wire-bytes connection)
             "The HTTP/2 connection exceeded its buffered-wire limit.")))
    (loop for length =
            (%websocket-http2-3-connection-http2-frame-length
             (websocket-http2-3-connection-wire-buffer connection))
          while (and length
                      (<= length
                          (fill-pointer
                           (websocket-http2-3-connection-wire-buffer connection))))
          do (let* ((buffer (websocket-http2-3-connection-wire-buffer connection))
                    (frame (subseq buffer 0 length))
                    (type (%websocket-http2-3-connection-http2-frame-type frame)))
               (when (> (- length 9)
                        (websocket-http2-3-connection-max-frame-size connection))
                 (%websocket-http2-3-fail
                  "An HTTP/2 peer exceeded the configured frame-size limit."
                  :detail (- length 9)))
               (setf (websocket-http2-3-connection-wire-buffer connection)
                     (%websocket-http2-3-connection-drop-prefix buffer length))
               (unless (websocket-http2-3-connection-peer-settings-seen-p
                        connection)
                 (unless (= type 4)
                   (%websocket-http2-3-fail
                    "The first HTTP/2 peer frame must be SETTINGS.")))
               (%websocket-http2-3-connection-h2-process-frame
                connection frame)))
    (when end-stream-p
      (when (websocket-http2-3-connection-pending-header-wire connection)
        (%websocket-http2-3-fail
         "The HTTP/2 connection ended with an incomplete header block."))
      (when (plusp (fill-pointer
                    (websocket-http2-3-connection-wire-buffer connection)))
        (%websocket-http2-3-fail
         "The HTTP/2 connection ended with an incomplete frame."))
      (unless (websocket-http2-3-connection-peer-settings-seen-p connection)
        (%websocket-http2-3-fail
         "The HTTP/2 connection ended before peer SETTINGS."))
      (setf (websocket-http2-3-connection-remote-end-p connection) t))
    connection))

(defun %websocket-http2-3-connection-h3-frame-complete-p
    (buffer)
  (multiple-value-bind (type payload-length after-length)
      (%websocket-http2-3-connection-h3-frame-header buffer)
    (when type
      (let ((end (+ after-length payload-length)))
        (when (<= end (fill-pointer buffer))
          (values type payload-length after-length end))))))

(defun %websocket-http2-3-connection-qpack-integer-end
    (buffer position prefix-bits)
  (let ((limit (fill-pointer buffer)))
    (cond
      ((or (< prefix-bits 1)
           (> prefix-bits 8)
           (< position 0)
           (> position limit))
       (values :invalid nil nil))
      ((= position limit)
       (values :incomplete nil nil))
      (t
       (let* ((mask (1- (ash 1 prefix-bits)))
              (first (aref buffer position))
              (value (logand first mask)))
         (if (< value mask)
             (values :complete (1+ position) value)
             (loop with result = value
                   with shift = 0
                   for index from (1+ position) below limit
                   for octet = (aref buffer index)
                   do (incf result (* (logand octet #x7f)
                                      (ash 1 shift)))
                      (if (zerop (logand octet #x80))
                          (return (values :complete (1+ index) result))
                          (incf shift 7))
                   finally (return (values :incomplete nil nil)))))))))

(defun %websocket-http2-3-connection-qpack-string-end
    (buffer position prefix-bits)
  (multiple-value-bind (status after-length string-length)
      (%websocket-http2-3-connection-qpack-integer-end
       buffer position prefix-bits)
    (if (eq status :complete)
        (let ((end (+ after-length string-length)))
          (if (<= end (fill-pointer buffer))
              (values :complete end)
              (values :incomplete nil)))
        (values status nil))))

(defun %websocket-http2-3-connection-qpack-encoder-instruction-end
    (buffer)
  (if (zerop (fill-pointer buffer))
      (values :incomplete nil)
      (let ((first (aref buffer 0)))
        (cond
          ((= (logand first #xe0) #x20)
           (multiple-value-bind (status end ignored)
               (%websocket-http2-3-connection-qpack-integer-end
                buffer 0 5)
             (declare (ignore ignored))
             (values status end)))
          ((not (zerop (logand first #x80)))
           (multiple-value-bind (status after-name ignored)
               (%websocket-http2-3-connection-qpack-integer-end
                buffer 0 6)
             (declare (ignore ignored))
             (if (eq status :complete)
                 (%websocket-http2-3-connection-qpack-string-end
                  buffer after-name 7)
                 (values status nil))))
          ((= (logand first #xc0) #x40)
           (multiple-value-bind (status after-name)
               (%websocket-http2-3-connection-qpack-string-end
                buffer 0 5)
             (if (eq status :complete)
                 (%websocket-http2-3-connection-qpack-string-end
                  buffer after-name 7)
                 (values status nil))))
          (t
           (multiple-value-bind (status end ignored)
               (%websocket-http2-3-connection-qpack-integer-end
                buffer 0 5)
             (declare (ignore ignored))
             (values status end)))))))

(defun %websocket-http2-3-connection-qpack-decoder-instruction-end
    (buffer)
  (if (zerop (fill-pointer buffer))
      (values :incomplete nil)
      (let ((first (aref buffer 0)))
        (multiple-value-bind (status end ignored)
            (%websocket-http2-3-connection-qpack-integer-end
             buffer 0 (if (not (zerop (logand first #x80))) 7 6))
          (declare (ignore ignored))
          (values status end)))))

(defun %websocket-http2-3-connection-qpack-wire-complete-p
    (octets scanner message)
  (let ((buffer (%websocket-http2-3-connection-copy-octets octets)))
    (loop while (plusp (fill-pointer buffer)) do
      (multiple-value-bind (status end)
          (funcall scanner buffer)
        (case status
          (:complete
           (setf buffer
                 (%websocket-http2-3-connection-drop-prefix buffer end)))
          (:incomplete
           (%websocket-http2-3-fail message))
          (otherwise
           (%websocket-http2-3-fail
            "An HTTP/3 QPACK instruction is malformed."
            :detail status)))))
    t))

(defun %websocket-http2-3-connection-process-http3-qpack-encoder-wire
    (connection)
  (let ((buffer (websocket-http2-3-connection-h3-qpack-encoder-wire-buffer
                connection))
        (table (websocket-http2-3-connection-h3-qpack-decoder-table
                connection)))
    (loop while (plusp (fill-pointer buffer)) do
      (multiple-value-bind (status end)
          (%websocket-http2-3-connection-qpack-encoder-instruction-end
           buffer)
        (case status
          (:incomplete (return connection))
          (:invalid
           (%websocket-http2-3-fail
            "An HTTP/3 QPACK encoder instruction is malformed."))
          (:complete
           (let ((instruction (subseq buffer 0 end)))
             (multiple-value-bind (events consumed)
                 (handler-case
                     (http-kit/http3:qpack-process-encoder-stream
                      table instruction)
                   (error (condition)
                     (%websocket-http2-3-fail
                      "An HTTP/3 QPACK encoder instruction was rejected."
                      :detail condition)))
               (unless (= consumed (length instruction))
                 (%websocket-http2-3-fail
                  "An HTTP/3 QPACK encoder instruction was not fully consumed."))
               (setf buffer
                     (%websocket-http2-3-connection-drop-prefix buffer end)
                     (websocket-http2-3-connection-h3-qpack-encoder-events
                      connection)
                     (append
                      (websocket-http2-3-connection-h3-qpack-encoder-events
                       connection)
                      events))))))))
    connection))

(defun %websocket-http2-3-connection-process-http3-qpack-decoder-wire
    (connection)
  (let ((buffer (websocket-http2-3-connection-h3-qpack-decoder-wire-buffer
                connection)))
    (loop while (plusp (fill-pointer buffer)) do
      (multiple-value-bind (status end)
          (%websocket-http2-3-connection-qpack-decoder-instruction-end
           buffer)
        (case status
          (:incomplete (return connection))
          (:invalid
           (%websocket-http2-3-fail
            "An HTTP/3 QPACK decoder instruction is malformed."))
          (:complete
           (let ((instruction (subseq buffer 0 end)))
             (multiple-value-bind (events consumed)
                 (handler-case
                     (http-kit/http3:qpack-process-decoder-stream instruction)
                   (error (condition)
                     (%websocket-http2-3-fail
                      "An HTTP/3 QPACK decoder instruction was rejected."
                      :detail condition)))
               (unless (= consumed (length instruction))
                 (%websocket-http2-3-fail
                  "An HTTP/3 QPACK decoder instruction was not fully consumed."))
               (setf buffer
                     (%websocket-http2-3-connection-drop-prefix buffer end)
                     (websocket-http2-3-connection-h3-qpack-decoder-events
                      connection)
                     (append
                      (websocket-http2-3-connection-h3-qpack-decoder-events
                       connection)
                      events))))))))
    connection))

(defun %websocket-http2-3-connection-feed-http3-qpack-encoder
    (connection octets &key fin-p)
  (when fin-p
    (%websocket-http2-3-fail
     "An HTTP/3 QPACK encoder stream must not be closed."))
  (%websocket-http2-3-connection-append
   (websocket-http2-3-connection-h3-qpack-encoder-wire-buffer connection)
   octets
   (websocket-http2-3-connection-max-buffered-wire-bytes connection)
   "HTTP/3 QPACK encoder buffering exceeds the configured limit.")
  (%websocket-http2-3-connection-process-http3-qpack-encoder-wire connection))

(defun %websocket-http2-3-connection-feed-http3-qpack-decoder
    (connection octets &key fin-p)
  (when fin-p
    (%websocket-http2-3-fail
     "An HTTP/3 QPACK decoder stream must not be closed."))
  (%websocket-http2-3-connection-append
   (websocket-http2-3-connection-h3-qpack-decoder-wire-buffer connection)
   octets
   (websocket-http2-3-connection-max-buffered-wire-bytes connection)
   "HTTP/3 QPACK decoder buffering exceeds the configured limit.")
  (%websocket-http2-3-connection-process-http3-qpack-decoder-wire connection))

(defun %websocket-http2-3-connection-send-http3-qpack-wire
    (connection octets encoder-p)
  (let ((wire (%websocket-http2-3-connection-copy-octets octets)))
    (unless (plusp (length wire))
      (%websocket-http2-3-fail
       "An HTTP/3 QPACK instruction stream write cannot be empty."))
    (%websocket-http2-3-connection-qpack-wire-complete-p
     wire
     (if encoder-p
         #'%websocket-http2-3-connection-qpack-encoder-instruction-end
         #'%websocket-http2-3-connection-qpack-decoder-instruction-end)
     (if encoder-p
         "An HTTP/3 QPACK encoder instruction stream ended mid-instruction."
         "An HTTP/3 QPACK decoder instruction stream ended mid-instruction."))
    (if encoder-p
        (multiple-value-bind (events consumed)
            (handler-case
                (http-kit/http3:qpack-process-encoder-stream
                 (websocket-http2-3-connection-h3-qpack-encoder-table
                  connection)
                 wire)
              (error (condition)
                (%websocket-http2-3-fail
                 "An HTTP/3 local QPACK encoder instruction was rejected."
                 :detail condition)))
          (unless (= consumed (length wire))
            (%websocket-http2-3-fail
             "An HTTP/3 local QPACK encoder instruction was not fully consumed."))
          (setf (websocket-http2-3-connection-h3-qpack-encoder-events connection)
                (append
                 (websocket-http2-3-connection-h3-qpack-encoder-events
                  connection)
                 events)))
        (multiple-value-bind (events consumed)
            (handler-case
                (http-kit/http3:qpack-process-decoder-stream wire)
              (error (condition)
                (%websocket-http2-3-fail
                 "An HTTP/3 local QPACK decoder instruction was rejected."
                 :detail condition)))
          (unless (= consumed (length wire))
            (%websocket-http2-3-fail
             "An HTTP/3 local QPACK decoder instruction was not fully consumed."))
          (setf (websocket-http2-3-connection-h3-qpack-decoder-events connection)
                (append
                 (websocket-http2-3-connection-h3-qpack-decoder-events
                  connection)
                 events))))
    (%websocket-http2-3-connection-write
     connection wire
     :stream-id
     (if encoder-p
         (websocket-http2-3-connection-h3-qpack-encoder-stream-id connection)
         (websocket-http2-3-connection-h3-qpack-decoder-stream-id connection)))
    wire))

(defun %websocket-http2-3-connection-set-http3-qpack-encoder-capacity
    (connection capacity)
  (let* ((table (websocket-http2-3-connection-h3-qpack-encoder-table
                 connection))
         (target
           (min capacity
                (http-kit/http3:qpack-dynamic-table-max-capacity table)))
         (current (http-kit/http3:qpack-dynamic-table-capacity table)))
    (unless (= current target)
      (let ((wire
              (http-kit/http3:qpack-encode-set-dynamic-table-capacity target)))
        (handler-case
            (http-kit/http3:qpack-dynamic-table-set-capacity table target)
          (error (condition)
            (%websocket-http2-3-fail
             "An HTTP/3 QPACK encoder capacity update was rejected."
             :detail condition)))
        (%websocket-http2-3-connection-write
         connection wire
         :stream-id
         (websocket-http2-3-connection-h3-qpack-encoder-stream-id connection))
        wire))))

(defun websocket-http3-connection-send-qpack-encoder-instructions
    (connection octets)
  "Apply and send local HTTP/3 QPACK encoder-stream instructions."
  (%websocket-http2-3-connection-ensure-protocol connection :http3)
  (%websocket-http2-3-connection-with-lock (connection)
    (%websocket-http2-3-connection-start-internal connection)
    (%websocket-http2-3-connection-send-http3-qpack-wire
     connection octets t)))

(defun websocket-http3-connection-send-qpack-decoder-instructions
    (connection octets)
  "Validate and send local HTTP/3 QPACK decoder-stream instructions."
  (%websocket-http2-3-connection-ensure-protocol connection :http3)
  (%websocket-http2-3-connection-with-lock (connection)
    (%websocket-http2-3-connection-start-internal connection)
    (%websocket-http2-3-connection-send-http3-qpack-wire
     connection octets nil)))

(defun %websocket-http2-3-connection-check-h3-goaway-id
    (connection stream-id &key local-p)
  (%websocket-http2-3-check-http3-transport-stream-id stream-id)
  (when (and (if local-p
                 (eq (websocket-http2-3-connection-role connection) :server)
                 (eq (websocket-http2-3-connection-role connection) :client))
             (not (zerop (logand stream-id 3))))
    (%websocket-http2-3-fail
     (if local-p
         "An HTTP/3 server GOAWAY must use a client-initiated bidirectional stream identifier."
         "An HTTP/3 GOAWAY from a server must use a client-initiated bidirectional stream identifier.")
     :detail stream-id))
  stream-id)

(defun %websocket-http2-3-connection-h3-process-control-frame
    (connection frame)
  (multiple-value-bind (type payload used)
      (%websocket-http2-3-decode-http3-frame
       frame :max-payload-bytes
       (websocket-http2-3-connection-max-frame-size connection))
    (declare (ignore used))
    (when (member type '(0 1 5) :test #'=)
      (%websocket-http2-3-fail
       "An HTTP/3 request frame appeared on the control stream."
       :detail type))
    (unless (or (= type http-kit/http3:+http3-settings-type+)
                (websocket-http2-3-connection-h3-control-settings-seen-p
                 connection))
      (%websocket-http2-3-fail
       "The first HTTP/3 control-stream frame must be SETTINGS."))
    (when (= type http-kit/http3:+http3-settings-type+)
      (when (websocket-http2-3-connection-h3-control-settings-seen-p connection)
        (%websocket-http2-3-fail
         "An HTTP/3 control stream sent SETTINGS more than once."))
      (multiple-value-bind (settings ignored)
          (decode-websocket-http3-connect-settings frame)
        (declare (ignore ignored))
        (let ((qpack-capacity
                (or (cdr (assoc
                          http-kit/http3:+http3-setting-qpack-max-table-capacity+
                          settings))
                    0))
              (max-field-section-size
                (cdr (assoc
                      http-kit/http3:+http3-setting-max-field-section-size+
                      settings)))
              (blocked-streams
                (or (cdr (assoc
                          http-kit/http3:+http3-setting-qpack-blocked-streams+
                          settings))
                    0)))
          (setf (websocket-http2-3-connection-peer-settings connection) settings
                (websocket-http2-3-connection-peer-settings-seen-p connection) t
                (websocket-http2-3-connection-peer-connect-enabled-p connection)
                (websocket-http3-connect-protocol-enabled-p settings)
                (websocket-http2-3-connection-h3-peer-qpack-max-table-capacity
                 connection)
                qpack-capacity
                (websocket-http2-3-connection-h3-peer-max-field-section-size
                 connection)
                max-field-section-size
                (websocket-http2-3-connection-h3-peer-qpack-blocked-streams
                 connection)
                blocked-streams
                (websocket-http2-3-connection-h3-control-settings-seen-p connection)
                t)
          (%websocket-http2-3-connection-set-http3-qpack-encoder-capacity
           connection qpack-capacity))))
    (when (member type '(3 7 13) :test #'=)
      (multiple-value-bind (value after)
          (%websocket-http2-3-decode-http3-varint payload 0)
        (unless (= after (length payload))
          (%websocket-http2-3-fail
           "An HTTP/3 control-stream variable-length integer has trailing data."
           :detail type))
        (when (= type 7)
          (%websocket-http2-3-connection-check-h3-goaway-id
           connection value)
          (when (and (websocket-http2-3-connection-goaway-last-stream-id connection)
                     (> value
                        (websocket-http2-3-connection-goaway-last-stream-id
                         connection)))
            (%websocket-http2-3-fail
             "An HTTP/3 GOAWAY stream identifier increased."))
          (setf (websocket-http2-3-connection-goaway-last-stream-id connection)
                value))))
    t))

(defun %websocket-http2-3-connection-h3-accept-header
    (connection stream frame)
  (multiple-value-bind (headers used ignored)
      (decode-websocket-http3-headers-frame
       frame
       :expected-stream-id (websocket-http2-3-stream-id stream)
       :context
       (websocket-http2-3-connection-h3-qpack-decoder-table connection)
       :request-p (eq (websocket-http2-3-connection-role connection) :server)
       :max-frame-size
       (websocket-http2-3-connection-max-frame-size connection)
       :max-header-block-bytes
       (%websocket-http2-3-connection-local-http3-field-section-size
        connection))
    (declare (ignore ignored))
    (unless (= used (length frame))
      (%websocket-http2-3-fail
       "An HTTP/3 HEADERS frame contained trailing bytes."))
    (%websocket-http2-3-connection-accept-header-section
     connection stream headers
     (eq (websocket-http2-3-connection-role connection) :server)
     (websocket-http2-3-stream-established-p stream)
     nil)))

(defun %websocket-http2-3-connection-h3-process-stream-frame
    (connection stream frame)
  (multiple-value-bind (type payload used)
      (%websocket-http2-3-decode-http3-frame
       frame :max-payload-bytes
       (websocket-http2-3-connection-max-frame-size connection))
    (declare (ignore used))
    (case type
      (#.http-kit/http3:+http3-headers-type+
       (if (websocket-http2-3-stream-established-p stream)
           (progn
             (when (websocket-http2-3-stream-remote-end-p stream)
               (%websocket-http2-3-fail
                "An HTTP/3 stream received trailers after END_STREAM."
                :detail stream))
             (multiple-value-bind (headers ignored ignored2)
                 (decode-websocket-http3-headers-frame
                  frame :expected-stream-id
                  (websocket-http2-3-stream-id stream)
                  :request-p (eq (websocket-http2-3-connection-role connection)
                                 :server)
                  :trailers-p t
                  :context
                  (websocket-http2-3-connection-h3-qpack-decoder-table
                   connection)
                  :max-frame-size
                  (websocket-http2-3-connection-max-frame-size connection)
                  :max-header-block-bytes
                  (%websocket-http2-3-connection-local-http3-field-section-size
                   connection))
               (declare (ignore ignored ignored2))
               (%websocket-http2-3-connection-accept-header-section
                connection stream headers
                (eq (websocket-http2-3-connection-role connection) :server)
                t nil)))
           (%websocket-http2-3-connection-h3-accept-header
            connection stream frame)))
      (#.http-kit/http3:+http3-data-type+
       (unless (websocket-http2-3-stream-headers-seen-p stream)
         (%websocket-http2-3-fail
          "An HTTP/3 DATA frame arrived before the stream HEADERS."))
       (when (websocket-http2-3-stream-remote-end-p stream)
         (%websocket-http2-3-fail
          "An HTTP/3 DATA frame arrived after the stream ended."
          :detail (websocket-http2-3-stream-id stream)))
       (when (> (length payload)
                (websocket-http2-3-connection-max-data-bytes connection))
         (%websocket-size-error
          "An HTTP/3 DATA frame exceeds the connection data budget."
          (websocket-http2-3-connection-max-data-bytes connection)
          (length payload)))
       (%websocket-http2-3-connection-enqueue
        stream frame nil (length payload)))
      (otherwise nil))
    t))

(defun %websocket-http2-3-connection-feed-http3-control
    (connection octets &key fin-p)
  (when fin-p
    (%websocket-http2-3-fail
     "An HTTP/3 control stream must not be closed by its peer."))
  (setf (websocket-http2-3-connection-h3-control-wire-buffer connection)
        (%websocket-http2-3-connection-append
         (websocket-http2-3-connection-h3-control-wire-buffer connection)
         octets
         (websocket-http2-3-connection-max-buffered-wire-bytes connection)
         "The HTTP/3 control stream exceeded its buffered-wire limit."))
  (loop for complete =
          (multiple-value-list
           (%websocket-http2-3-connection-h3-frame-complete-p
            (websocket-http2-3-connection-h3-control-wire-buffer connection)))
        while (first complete)
        do (let* ((buffer
                    (websocket-http2-3-connection-h3-control-wire-buffer connection))
                  (end (fourth complete))
                  (frame (subseq buffer 0 end)))
             (setf (websocket-http2-3-connection-h3-control-wire-buffer connection)
                   (%websocket-http2-3-connection-drop-prefix buffer end))
             (%websocket-http2-3-connection-h3-process-control-frame
              connection frame)))
  (when (and fin-p
             (plusp
              (fill-pointer
               (websocket-http2-3-connection-h3-control-wire-buffer connection))))
    (%websocket-http2-3-fail
     "The HTTP/3 control stream ended with an incomplete frame."))
  connection)

(defun %websocket-http2-3-connection-feed-http3-bidi
    (connection stream octets &key fin-p)
  (when (websocket-http2-3-stream-remote-end-p stream)
    (%websocket-http2-3-fail
     "An HTTP/3 WebSocket stream received bytes after FIN."
     :detail (websocket-http2-3-stream-id stream)))
  (setf (websocket-http2-3-stream-wire-buffer stream)
        (%websocket-http2-3-connection-append
         (websocket-http2-3-stream-wire-buffer stream)
         octets
         (websocket-http2-3-connection-max-buffered-wire-bytes connection)
         "An HTTP/3 stream exceeded its buffered-wire limit."))
  (loop for complete =
          (multiple-value-list
           (%websocket-http2-3-connection-h3-frame-complete-p
            (websocket-http2-3-stream-wire-buffer stream)))
        while (first complete)
        do (let* ((buffer (websocket-http2-3-stream-wire-buffer stream))
                  (end (fourth complete))
                  (frame (subseq buffer 0 end)))
             (setf (websocket-http2-3-stream-wire-buffer stream)
                   (%websocket-http2-3-connection-drop-prefix buffer end))
             (unless (websocket-http2-3-stream-headers-seen-p stream)
               (unless (= (first complete) http-kit/http3:+http3-headers-type+)
                 (%websocket-http2-3-fail
                  "The first HTTP/3 WebSocket stream frame must be HEADERS.")))
             (%websocket-http2-3-connection-h3-process-stream-frame
              connection stream frame)))
  (when (and fin-p
             (plusp (fill-pointer (websocket-http2-3-stream-wire-buffer stream))))
    (%websocket-http2-3-fail
     "An HTTP/3 WebSocket stream ended with an incomplete frame."))
  (when fin-p
    (unless (websocket-http2-3-stream-headers-seen-p stream)
      (%websocket-http2-3-fail
       "An HTTP/3 WebSocket stream ended before its HEADERS."))
    (setf (websocket-http2-3-stream-remote-end-p stream) t))
  stream)

(defun %websocket-http2-3-connection-start-http2 (connection)
  (setf (websocket-http2-3-connection-local-settings connection)
        (%websocket-http2-3-connection-local-http2-settings connection)
        (websocket-http2-3-connection-local-settings-ack-pending-p connection)
        t)
  (when (eq (websocket-http2-3-connection-role connection) :client)
    (%websocket-http2-3-connection-write
     connection (websocket-http2-connection-preface) :stream-id 0))
  (%websocket-http2-3-connection-write
   connection
   (%websocket-http2-3-connection-encode-settings
    (websocket-http2-3-connection-local-settings connection))
   :stream-id 0)
  t)

(defun %websocket-http2-3-connection-start-http3 (connection)
  (setf (websocket-http2-3-connection-local-settings connection)
        (%websocket-http2-3-connection-local-http3-settings connection))
  (%websocket-http2-3-connection-write
   connection
   (encode-websocket-http3-connect-settings
    :qpack-max-table-capacity
    (websocket-http2-3-connection-h3-qpack-max-table-capacity connection)
    :max-field-section-size
    (websocket-http2-3-connection-h3-max-field-section-size connection)
    :qpack-blocked-streams
    (websocket-http2-3-connection-h3-qpack-blocked-streams connection)
    :enable-connect 1)
   :stream-id (websocket-http2-3-connection-h3-control-stream-id connection))
  t)

(defun %websocket-http2-3-connection-start-internal (connection)
  (unless (websocket-http2-3-connection-started-p connection)
    (setf (websocket-http2-3-connection-started-p connection) t)
    (handler-case
        (if (eq (websocket-http2-3-connection-protocol connection) :http2)
            (%websocket-http2-3-connection-start-http2 connection)
            (%websocket-http2-3-connection-start-http3 connection))
      (error (condition)
        (setf (websocket-http2-3-connection-closed-p connection) t)
        (error condition))))
  connection)

(defun %websocket-http2-3-connection-prepare-http3-qpack-tables
    (encoder-table decoder-table qpack-max-table-capacity)
  (let ((encoder
          (or encoder-table
              (http-kit/http3:make-qpack-dynamic-table
               :max-capacity
               +websocket-http3-default-qpack-encoder-table-capacity+
               :capacity 0)))
        (decoder
          (or decoder-table
              (http-kit/http3:make-qpack-dynamic-table
               :max-capacity qpack-max-table-capacity
               :capacity qpack-max-table-capacity))))
    (unless (http-kit/http3:qpack-dynamic-table-p encoder)
      (%websocket-http2-3-fail
       "QPACK-ENCODER-TABLE must be a QPACK dynamic table." :detail encoder))
    (unless (http-kit/http3:qpack-dynamic-table-p decoder)
      (%websocket-http2-3-fail
       "QPACK-DECODER-TABLE must be a QPACK dynamic table." :detail decoder))
    (when (eq encoder decoder)
      (%websocket-http2-3-fail
       "QPACK encoder and decoder tables must be distinct." :detail encoder))
    (when (< (http-kit/http3:qpack-dynamic-table-max-capacity decoder)
             qpack-max-table-capacity)
      (%websocket-http2-3-fail
       "QPACK-DECODER-TABLE cannot represent the advertised capacity."
       :detail decoder))
    (http-kit/http3:qpack-dynamic-table-set-capacity encoder 0)
    (http-kit/http3:qpack-dynamic-table-set-capacity
     decoder qpack-max-table-capacity)
    (values encoder decoder)))

(defun make-websocket-http2-connection
    (&key (role :client) read-function write-function close-function
       (max-concurrent-streams
        +websocket-http2-3-connection-default-max-concurrent-streams+)
       (max-frame-size +websocket-http2-default-max-frame-size+)
       (initial-window-size
        +websocket-http2-3-default-initial-window-size+)
       (max-header-block-bytes +websocket-default-max-header-bytes+)
       (max-continuation-frames +websocket-default-max-fragments+)
       (max-buffered-wire-bytes
        +websocket-http2-3-default-max-buffered-wire-bytes+)
       (max-data-bytes +websocket-default-max-payload-bytes+)
       (max-data-frames +websocket-default-max-fragments+)
       (hpack-dynamic-p t)
       hpack-encoder-context hpack-decoder-context
       (hpack-huffman-p nil)
       stream-open-function stream-close-function)
  (%websocket-http2-3-connection-check-connection-options
   :http2 role max-concurrent-streams max-frame-size initial-window-size
   max-header-block-bytes max-continuation-frames max-buffered-wire-bytes
   max-data-bytes max-data-frames)
  (when (and read-function (not (functionp read-function)))
    (%websocket-http2-3-fail
     "READ-FUNCTION must be a function or NIL." :detail read-function))
  (unless (functionp write-function)
    (%websocket-http2-3-fail
     "An HTTP/2 WebSocket connection requires a write callback."
     :detail write-function))
  (when (and close-function (not (functionp close-function)))
    (%websocket-http2-3-fail
     "CLOSE-FUNCTION must be a function or NIL." :detail close-function))
  (unless (member hpack-dynamic-p '(nil t) :test #'eq)
    (%websocket-http2-3-fail
     "HPACK-DYNAMIC-P must be a generalized boolean."
     :detail hpack-dynamic-p))
  (unless (member hpack-huffman-p '(nil t) :test #'eq)
    (%websocket-http2-3-fail
     "HPACK-HUFFMAN-P must be a generalized boolean."
     :detail hpack-huffman-p))
  (dolist (context (list hpack-encoder-context hpack-decoder-context))
    (when (and context (not (websocket-http2-hpack-context-p context)))
      (%websocket-http2-3-fail
       "HPACK contexts must be websocket-http2-hpack-context objects."
       :detail context)))
  (when (and (not hpack-dynamic-p)
             (or hpack-encoder-context hpack-decoder-context))
    (%websocket-http2-3-fail
     "Explicit HPACK contexts require HPACK dynamic encoding."))
  (when (and hpack-encoder-context hpack-decoder-context
             (eq hpack-encoder-context hpack-decoder-context))
    (%websocket-http2-3-fail
     "HPACK encoder and decoder contexts must be distinct."))
  (let ((encoder-context
          (and hpack-dynamic-p
               (or hpack-encoder-context
                   (make-websocket-http2-hpack-context))))
        (decoder-context
          (and hpack-dynamic-p
               (or hpack-decoder-context
                   (make-websocket-http2-hpack-context)))))
    (%make-websocket-http2-3-connection
   :protocol :http2
   :role role
   :read-function read-function
   :write-function write-function
   :close-function close-function
   :stream-open-function stream-open-function
   :stream-close-function stream-close-function
   :max-concurrent-streams max-concurrent-streams
   :max-frame-size max-frame-size
   :initial-window-size initial-window-size
   :max-header-block-bytes max-header-block-bytes
   :max-continuation-frames max-continuation-frames
   :hpack-encoder-context encoder-context
   :hpack-decoder-context decoder-context
   :hpack-huffman-p hpack-huffman-p
   :max-buffered-wire-bytes max-buffered-wire-bytes
   :max-data-bytes max-data-bytes
   :max-data-frames max-data-frames
   :send-window initial-window-size
   :receive-window initial-window-size
   :unconsumed-receive-bytes 0
   :peer-initial-window-size +websocket-http2-3-default-initial-window-size+
   :peer-max-concurrent-streams
   +websocket-http2-3-connection-default-max-concurrent-streams+
   :peer-max-frame-size +websocket-http2-default-max-frame-size+
   :local-settings-ack-pending-p nil
   :streams (make-hash-table :test #'eql)
   :next-stream-id (if (eq role :client) 1 2)
   :preface-received-p (eq role :client)
   :preface-buffer (%websocket-http2-3-connection-empty-buffer)
   :wire-buffer (%websocket-http2-3-connection-empty-buffer)
   :h3-control-wire-buffer (%websocket-http2-3-connection-empty-buffer))))

(defun make-websocket-http3-connection
    (&key (role :client) read-function write-function close-function
       (max-concurrent-streams
        +websocket-http2-3-connection-default-max-concurrent-streams+)
       (max-frame-size +websocket-http3-default-max-frame-size+)
       (initial-window-size
        +websocket-http2-3-default-initial-window-size+)
       (max-header-block-bytes +websocket-default-max-header-bytes+)
       (max-continuation-frames +websocket-default-max-fragments+)
       (max-buffered-wire-bytes
        +websocket-http2-3-default-max-buffered-wire-bytes+)
       (max-data-bytes +websocket-default-max-payload-bytes+)
       (max-data-frames +websocket-default-max-fragments+)
       h3-control-stream-id h3-peer-control-stream-id
       h3-qpack-encoder-stream-id h3-qpack-decoder-stream-id
       h3-qpack-peer-encoder-stream-id h3-qpack-peer-decoder-stream-id
       stream-open-function stream-close-function
       qpack-encoder-table qpack-decoder-table
       (qpack-max-table-capacity
        +websocket-http3-default-qpack-max-table-capacity+)
       (qpack-blocked-streams +websocket-http3-default-qpack-blocked-streams+)
       (max-field-section-size max-header-block-bytes)
       (qpack-huffman-p nil))
  (%websocket-http2-3-connection-check-connection-options
   :http3 role max-concurrent-streams max-frame-size initial-window-size
   max-header-block-bytes max-continuation-frames max-buffered-wire-bytes
   max-data-bytes max-data-frames)
  (%websocket-validate-limit qpack-max-table-capacity
                             "QPACK-MAX-TABLE-CAPACITY")
  (%websocket-validate-limit qpack-blocked-streams
                             "QPACK-BLOCKED-STREAMS")
  (%websocket-validate-limit max-field-section-size
                             "MAX-FIELD-SECTION-SIZE")
  (when (and read-function (not (functionp read-function)))
    (%websocket-http2-3-fail
     "READ-FUNCTION must be a function or NIL." :detail read-function))
  (unless (functionp write-function)
    (%websocket-http2-3-fail
     "An HTTP/3 WebSocket connection requires a write callback."
     :detail write-function))
  (unless (member qpack-huffman-p '(nil t) :test #'eq)
    (%websocket-http2-3-fail
     "QPACK-HUFFMAN-P must be a generalized boolean."
     :detail qpack-huffman-p))
  (when (and close-function (not (functionp close-function)))
    (%websocket-http2-3-fail
     "CLOSE-FUNCTION must be a function or NIL." :detail close-function))
  (multiple-value-bind (encoder-table decoder-table)
      (%websocket-http2-3-connection-prepare-http3-qpack-tables
       qpack-encoder-table qpack-decoder-table qpack-max-table-capacity)
    (let* ((local-stream-type (if (eq role :client) 2 3))
           (peer-stream-type (if (eq role :client) 3 2))
           (control-id (or h3-control-stream-id local-stream-type))
           (peer-control-id (or h3-peer-control-stream-id peer-stream-type))
           (encoder-stream-id
             (or h3-qpack-encoder-stream-id
                 (if (eq role :client) 6 7)))
           (decoder-stream-id
             (or h3-qpack-decoder-stream-id
                 (if (eq role :client) 10 11)))
           (peer-encoder-stream-id
             (or h3-qpack-peer-encoder-stream-id
                 (if (eq role :client) 7 6)))
           (peer-decoder-stream-id
             (or h3-qpack-peer-decoder-stream-id
                 (if (eq role :client) 11 10)))
           (local-stream-ids
             (list control-id encoder-stream-id decoder-stream-id))
           (peer-stream-ids
             (list peer-control-id peer-encoder-stream-id
                   peer-decoder-stream-id))
           (all-stream-ids (append local-stream-ids peer-stream-ids)))
      (dolist (stream-id local-stream-ids)
        (%websocket-http2-3-check-http3-transport-stream-id stream-id)
        (unless (= (logand stream-id 3) local-stream-type)
          (%websocket-http2-3-fail
           "A local HTTP/3 transport stream identifier has the wrong initiator type."
           :detail stream-id)))
      (dolist (stream-id peer-stream-ids)
        (%websocket-http2-3-check-http3-transport-stream-id stream-id)
        (unless (= (logand stream-id 3) peer-stream-type)
          (%websocket-http2-3-fail
           "A peer HTTP/3 transport stream identifier has the wrong initiator type."
           :detail stream-id)))
      (unless (= (length all-stream-ids)
                 (length (remove-duplicates all-stream-ids :test #'=)))
        (%websocket-http2-3-fail
         "HTTP/3 control and QPACK stream identifiers must be unique."
         :detail all-stream-ids))
    (%make-websocket-http2-3-connection
     :protocol :http3
     :role role
     :read-function read-function
     :write-function write-function
     :close-function close-function
     :stream-open-function stream-open-function
     :stream-close-function stream-close-function
     :max-concurrent-streams max-concurrent-streams
     :max-frame-size max-frame-size
     :initial-window-size initial-window-size
     :max-header-block-bytes max-header-block-bytes
     :max-continuation-frames max-continuation-frames
     :h3-qpack-huffman-p qpack-huffman-p
     :h3-qpack-encoder-table encoder-table
     :h3-qpack-decoder-table decoder-table
     :h3-qpack-encoder-stream-id encoder-stream-id
     :h3-qpack-decoder-stream-id decoder-stream-id
     :h3-qpack-peer-encoder-stream-id peer-encoder-stream-id
     :h3-qpack-peer-decoder-stream-id peer-decoder-stream-id
     :h3-qpack-max-table-capacity qpack-max-table-capacity
     :h3-qpack-blocked-streams qpack-blocked-streams
     :h3-max-field-section-size max-field-section-size
     :h3-peer-qpack-max-table-capacity 0
     :h3-peer-qpack-blocked-streams 0
     :max-buffered-wire-bytes max-buffered-wire-bytes
     :max-data-bytes max-data-bytes
     :max-data-frames max-data-frames
     :send-window initial-window-size
     :receive-window initial-window-size
     :unconsumed-receive-bytes 0
     :peer-initial-window-size initial-window-size
     :peer-max-concurrent-streams max-concurrent-streams
     :peer-max-frame-size max-frame-size
     :local-settings-ack-pending-p nil
     :h3-control-stream-id control-id
     :h3-peer-control-stream-id peer-control-id
     :streams (make-hash-table :test #'eql)
     :next-stream-id (if (eq role :client) 0 1)
     :preface-received-p t
     :preface-buffer (%websocket-http2-3-connection-empty-buffer)
     :wire-buffer (%websocket-http2-3-connection-empty-buffer)
     :h3-control-wire-buffer (%websocket-http2-3-connection-empty-buffer)
     :h3-qpack-encoder-wire-buffer
     (%websocket-http2-3-connection-empty-buffer)
     :h3-qpack-decoder-wire-buffer
     (%websocket-http2-3-connection-empty-buffer)))))

(defun websocket-http2-3-connection-start (connection)
  "Start the HTTP/2 or HTTP/3 connection preface and control streams."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-http2-3-connection-with-lock (connection)
    (%websocket-http2-3-connection-start-internal connection)))

(defun websocket-http2-3-connection-feed
    (connection octets &key end-stream-p)
  "Feed one transport chunk into an HTTP/2 connection."
  (%websocket-http2-3-connection-ensure-protocol connection :http2)
  (%websocket-http2-3-connection-with-lock (connection)
    (%websocket-http2-3-connection-start-internal connection)
    (%websocket-http2-3-connection-feed-http2
     connection octets :end-stream-p end-stream-p)))

(defun websocket-http3-connection-feed-stream
    (connection stream-id octets &key fin-p)
  "Feed one QUIC stream chunk into an HTTP/3 connection.

The caller owns QUIC stream type negotiation and supplies the stream id so
  that this library can keep HTTP/3 control and bidirectional WebSocket state
  separate without embedding a QUIC implementation.  Unrecognized
  unidirectional streams are ignored; configured control and QPACK stream
  identifiers are still validated."
  (%websocket-http2-3-connection-ensure-protocol connection :http3)
  (%websocket-http2-3-check-http3-transport-stream-id stream-id)
  (%websocket-http2-3-connection-with-lock (connection)
    (%websocket-http2-3-connection-start-internal connection)
    (cond
      ((= stream-id
          (websocket-http2-3-connection-h3-peer-control-stream-id connection))
       (%websocket-http2-3-connection-feed-http3-control
        connection octets :fin-p fin-p))
      ((= stream-id
          (websocket-http2-3-connection-h3-control-stream-id connection))
       (%websocket-http2-3-fail
        "An HTTP/3 peer attempted to feed the local control stream."))
      ((= stream-id
          (websocket-http2-3-connection-h3-qpack-encoder-stream-id connection))
       (%websocket-http2-3-fail
        "An HTTP/3 peer attempted to feed the local QPACK encoder stream."))
      ((= stream-id
          (websocket-http2-3-connection-h3-qpack-decoder-stream-id connection))
       (%websocket-http2-3-fail
        "An HTTP/3 peer attempted to feed the local QPACK decoder stream."))
      ((= stream-id
          (websocket-http2-3-connection-h3-qpack-peer-encoder-stream-id
           connection))
       (%websocket-http2-3-connection-feed-http3-qpack-encoder
        connection octets :fin-p fin-p))
      ((= stream-id
          (websocket-http2-3-connection-h3-qpack-peer-decoder-stream-id
           connection))
       (%websocket-http2-3-connection-feed-http3-qpack-decoder
        connection octets :fin-p fin-p))
      ((not (zerop (logand stream-id 2)))
       connection)
      (t
       (%websocket-http2-3-check-http3-stream-id stream-id)
       (unless (%websocket-http2-3-connection-peer-bidi-stream-p
                connection stream-id)
         (%websocket-http2-3-fail
          "An HTTP/3 peer opened a stream with the wrong initiator bit."
          :detail stream-id))
       (let ((stream (gethash stream-id
                              (websocket-http2-3-connection-streams connection))))
         (unless stream
           (%websocket-http2-3-connection-check-open-capacity connection)
           (setf stream
                 (%websocket-http2-3-connection-make-stream
                  connection stream-id
                  :request-p
                  (eq (websocket-http2-3-connection-role connection) :server))))
         (%websocket-http2-3-connection-feed-http3-bidi
          connection stream octets :fin-p fin-p))))))

(defun %websocket-http2-3-connection-pump-once
    (connection deadline)
  "Read and feed one chunk from the connection read callback.

HTTP/2 READ-FUNCTION returns OCTETS and an optional end-stream flag.  HTTP/3
READ-FUNCTION returns STREAM-ID, OCTETS, and an optional FIN flag."
  (let ((function (websocket-http2-3-connection-read-function connection)))
    (unless (functionp function)
      (%websocket-http2-3-connection-transport-error
       "The WebSocket connection has no read callback."
       :read nil))
    (handler-case
        (if (eq (websocket-http2-3-connection-protocol connection) :http2)
            (multiple-value-bind (octets endp)
                (if deadline
                    (funcall function :deadline deadline)
                    (funcall function))
              (cond
                ((or (eq octets :eof)
                     (and (null octets) endp)
                     (and (%websocket-http2-3-octet-vector-p octets)
                          (zerop (length octets))
                          endp))
                 (websocket-http2-3-connection-feed
                  connection
                  (make-array 0 :element-type '(unsigned-byte 8))
                  :end-stream-p t)
                 (values connection t))
                ((and (%websocket-http2-3-octet-vector-p octets)
                      (zerop (length octets)))
                 (%websocket-http2-3-connection-transport-error
                  "An HTTP/2 connection read callback returned an empty octet vector without ending the connection."
                  :read nil))
                ((null octets)
                 (%websocket-http2-3-connection-transport-error
                  "An HTTP/2 connection read callback returned no data without ending the connection."
                  :read nil))
                (t
                 (websocket-http2-3-connection-feed
                  connection octets :end-stream-p endp)
                 (values connection (not (null endp))))))
            (multiple-value-bind (stream-id octets finp)
                (if deadline
                    (funcall function :deadline deadline)
                    (funcall function))
              (cond
                ((and (%websocket-http2-3-octet-vector-p octets)
                      (zerop (length octets))
                      finp)
                 (websocket-http3-connection-feed-stream
                  connection stream-id octets :fin-p t)
                 (values connection t))
                ((and (%websocket-http2-3-octet-vector-p octets)
                      (zerop (length octets)))
                 (%websocket-http2-3-connection-transport-error
                  "An HTTP/3 connection read callback returned an empty octet vector without ending a stream."
                  :read nil
                  :detail stream-id))
                ((null octets)
                 (%websocket-http2-3-connection-transport-error
                  "An HTTP/3 connection read callback returned no data without ending a stream."
                  :read nil
                  :detail stream-id))
                (t
                 (websocket-http3-connection-feed-stream
                  connection stream-id octets :fin-p finp)
                 (values connection (not (null finp)))))))
      (websocket-error (condition)
        (error condition))
      (error (condition)
        (%websocket-http2-3-connection-transport-error
         "A WebSocket connection read callback failed."
         :read condition)))))

(defun websocket-http2-3-connection-pump
    (connection &key timeout deadline clock-function)
  "Read and feed one chunk from CONNECTION's transport.

TIMEOUT is relative to CLOCK-FUNCTION and DEADLINE is an absolute clock value.
The effective deadline is passed to the transport read callback as
`:DEADLINE'."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-http2-3-connection-with-read-lock (connection)
    (%websocket-http2-3-connection-pump-once
     connection
     (if (or timeout deadline)
         (%websocket-effective-deadline timeout deadline clock-function)
         nil))))

(defun websocket-http2-3-connection-stream
    (connection stream-id)
  (%websocket-http2-3-connection-ensure connection)
  (gethash stream-id (websocket-http2-3-connection-streams connection)))

(defun websocket-http2-3-connection-open-stream
    (connection &rest args)
  "Open a local extended-CONNECT WebSocket stream and return its stream object.

ARGS may begin with a header list, or may contain :AUTHORITY, :SCHEME,
:PATH, :HEADERS, :SESSION-INITARGS, and :END-STREAM-P."
  (%websocket-http2-3-connection-ensure connection)
  (multiple-value-bind (headers session-initargs end-stream-p)
      (%websocket-http2-3-connection-parse-header-arguments connection args)
    (%websocket-http2-3-connection-with-lock (connection)
      (%websocket-http2-3-connection-start-internal connection)
      (unless (websocket-http2-3-connection-peer-settings-seen-p connection)
        (%websocket-http2-3-fail
         "A WebSocket stream cannot open before peer SETTINGS are received."))
      (when (websocket-http2-3-connection-goaway-last-stream-id connection)
        (%websocket-http2-3-fail
         "A WebSocket stream cannot open after peer GOAWAY."))
      (unless (websocket-http2-3-connection-peer-connect-enabled-p connection)
        (%websocket-http2-3-fail
         "The peer has not enabled extended CONNECT."))
      (%websocket-http2-3-connection-check-open-capacity connection)
      (let* ((stream-id (%websocket-http2-3-connection-new-stream-id connection))
             (stream (%websocket-http2-3-connection-make-stream
                      connection stream-id
                      :headers headers
                      :request-p t))
             (wire
               (%websocket-http2-3-connection-open-stream-headers
                connection headers stream-id t end-stream-p)))
        (%websocket-http2-3-connection-write
         connection wire :stream-id stream-id :end-stream-p end-stream-p)
        (setf (websocket-http2-3-stream-headers-seen-p stream) t
              (websocket-http2-3-stream-established-p stream) nil
              (websocket-http2-3-stream-local-end-p stream) end-stream-p)
        (%websocket-http2-3-connection-create-session
         stream :initargs session-initargs)
        stream))))

(defun websocket-http2-3-connection-accept-stream
    (connection stream-or-id &rest args)
  "Accept an inbound WebSocket extended-CONNECT stream.

The default response is status 200.  Use :HEADERS for additional response
headers, :STATUS for the status value, :SESSION-INITARGS for session limits,
and :SEND-RESPONSE-P NIL when the application owns the response write."
  (%websocket-http2-3-connection-ensure connection)
  (let* ((stream
           (if (websocket-http2-3-stream-p stream-or-id)
               stream-or-id
               (gethash stream-or-id
                        (websocket-http2-3-connection-streams connection))))
         (headers (getf args :headers))
         (status (getf args :status 200))
         (session-initargs (or (getf args :session-initargs)
                               (getf args :initargs)))
         (send-response-p (getf args :send-response-p t)))
    (unless (and stream
                 (eq (websocket-http2-3-stream-connection stream) connection))
      (%websocket-http2-3-fail
       "The HTTP/2 or HTTP/3 stream does not belong to this connection."
       :detail stream-or-id))
    (%websocket-http2-3-connection-with-lock (connection)
      (unless (websocket-http2-3-stream-headers-seen-p stream)
        (%websocket-http2-3-fail
         "A WebSocket stream cannot be accepted before request HEADERS."))
      (unless (websocket-http2-3-stream-request-p stream)
        (%websocket-http2-3-fail
         "Only an inbound WebSocket request stream can be accepted."))
      (when send-response-p
        (setf headers
              (or headers
                  (if (eq (websocket-http2-3-connection-protocol connection)
                          :http2)
                      (make-websocket-http2-connect-response-headers
                       :status status)
                      (make-websocket-http3-connect-response-headers
                       :status status))))
        (%websocket-http2-3-connection-validate-open-headers
         connection headers nil)
        (%websocket-http2-3-connection-write
         connection
         (%websocket-http2-3-connection-open-stream-headers
          connection headers (websocket-http2-3-stream-id stream) nil nil)
         :stream-id (websocket-http2-3-stream-id stream))
        (setf (websocket-http2-3-stream-established-p stream) t))
      (or (websocket-http2-3-stream-session stream)
          (%websocket-http2-3-connection-create-session
           stream :initargs session-initargs)))))

(defun websocket-http2-3-connection-update-send-window
    (connection amount &key stream-id)
  "Increase a local HTTP/2 send window after receiving WINDOW_UPDATE credit.

For HTTP/3 the QUIC implementation owns flow control and this function only
accepts the call as a bookkeeping no-op.  STREAM-ID NIL updates the connection
window; a stream id updates that stream's window."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-positive-limit amount "WINDOW-INCREMENT")
  (when (eq (websocket-http2-3-connection-protocol connection) :http2)
    (%websocket-http2-3-connection-with-lock (connection)
      (if stream-id
          (let ((stream (gethash stream-id
                                 (websocket-http2-3-connection-streams connection))))
            (unless stream
              (%websocket-http2-3-fail
               "WINDOW-INCREMENT referenced an unknown stream."
               :detail stream-id))
            (let ((window (+ (websocket-http2-3-stream-send-window stream)
                             amount)))
              (when (> window #x7fffffff)
                (error 'websocket-flow-control-error
                       :message "The HTTP/2 stream send window overflowed."
                       :operation :window-update
                       :window window
                       :required amount
                       :kind :stream))
              (setf (websocket-http2-3-stream-send-window stream) window)))
          (let ((window (+ (websocket-http2-3-connection-send-window connection)
                           amount)))
            (when (> window #x7fffffff)
              (error 'websocket-flow-control-error
                     :message "The HTTP/2 connection send window overflowed."
                     :operation :window-update
                     :window window
                     :required amount
                     :kind :connection))
            (setf (websocket-http2-3-connection-send-window connection) window)))))
  connection)

(defun websocket-http2-3-stream-update-send-window (stream amount)
  (unless (websocket-http2-3-stream-p stream)
    (%websocket-http2-3-fail
     "Expected an HTTP/2 or HTTP/3 WebSocket stream." :detail stream))
  (websocket-http2-3-connection-update-send-window
   (websocket-http2-3-stream-connection stream) amount
   :stream-id (websocket-http2-3-stream-id stream)))

(defun websocket-http2-3-connection-consume
    (connection stream-or-id amount)
  "Return consumed inbound DATA credit to the peer.

For HTTP/2 this emits connection and stream WINDOW_UPDATE frames.  For HTTP/3
the QUIC boundary owns wire-level flow control, but the connection still
accounts for consumed bytes so its local receive budget can be released."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-positive-limit amount "CONSUME-BYTES")
  (%websocket-http2-3-connection-with-lock (connection)
    (let ((stream
            (if (websocket-http2-3-stream-p stream-or-id)
                stream-or-id
                (gethash stream-or-id
                         (websocket-http2-3-connection-streams connection)))))
      (unless (and stream
                   (eq (websocket-http2-3-stream-connection stream) connection))
        (%websocket-http2-3-fail
         "CONSUME referenced an unknown HTTP/2 or HTTP/3 stream."
         :detail stream-or-id))
      (let ((stream-unconsumed
              (websocket-http2-3-stream-unconsumed-receive-bytes stream))
            (connection-unconsumed
              (websocket-http2-3-connection-unconsumed-receive-bytes
               connection)))
        (when (> amount stream-unconsumed)
          (error 'websocket-flow-control-error
                 :message "CONSUME exceeds the stream's unconsumed DATA."
                 :operation :consume
                 :window stream-unconsumed
                 :required amount
                 :kind :stream))
        (when (> amount connection-unconsumed)
          (error 'websocket-flow-control-error
                 :message "CONSUME exceeds the connection's unconsumed DATA."
                 :operation :consume
                 :window connection-unconsumed
                 :required amount
                 :kind :connection))
        (when (eq (websocket-http2-3-connection-protocol connection) :http2)
          (let ((connection-window
                  (+ (websocket-http2-3-connection-receive-window connection)
                     amount))
                (stream-window
                  (+ (websocket-http2-3-stream-receive-window stream) amount)))
            (when (> connection-window #x7fffffff)
              (%websocket-http2-3-fail
               "CONSUME would overflow the HTTP/2 connection receive window."))
            (when (> stream-window #x7fffffff)
              (%websocket-http2-3-fail
               "CONSUME would overflow the HTTP/2 stream receive window."))
            (setf (websocket-http2-3-connection-receive-window connection)
                  connection-window
                  (websocket-http2-3-stream-receive-window stream)
                  stream-window)
            (%websocket-http2-3-connection-write
             connection
             (%websocket-http2-3-encode-http2-frame
              :window-update 0 0
              (%websocket-http2-3-connection-u32 amount))
             :stream-id 0)
            (%websocket-http2-3-connection-write
             connection
             (%websocket-http2-3-encode-http2-frame
              :window-update 0 (websocket-http2-3-stream-id stream)
              (%websocket-http2-3-connection-u32 amount))
             :stream-id 0)))
        (decf (websocket-http2-3-stream-unconsumed-receive-bytes stream)
              amount)
        (decf (websocket-http2-3-connection-unconsumed-receive-bytes connection)
              amount)))
    connection))

(defun websocket-http2-3-stream-consume (stream amount)
  (unless (websocket-http2-3-stream-p stream)
    (%websocket-http2-3-fail
     "Expected an HTTP/2 or HTTP/3 WebSocket stream." :detail stream))
  (websocket-http2-3-connection-consume
   (websocket-http2-3-stream-connection stream) stream amount))

(defun websocket-http2-3-connection-close
    (connection &key (code 0) (last-stream-id nil))
  "Write GOAWAY and notify the caller to shut down the HTTP/2/3 transport.

This operation marks the connection locally closed and invokes its close
callback immediately after the protocol frame is accepted.  It does not drain
existing streams or wait for a peer GOAWAY; applications requiring a drain
phase must implement that policy in the transport callback and use ABORT when
the policy completes."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-http2-3-connection-with-lock (connection)
    (unless (websocket-http2-3-connection-closed-p connection)
      (%websocket-http2-3-connection-start-internal connection)
      (if (eq (websocket-http2-3-connection-protocol connection) :http2)
          (let ((last (or last-stream-id
                          (websocket-http2-3-connection-last-peer-stream-id connection)
                          0)))
            (%websocket-http2-3-check-http2-stream-id
             (if (zerop last) 1 last))
            (%websocket-http2-3-connection-write
             connection
             (%websocket-http2-3-encode-http2-frame
              :goaway 0 0
              (%websocket-http2-3-append-octets
               (list (%websocket-http2-3-connection-u32 last)
              (%websocket-http2-3-connection-u32 code))))
             :stream-id 0))
          (let ((last (or last-stream-id 0)))
            (%websocket-http2-3-connection-check-h3-goaway-id
             connection last :local-p t)
            (%websocket-http2-3-connection-write
             connection
             (%websocket-http2-3-encode-http3-frame
              http-kit/http3:+http3-goaway-type+
              (http-kit/http3:http3-varint-encode last))
             :stream-id
             (websocket-http2-3-connection-h3-control-stream-id connection))))
      (setf (websocket-http2-3-connection-closed-p connection) t
            (websocket-http2-3-connection-local-end-p connection) t)
      (%websocket-http2-3-connection-call-close connection nil))
    connection))

(defun websocket-http2-3-connection-abort (connection)
  "Abort a connection without sending a GOAWAY or HTTP/3 close frame."
  (%websocket-http2-3-connection-ensure connection)
  (%websocket-http2-3-connection-with-lock (connection)
    (unless (websocket-http2-3-connection-closed-p connection)
      (setf (websocket-http2-3-connection-closed-p connection) t
            (websocket-http2-3-connection-local-end-p connection) t
            (websocket-http2-3-connection-remote-end-p connection) t)
      (%websocket-http2-3-connection-call-close connection t))
    connection))

(defun websocket-http2-session-open-stream (connection &rest args)
  (%websocket-http2-3-connection-ensure-protocol connection :http2)
  (apply #'websocket-http2-3-connection-open-stream connection args))

(defun websocket-http3-session-open-stream (connection &rest args)
  (%websocket-http2-3-connection-ensure-protocol connection :http3)
  (apply #'websocket-http2-3-connection-open-stream connection args))

(defun websocket-http2-connection-open-stream (connection &rest args)
  (%websocket-http2-3-connection-ensure-protocol connection :http2)
  (apply #'websocket-http2-3-connection-open-stream connection args))

(defun websocket-http3-connection-open-stream (connection &rest args)
  (%websocket-http2-3-connection-ensure-protocol connection :http3)
  (apply #'websocket-http2-3-connection-open-stream connection args))
