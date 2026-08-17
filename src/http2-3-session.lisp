(in-package #:websocket-kit)

(defconstant +websocket-http2-3-default-max-buffered-wire-bytes+
  (* 2 +websocket-default-max-payload-bytes+))

(defstruct (websocket-http2-3-session
            (:constructor %make-websocket-http2-3-session))
  protocol
  stream-id
  read-function
  write-function
  close-function
  max-message-bytes
  max-payload-bytes
  max-fragments
  max-control-frames
  max-frames
  allowed-reserved-bits
  require-mask-p
  allow-unmasked-p
  require-unmasked-p
  payload-decoder
  payload-encoder
  send-reserved-bits
  max-buffered-wire-bytes
  max-data-bytes
  max-data-frames
  max-frame-size
  max-frame-payload-bytes
  send-mask-p
  send-masking-key
  send-masking-key-function
  wire-buffer
  message-wire-buffer
  message-opcode
  fragment-count
  message-buffer
  control-frame-count
  data-bytes
  data-frame-count
  frame-count
  closed-p
  local-end-p
  remote-end-p
  #+sbcl (read-lock (sb-thread:make-mutex
                     :name "websocket-kit-http2-3-session-read"))
  #-sbcl (read-lock nil)
  #+sbcl (write-lock (sb-thread:make-mutex
                      :name "websocket-kit-http2-3-session-write"))
  #-sbcl (write-lock nil))

(defmacro %websocket-http2-3-session-with-read-lock ((session) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-http2-3-session-read-lock ,session))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defmacro %websocket-http2-3-session-with-write-lock ((session) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-http2-3-session-write-lock ,session))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defun %websocket-http2-3-session-empty-buffer ()
  (make-array 0
              :element-type '(unsigned-byte 8)
              :adjustable t
              :fill-pointer 0))

(defun %websocket-http2-3-session-drop-prefix (buffer count)
  (let* ((length (fill-pointer buffer))
         (remaining (- length count))
         (result (make-array remaining
                             :element-type '(unsigned-byte 8)
                             :adjustable t
                             :fill-pointer remaining)))
    (replace result buffer :start2 count)
    result))

(defun %websocket-http2-3-session-append (buffer octets)
  (%websocket-append-octets buffer octets))

(defun %websocket-http2-3-session-transport-error
    (message cause detail)
  (error 'websocket-transport-error
         :message message
         :operation :websocket-http2-3-session
         :cause cause
         :detail detail))

(defun %websocket-http2-3-session-ensure (session)
  (unless (websocket-http2-3-session-p session)
    (%websocket-http2-3-fail
     "Expected an HTTP/2 or HTTP/3 WebSocket session."
     :detail session))
  session)

(defun %websocket-http2-3-session-mark-failed (session)
  (unless (websocket-http2-3-session-closed-p session)
    (setf (websocket-http2-3-session-closed-p session) t
          (websocket-http2-3-session-local-end-p session) t)
    (handler-case
        (%websocket-http2-3-session-call-close session t)
      (error () nil)))
  session)

(defun %websocket-http2-3-session-call-with-failure
    (session function)
  (handler-case
      (funcall function)
    (websocket-error (condition)
      (%websocket-http2-3-session-mark-failed session)
      (error condition))
    (error (condition)
      (%websocket-http2-3-session-mark-failed session)
      (error condition))))

(defun %websocket-http2-3-session-ensure-protocol (session protocol)
  (%websocket-http2-3-session-ensure session)
  (unless (eq protocol (websocket-http2-3-session-protocol session))
    (%websocket-http2-3-fail
     "The WebSocket session protocol does not match the requested operation."
     :detail (list :expected protocol
                   :actual (websocket-http2-3-session-protocol session))))
  session)

(defun %websocket-http2-3-session-check-buffer-size
    (session buffer octets message)
  (let ((limit (websocket-http2-3-session-max-buffered-wire-bytes session))
        (observed (+ (fill-pointer buffer) (length octets))))
    (when (> observed limit)
      (%websocket-size-error message limit observed))))

(defun %websocket-http2-3-session-copy-transport-octets
    (session octets)
  (unless (%websocket-http2-3-octet-vector-p octets)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 WebSocket transport callback must return octets."
     :detail octets))
  (%websocket-http2-3-session-check-buffer-size
   session
   (websocket-http2-3-session-wire-buffer session)
   octets
   "An HTTP/2 or HTTP/3 WebSocket session exceeded its buffered-wire limit.")
  (%websocket-http2-3-copy-octets octets))

(defun %websocket-http2-3-session-read-transport
    (session &optional deadline)
  (handler-case
      (multiple-value-bind (octets end-stream-p)
          (if deadline
              (funcall (websocket-http2-3-session-read-function session)
                       :deadline deadline)
              (funcall (websocket-http2-3-session-read-function session)))
        (cond
          ((eq octets :eof)
           (values nil t))
          ((and (null octets) end-stream-p)
           (values nil t))
          ((and (%websocket-http2-3-octet-vector-p octets)
                (zerop (length octets))
                end-stream-p)
           (values nil t))
          ((and (%websocket-http2-3-octet-vector-p octets)
                (zerop (length octets)))
           (%websocket-http2-3-session-transport-error
            "An HTTP/2 or HTTP/3 WebSocket read callback returned an empty octet vector without ending the stream."
            :read
            nil))
          ((null octets)
           (%websocket-http2-3-session-transport-error
            "An HTTP/2 or HTTP/3 WebSocket read callback returned no data without ending the stream."
            :read
            nil))
          (t
           (values (%websocket-http2-3-session-copy-transport-octets
                    session
                    octets)
                   (not (null end-stream-p))))))
    (websocket-error (condition)
      (error condition))
    (error (condition)
      (%websocket-http2-3-session-transport-error
       "An HTTP/2 or HTTP/3 WebSocket read callback failed."
       :read
       condition))))

(defun %websocket-http2-3-session-write-transport
    (session octets end-stream-p &optional deadline)
  (handler-case
      (let ((accepted
              (if deadline
                  (funcall
                   (websocket-http2-3-session-write-function session)
                   octets
                   :end-stream-p (not (null end-stream-p))
                   :deadline deadline)
                  (funcall
                   (websocket-http2-3-session-write-function session)
                   octets
                   :end-stream-p (not (null end-stream-p))))))
        (unless (or (null accepted)
                    (eq accepted t)
                    (and (integerp accepted)
                         (= accepted (length octets))))
          (%websocket-http2-3-session-transport-error
           "An HTTP/2 or HTTP/3 WebSocket write callback did not accept the complete frame batch."
           :write
           (list :accepted accepted
                 :expected (length octets))))
        accepted)
    (websocket-error (condition)
      (error condition))
    (error (condition)
      (%websocket-http2-3-session-transport-error
       "An HTTP/2 or HTTP/3 WebSocket write callback failed."
       :write
       condition))))

(defun %websocket-http2-3-session-call-close (session abort-p)
  (let ((function (websocket-http2-3-session-close-function session)))
    (when function
      (handler-case
          (funcall function :abort-p (not (null abort-p)))
        (websocket-error (condition)
          (error condition))
        (error (condition)
          (%websocket-http2-3-session-transport-error
           "An HTTP/2 or HTTP/3 WebSocket close callback failed."
           :close
           condition))))))

(defun %websocket-http2-3-session-frame-wire-length
    (octets max-payload-bytes)
  (let ((available (length octets)))
    (when (< available 2)
      (return-from %websocket-http2-3-session-frame-wire-length nil))
    (let* ((first (aref octets 0))
           (second (aref octets 1))
           (opcode (logand first #x0f))
           (fin-p (not (zerop (logand first #x80))))
           (length-code (logand second #x7f))
           (mask-p (not (zerop (logand second #x80))))
           (extended-width (case length-code
                             ((126) 2)
                             ((127) 8)
                             (otherwise 0))))
      (when (and (%websocket-control-opcode-p opcode)
                 (or (not fin-p) (>= length-code 126)))
        (%websocket-protocol-error
         "A WebSocket control frame must be final and no larger than 125 octets."
         opcode))
      (let ((header-end (+ 2 extended-width)))
        (when (< available header-end)
          (return-from %websocket-http2-3-session-frame-wire-length nil))
        (when (and (= length-code 127)
                   (logbitp 63 (%websocket-read-integer octets 2 8)))
          (%websocket-protocol-error
           "A WebSocket payload length must have its high bit clear."))
        (let ((payload-length
                (if (zerop extended-width)
                    length-code
                    (%websocket-read-integer
                     octets 2 extended-width))))
          (%websocket-validate-length-encoding length-code payload-length)
          (when (> payload-length max-payload-bytes)
            (%websocket-size-error
             "A WebSocket frame exceeded its payload-size limit."
             max-payload-bytes
             payload-length))
          (let ((frame-end (+ header-end (if mask-p 4 0) payload-length)))
            (if (< available frame-end)
                nil
                frame-end)))))))

(defun %websocket-http2-3-session-http3-varint
    (octets position)
  (let ((length (length octets)))
    (when (>= position length)
      (return-from %websocket-http2-3-session-http3-varint nil))
    (let* ((first (aref octets position))
           (width (case (logand first #xc0)
                    (0 1)
                    (#x40 2)
                    (#x80 4)
                    (#xc0 8)))
           (end (+ position width)))
      (when (> end length)
        (return-from %websocket-http2-3-session-http3-varint nil))
      (let ((value (logand first #x3f)))
        (loop for index from (1+ position) below end
              do (setf value (+ (ash value 8)
                                (aref octets index))))
        (values value end)))))

(defun %websocket-http2-3-session-next-http2-data (session)
  (let* ((buffer (websocket-http2-3-session-wire-buffer session))
         (available (fill-pointer buffer)))
    (when (< available 9)
      (return-from %websocket-http2-3-session-next-http2-data
        (values nil nil nil)))
    (let* ((payload-length (logior (ash (aref buffer 0) 16)
                                   (ash (aref buffer 1) 8)
                                   (aref buffer 2)))
           (frame-end (+ 9 payload-length)))
      (when (> payload-length
               (websocket-http2-3-session-max-frame-size session))
        (%websocket-size-error
         "An HTTP/2 DATA frame exceeds the session frame-size limit."
         (websocket-http2-3-session-max-frame-size session)
         payload-length))
      (when (< available frame-end)
        (return-from %websocket-http2-3-session-next-http2-data
          (values nil nil nil)))
      (multiple-value-bind (payload used stream-id end-stream-p)
          (decode-websocket-http2-data-frame
           buffer
           :expected-stream-id
           (websocket-http2-3-session-stream-id session)
           :max-frame-size
           (websocket-http2-3-session-max-frame-size session))
        (declare (ignore stream-id))
        (setf (websocket-http2-3-session-wire-buffer session)
              (%websocket-http2-3-session-drop-prefix buffer used))
        (incf (websocket-http2-3-session-data-frame-count session))
        (incf (websocket-http2-3-session-data-bytes session)
              (length payload))
        (when (> (websocket-http2-3-session-data-frame-count session)
                 (websocket-http2-3-session-max-data-frames session))
          (%websocket-size-error
           "An HTTP/2 or HTTP/3 WebSocket session exceeded its DATA-frame limit."
           (websocket-http2-3-session-max-data-frames session)
           (websocket-http2-3-session-data-frame-count session)))
        (when (> (websocket-http2-3-session-data-bytes session)
                 (websocket-http2-3-session-max-data-bytes session))
          (%websocket-size-error
           "An HTTP/2 or HTTP/3 WebSocket session exceeded its DATA-byte limit."
           (websocket-http2-3-session-max-data-bytes session)
           (websocket-http2-3-session-data-bytes session)))
        (values payload end-stream-p t)))))

(defun %websocket-http2-3-session-next-http3-data (session)
  (let* ((buffer (websocket-http2-3-session-wire-buffer session))
         (available (fill-pointer buffer)))
    (multiple-value-bind (type after-type)
        (%websocket-http2-3-session-http3-varint buffer 0)
      (unless after-type
        (return-from %websocket-http2-3-session-next-http3-data
          (values nil nil nil)))
      (multiple-value-bind (payload-length after-length)
          (%websocket-http2-3-session-http3-varint buffer after-type)
        (unless after-length
          (return-from %websocket-http2-3-session-next-http3-data
            (values nil nil nil)))
        (when (> payload-length
                 (websocket-http2-3-session-max-frame-size session))
          (%websocket-size-error
           "An HTTP/3 DATA frame exceeds the session frame-size limit."
           (websocket-http2-3-session-max-frame-size session)
           payload-length))
        (let ((frame-end (+ after-length payload-length)))
          (when (> frame-end available)
            (return-from %websocket-http2-3-session-next-http3-data
              (values nil nil nil)))
          (unless (= type http-kit/http3:+http3-data-type+)
            (%websocket-http2-3-fail
             "An HTTP/3 WebSocket session received a non-DATA frame on its data stream."
             :detail type))
          (multiple-value-bind (payload used stream-id)
              (decode-websocket-http3-data-frame
               buffer
               :expected-stream-id
               (websocket-http2-3-session-stream-id session)
               :max-frame-size
               (websocket-http2-3-session-max-frame-size session))
            (declare (ignore stream-id))
            (setf (websocket-http2-3-session-wire-buffer session)
                  (%websocket-http2-3-session-drop-prefix buffer used))
            (incf (websocket-http2-3-session-data-frame-count session))
            (incf (websocket-http2-3-session-data-bytes session)
                  (length payload))
            (when (> (websocket-http2-3-session-data-frame-count session)
                     (websocket-http2-3-session-max-data-frames session))
              (%websocket-size-error
               "An HTTP/2 or HTTP/3 WebSocket session exceeded its DATA-frame limit."
               (websocket-http2-3-session-max-data-frames session)
               (websocket-http2-3-session-data-frame-count session)))
            (when (> (websocket-http2-3-session-data-bytes session)
                     (websocket-http2-3-session-max-data-bytes session))
              (%websocket-size-error
               "An HTTP/2 or HTTP/3 WebSocket session exceeded its DATA-byte limit."
               (websocket-http2-3-session-max-data-bytes session)
               (websocket-http2-3-session-data-bytes session)))
            (values payload nil t)))))))

(defun %websocket-http2-3-session-next-data (session)
  (ecase (websocket-http2-3-session-protocol session)
    (:http2 (%websocket-http2-3-session-next-http2-data session))
    (:http3 (%websocket-http2-3-session-next-http3-data session))))

(defun %websocket-http2-3-session-drain-data (session)
  (loop
    (multiple-value-bind (payload end-stream-p data-p)
        (%websocket-http2-3-session-next-data session)
      (unless data-p
        (return nil))
      (%websocket-http2-3-session-check-buffer-size
       session
       (websocket-http2-3-session-message-wire-buffer session)
       payload
       "An HTTP/2 or HTTP/3 WebSocket session exceeded its buffered-message-wire limit.")
      (setf (websocket-http2-3-session-message-wire-buffer session)
            (%websocket-http2-3-session-append
             (websocket-http2-3-session-message-wire-buffer session)
             payload))
      (when end-stream-p
        (setf (websocket-http2-3-session-remote-end-p session) t)
        (when (plusp (fill-pointer
                      (websocket-http2-3-session-wire-buffer session)))
          (%websocket-http2-3-session-transport-error
           "An HTTP/2 DATA frame with END_STREAM was followed by more frame data."
           :protocol
           nil))
        (return t)))))

(defun %websocket-http2-3-session-finish-message (session)
  (let* ((opcode (websocket-http2-3-session-message-opcode session))
         (payload (%websocket-copy-octets
                   (websocket-http2-3-session-message-buffer session))))
    (when (= opcode 1)
      (%websocket-utf8-string payload :invalid-data-p t))
    (setf (websocket-http2-3-session-message-opcode session) nil
          (websocket-http2-3-session-fragment-count session) 0
          (websocket-http2-3-session-message-buffer session)
          (%websocket-http2-3-session-empty-buffer)
          (websocket-http2-3-session-control-frame-count session) 0)
    (values payload opcode :message)))

(defun %websocket-http2-3-session-append-message-payload (session payload)
  (let ((new-length (+ (fill-pointer
                        (websocket-http2-3-session-message-buffer session))
                       (length payload))))
    (when (> new-length
             (websocket-http2-3-session-max-message-bytes session))
      (%websocket-size-error
       "A WebSocket message exceeded the session message-size limit."
       (websocket-http2-3-session-max-message-bytes session)
       new-length))
    (setf (websocket-http2-3-session-message-buffer session)
          (%websocket-http2-3-session-append
           (websocket-http2-3-session-message-buffer session)
           payload))))

(defun %websocket-http2-3-session-write-frame
    (session frame &key end-stream-p deadline)
  (let* ((mask-p (websocket-http2-3-session-send-mask-p session))
         (masking-key
           (%websocket-next-masking-key
            mask-p
            (websocket-http2-3-session-send-masking-key session)
            (websocket-http2-3-session-send-masking-key-function session)))
         (wire (serialize-websocket-frame
                (make-websocket-frame
                 :fin-p (websocket-frame-fin-p frame)
                 :opcode (websocket-frame-opcode frame)
                 :reserved-bits (websocket-frame-reserved-bits frame)
                 :mask-p mask-p
                 :masking-key masking-key
                 :payload (websocket-frame-payload frame)))))
    (let ((transport-wire
            (ecase (websocket-http2-3-session-protocol session)
              (:http2
               (encode-websocket-http2-data-frames
                wire
                (websocket-http2-3-session-stream-id session)
                :end-stream-p end-stream-p
                :max-frame-size
                (websocket-http2-3-session-max-frame-size session)))
              (:http3
               (encode-websocket-http3-data-frames
                wire
                (websocket-http2-3-session-stream-id session)
                :max-frame-size
                (websocket-http2-3-session-max-frame-size session))))))
      (%websocket-http2-3-session-write-transport
       session transport-wire end-stream-p deadline)
      transport-wire)))

(defun %websocket-http2-3-session-write-control
    (session opcode payload &key end-stream-p deadline)
  (%websocket-http2-3-session-write-frame
   session
   (make-websocket-frame :fin-p t
                         :opcode opcode
                         :mask-p nil
                         :payload payload)
   :end-stream-p end-stream-p
   :deadline deadline))

(defun %websocket-http2-3-session-handle-control
    (session frame on-control &optional deadline)
  (let ((opcode (websocket-frame-opcode frame))
        (payload (websocket-frame-payload frame)))
    (incf (websocket-http2-3-session-control-frame-count session))
    (when (> (websocket-http2-3-session-control-frame-count session)
             (websocket-http2-3-session-max-control-frames session))
      (%websocket-size-error
       "A WebSocket message exceeded the session control-frame limit."
       (websocket-http2-3-session-max-control-frames session)
       (websocket-http2-3-session-control-frame-count session)))
    (when on-control
      (funcall on-control frame))
    (case opcode
      (9
       (%websocket-http2-3-session-with-write-lock (session)
         (%websocket-http2-3-session-write-control
          session 10 payload :deadline deadline)))
      (8
       (parse-websocket-close-payload payload)
       (%websocket-http2-3-session-with-write-lock (session)
         (unless (websocket-http2-3-session-local-end-p session)
           (%websocket-http2-3-session-write-control
            session 8 payload :end-stream-p t :deadline deadline)
           (setf (websocket-http2-3-session-local-end-p session) t))
         (setf (websocket-http2-3-session-closed-p session) t))
       (values payload :close :close))
      (10 nil))))

(defun %websocket-http2-3-session-handle-frame
    (session frame on-control &optional deadline)
  (let* ((opcode (websocket-frame-opcode frame))
         (payload (websocket-frame-payload frame)))
    (when (and (not (%websocket-control-opcode-p opcode))
               (websocket-http2-3-session-payload-decoder session))
      (setf payload
            (%websocket-decode-payload
             payload frame
             (websocket-http2-3-session-payload-decoder session)
             (websocket-http2-3-session-max-message-bytes session))))
    (if (%websocket-control-opcode-p opcode)
        (%websocket-http2-3-session-handle-control
         session frame on-control deadline)
        (cond
          ((member opcode '(1 2) :test #'=)
           (when (websocket-http2-3-session-message-opcode session)
             (%websocket-protocol-error
              "A new WebSocket data message cannot start before the previous fragmented message finishes."))
           (setf (websocket-http2-3-session-message-opcode session) opcode
                 (websocket-http2-3-session-fragment-count session) 1)
           (%websocket-http2-3-session-append-message-payload session payload)
           (if (websocket-frame-fin-p frame)
               (%websocket-http2-3-session-finish-message session)
               nil))
          ((zerop opcode)
           (unless (websocket-http2-3-session-message-opcode session)
             (%websocket-protocol-error
              "A WebSocket continuation frame has no initial data frame."))
           (incf (websocket-http2-3-session-fragment-count session))
           (when (> (websocket-http2-3-session-fragment-count session)
                    (websocket-http2-3-session-max-fragments session))
             (%websocket-size-error
              "A WebSocket message exceeded the session fragment limit."
              (websocket-http2-3-session-max-fragments session)
              (websocket-http2-3-session-fragment-count session)))
           (%websocket-http2-3-session-append-message-payload session payload)
           (when (websocket-frame-fin-p frame)
             (%websocket-http2-3-session-finish-message session)))))))

(defun %websocket-http2-3-session-process-wire
    (session on-control &optional deadline)
  (loop
    (let ((frame-length
            (%websocket-http2-3-session-frame-wire-length
             (websocket-http2-3-session-message-wire-buffer session)
             (websocket-http2-3-session-max-payload-bytes session))))
      (unless frame-length
        (return nil))
      (multiple-value-bind (frame used)
          (parse-websocket-frame
           (websocket-http2-3-session-message-wire-buffer session)
           :max-payload-bytes
           (websocket-http2-3-session-max-payload-bytes session)
           :allowed-reserved-bits
           (websocket-http2-3-session-allowed-reserved-bits session)
           :require-mask-p
           (websocket-http2-3-session-require-mask-p session)
           :allow-unmasked-p
           (websocket-http2-3-session-allow-unmasked-p session)
           :require-unmasked-p
           (websocket-http2-3-session-require-unmasked-p session))
        (setf (websocket-http2-3-session-message-wire-buffer session)
              (%websocket-http2-3-session-drop-prefix
               (websocket-http2-3-session-message-wire-buffer session)
               used))
        (incf (websocket-http2-3-session-frame-count session))
        (when (> (websocket-http2-3-session-frame-count session)
                 (websocket-http2-3-session-max-frames session))
          (%websocket-size-error
           "An HTTP/2 or HTTP/3 WebSocket session exceeded its frame-count limit."
           (websocket-http2-3-session-max-frames session)
           (websocket-http2-3-session-frame-count session)))
        (multiple-value-bind (payload opcode status)
          (%websocket-http2-3-session-handle-frame
             session frame on-control deadline)
          (when status
            (when (or (plusp
                       (fill-pointer
                        (websocket-http2-3-session-wire-buffer session)))
                      (plusp
                       (fill-pointer
                        (websocket-http2-3-session-message-wire-buffer
                         session))))
              (%websocket-protocol-error
               "A WebSocket Close frame must be followed by no additional stream data."))
            (return (values payload opcode status))))))))

(defun %websocket-http2-3-session-pending-p (session)
  (or (plusp (fill-pointer
              (websocket-http2-3-session-wire-buffer session)))
      (plusp (fill-pointer
              (websocket-http2-3-session-message-wire-buffer session)))
      (websocket-http2-3-session-message-opcode session)))

(defun %websocket-http2-3-session-validate-receive-options (on-control)
  (when (and on-control (not (functionp on-control)))
    (%websocket-protocol-error "ON-CONTROL must be a function or NIL."
                               on-control))
  on-control)

(defun %websocket-http2-3-session-receive
    (session on-control &optional deadline)
  (%websocket-http2-3-session-validate-receive-options on-control)
  (let* ((control-frames nil)
         (result nil)
         (control-callback
           (when on-control
             (lambda (frame)
               (push frame control-frames)))))
    (setf result
          (multiple-value-list
           (%websocket-http2-3-session-with-read-lock (session)
             (loop
               (when (websocket-http2-3-session-closed-p session)
                 (return (values nil :eof)))
               (multiple-value-bind (payload opcode status)
                   (%websocket-http2-3-session-process-wire
                    session control-callback deadline)
                 (when status
                   (return (values payload opcode))))
               (when (and (websocket-http2-3-session-remote-end-p session)
                          (%websocket-http2-3-session-pending-p session))
                 (%websocket-http2-3-session-transport-error
                  "The HTTP/2 or HTTP/3 WebSocket stream ended with an incomplete message."
                  :eof
                  (list :wire-bytes
                        (fill-pointer
                         (websocket-http2-3-session-message-wire-buffer session))
                        :message-opcode
                        (websocket-http2-3-session-message-opcode session))))
               (%websocket-http2-3-session-drain-data session)
               (multiple-value-bind (payload opcode status)
                   (%websocket-http2-3-session-process-wire
                    session control-callback deadline)
                 (when status
                   (return (values payload opcode))))
               (when (and (websocket-http2-3-session-remote-end-p session)
                          (%websocket-http2-3-session-pending-p session))
                 (%websocket-http2-3-session-transport-error
                  "The HTTP/2 or HTTP/3 WebSocket stream ended with an incomplete message."
                  :eof
                  (list :wire-bytes
                        (fill-pointer
                         (websocket-http2-3-session-message-wire-buffer session))
                        :message-opcode
                        (websocket-http2-3-session-message-opcode session))))
               (when (websocket-http2-3-session-remote-end-p session)
                 (return (values nil :eof)))
               (multiple-value-bind (octets end-stream-p)
                   (%websocket-http2-3-session-read-transport
                    session deadline)
                 (when octets
                   (setf (websocket-http2-3-session-wire-buffer session)
                         (%websocket-http2-3-session-append
                          (websocket-http2-3-session-wire-buffer session)
                          octets)))
                 (when end-stream-p
                   (setf (websocket-http2-3-session-remote-end-p session)
                         t)))))))
    (when on-control
      (dolist (frame (nreverse control-frames))
        (funcall on-control frame)))
    (values-list result)))

(defun %websocket-http2-3-session-send
    (session payload &key (opcode 2) max-frame-payload-bytes
                         max-message-bytes end-stream-p timeout deadline
                         clock-function)
  (let ((effective-deadline
          (if (or timeout deadline)
              (%websocket-effective-deadline
               timeout deadline clock-function)
              nil)))
    (unless (member opcode '(1 2) :test #'=)
      (%websocket-protocol-error
       "A WebSocket message opcode must be 1 (text) or 2 (binary)."
       opcode))
    (let ((frame-size (or max-frame-payload-bytes
                          (websocket-http2-3-session-max-frame-payload-bytes
                           session)))
          (message-size (or max-message-bytes
                            (websocket-http2-3-session-max-message-bytes
                             session))))
      (%websocket-positive-limit frame-size "MAX-FRAME-PAYLOAD-BYTES")
      (%websocket-validate-limit message-size "MAX-MESSAGE-BYTES")
      (%websocket-http2-3-session-with-write-lock (session)
        (when (or (websocket-http2-3-session-closed-p session)
                  (websocket-http2-3-session-local-end-p session))
          (%websocket-protocol-error
           "A WebSocket session cannot send after its local end has been sent."))
        (let ((wire (%websocket-http2-3-append-octets
                     (%websocket-http2-3-message-frame-wire
                      payload
                      :opcode opcode
                      :max-frame-payload-bytes frame-size
                      :mask-p
                      (websocket-http2-3-session-send-mask-p session)
                      :masking-key
                      (websocket-http2-3-session-send-masking-key session)
                      :masking-key-function
                      (websocket-http2-3-session-send-masking-key-function session)
                      :reserved-bits
                      (websocket-http2-3-session-send-reserved-bits session)
                      :payload-encoder
                      (websocket-http2-3-session-payload-encoder session)
                      :max-message-bytes message-size))))
          (let ((transport-wire
                  (ecase (websocket-http2-3-session-protocol session)
                    (:http2
                     (encode-websocket-http2-data-frames
                      wire
                      (websocket-http2-3-session-stream-id session)
                      :end-stream-p end-stream-p
                      :max-frame-size
                      (websocket-http2-3-session-max-frame-size session)))
                    (:http3
                     (encode-websocket-http3-data-frames
                      wire
                      (websocket-http2-3-session-stream-id session)
                      :max-frame-size
                      (websocket-http2-3-session-max-frame-size session))))))
            (%websocket-http2-3-session-write-transport
             session transport-wire end-stream-p effective-deadline)
            (when end-stream-p
              (setf (websocket-http2-3-session-local-end-p session) t))
            session))))))

(defun %websocket-http2-3-session-make
    (protocol stream-id read-function write-function
     &key close-function
       (max-message-bytes +websocket-default-max-payload-bytes+)
       (max-payload-bytes +websocket-default-max-payload-bytes+)
       (max-fragments +websocket-default-max-fragments+)
       (max-control-frames +websocket-default-max-control-frames+)
       (max-frames +websocket-default-max-fragments+)
       (allowed-reserved-bits 0)
       (require-mask-p nil)
       (allow-unmasked-p t)
       (require-unmasked-p nil)
       payload-decoder
       payload-encoder
       (reserved-bits 0)
       (max-buffered-wire-bytes
        +websocket-http2-3-default-max-buffered-wire-bytes+)
       (max-data-bytes +websocket-default-max-payload-bytes+)
       (max-data-frames +websocket-default-max-fragments+)
       max-frame-size
       (max-frame-payload-bytes 65535)
       (mask-p nil)
       masking-key
       masking-key-function)
  (unless (member protocol '(:http2 :http3))
    (%websocket-http2-3-fail
     "The WebSocket session protocol must be :HTTP2 or :HTTP3."
     :detail protocol))
  (if (eq protocol :http2)
      (%websocket-http2-3-check-http2-stream-id stream-id)
      (%websocket-http2-3-check-http3-stream-id stream-id))
  (unless (functionp read-function)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 WebSocket session requires a read callback."
     :detail read-function))
  (unless (functionp write-function)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 WebSocket session requires a write callback."
     :detail write-function))
  (when (and close-function (not (functionp close-function)))
    (%websocket-http2-3-fail
     "CLOSE-FUNCTION must be a function or NIL."
     :detail close-function))
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (%websocket-validate-limit max-payload-bytes "MAX-PAYLOAD-BYTES")
  (%websocket-validate-limit max-fragments "MAX-FRAGMENTS")
  (%websocket-validate-limit max-control-frames "MAX-CONTROL-FRAMES")
  (%websocket-validate-limit max-frames "MAX-FRAMES")
  (%websocket-validate-reserved-bits
   allowed-reserved-bits "ALLOWED-RESERVED-BITS")
  (%websocket-validate-payload-transformer
   payload-decoder "PAYLOAD-DECODER")
  (%websocket-validate-payload-transformer
   payload-encoder "PAYLOAD-ENCODER")
  (%websocket-validate-reserved-bits reserved-bits "RESERVED-BITS")
  (%websocket-validate-limit
   max-buffered-wire-bytes "MAX-BUFFERED-WIRE-BYTES")
  (%websocket-validate-limit max-data-bytes "MAX-DATA-BYTES")
  (%websocket-positive-limit max-data-frames "MAX-DATA-FRAMES")
  (%websocket-positive-limit
   max-frame-payload-bytes "MAX-FRAME-PAYLOAD-BYTES")
  (let ((frame-size
          (or max-frame-size
              (if (eq protocol :http2)
                  +websocket-http2-default-max-frame-size+
                  +websocket-http3-default-max-frame-size+))))
    (if (eq protocol :http2)
        (%websocket-http2-3-check-http2-max-frame-size frame-size)
        (%websocket-http2-3-check-http3-max-frame-size frame-size))
    (%websocket-masking-options mask-p masking-key masking-key-function)
    (%make-websocket-http2-3-session
     :protocol protocol
     :stream-id stream-id
     :read-function read-function
     :write-function write-function
     :close-function close-function
     :max-message-bytes max-message-bytes
      :max-payload-bytes max-payload-bytes
      :max-fragments max-fragments
      :max-control-frames max-control-frames
      :max-frames max-frames
     :allowed-reserved-bits allowed-reserved-bits
     :require-mask-p require-mask-p
      :allow-unmasked-p allow-unmasked-p
      :require-unmasked-p require-unmasked-p
      :payload-decoder payload-decoder
      :payload-encoder payload-encoder
      :send-reserved-bits reserved-bits
      :max-buffered-wire-bytes max-buffered-wire-bytes
     :max-data-bytes max-data-bytes
     :max-data-frames max-data-frames
     :max-frame-size frame-size
     :max-frame-payload-bytes max-frame-payload-bytes
     :send-mask-p mask-p
     :send-masking-key
     (and masking-key (%websocket-copy-octets masking-key))
     :send-masking-key-function masking-key-function
     :wire-buffer (%websocket-http2-3-session-empty-buffer)
     :message-wire-buffer (%websocket-http2-3-session-empty-buffer)
     :message-buffer (%websocket-http2-3-session-empty-buffer)
     :fragment-count 0
     :control-frame-count 0
     :data-bytes 0
     :data-frame-count 0
     :frame-count 0)))

(defun make-websocket-http2-session
    (stream-id read-function write-function &rest initargs)
  "Create a stateful WebSocket DATA session on an established HTTP/2 stream.

READ-FUNCTION returns one or more raw HTTP/2 frame octets at a time and may
return :EOF, or NIL with a true second value, when the peer ends its side.
WRITE-FUNCTION receives raw HTTP/2 frame octets and the keyword
:END-STREAM-P and must accept the complete batch before returning.  It may
return NIL, T, or the accepted byte count; a partial count is an error.  The
  caller owns the HTTP/2 connection preface, SETTINGS, extended CONNECT
  exchange, flow control, and stream scheduling.  PAYLOAD-ENCODER, when
  supplied, receives the normalized message octets and opcode before
  fragmentation; PAYLOAD-DECODER receives each data-frame payload and frame.
  The encoder and decoder results are checked against MAX-MESSAGE-BYTES, and
  RESERVED-BITS are emitted only on the first outbound data frame.  A session
  close writes its Close frame and local stream end without waiting for the
  peer's Close frame; the transport callback remains caller-owned."
  (apply #'%websocket-http2-3-session-make
         :http2 stream-id read-function write-function initargs))

(defun make-websocket-http3-session
    (stream-id read-function write-function &rest initargs)
  "Create a stateful WebSocket DATA session on an established HTTP/3 stream.

The callbacks own QUIC stream I/O, FIN handling, flow control, and stream
scheduling.  WRITE-FUNCTION receives raw HTTP/3 frame octets and the keyword
:END-STREAM-P and must accept the complete batch before returning.  It may
return NIL, T, or the accepted byte count; a partial count is an error.
READ-FUNCTION returns octets and an optional FIN indication.  PAYLOAD-ENCODER,
when supplied, receives the normalized message octets and opcode before
fragmentation; PAYLOAD-DECODER receives each data-frame payload and frame.
The encoder and decoder results are checked against MAX-MESSAGE-BYTES, and
RESERVED-BITS are emitted only on the first outbound data frame.  A session
close writes its Close frame and local stream end without waiting for the
peer's Close frame; the transport callback remains caller-owned."
  (apply #'%websocket-http2-3-session-make
         :http3 stream-id read-function write-function initargs))

(defun websocket-http2-3-session-send
    (session payload &rest initargs)
  "Send one complete WebSocket data message through SESSION."
  (%websocket-http2-3-session-ensure session)
  (%websocket-http2-3-session-call-with-failure
   session
   (lambda ()
     (apply #'%websocket-http2-3-session-send session payload initargs))))

(defun websocket-http2-session-send
    (session payload &rest initargs)
  (%websocket-http2-3-session-ensure-protocol session :http2)
  (apply #'websocket-http2-3-session-send session payload initargs))

(defun websocket-http3-session-send
    (session payload &rest initargs)
  (%websocket-http2-3-session-ensure-protocol session :http3)
  (apply #'websocket-http2-3-session-send session payload initargs))

(defun websocket-http2-3-session-receive
    (session &key on-control timeout deadline clock-function)
  "Read one complete WebSocket message from SESSION.

Returns payload and opcode, returns NIL and :EOF after a clean peer FIN, and
returns the close payload and :CLOSE when the peer sends a WebSocket Close.
  ON-CONTROL receives Ping, Pong, and Close frames; Ping is answered
  automatically and Close is echoed when the local side is still open."
  (%websocket-http2-3-session-ensure session)
  (let ((effective-deadline
          (if (or timeout deadline)
              (%websocket-effective-deadline
               timeout deadline clock-function)
              nil)))
    (%websocket-http2-3-session-call-with-failure
     session
     (lambda ()
       (%websocket-http2-3-session-receive
        session on-control effective-deadline)))))

(defun websocket-http2-session-receive
    (session &key on-control timeout deadline clock-function)
  (%websocket-http2-3-session-ensure-protocol session :http2)
  (websocket-http2-3-session-receive
   session
   :on-control on-control
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-http3-session-receive
    (session &key on-control timeout deadline clock-function)
  (%websocket-http2-3-session-ensure-protocol session :http3)
  (websocket-http2-3-session-receive
   session
   :on-control on-control
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-http2-3-session-close
    (session &key (code 1000) (reason "") timeout deadline clock-function)
  "Send a WebSocket Close frame and end the local HTTP/2 or HTTP/3 stream."
  (%websocket-http2-3-session-ensure session)
  (let ((effective-deadline
          (if (or timeout deadline)
              (%websocket-effective-deadline
               timeout deadline clock-function)
              nil)))
    (%websocket-http2-3-session-call-with-failure
     session
     (lambda ()
       (%websocket-http2-3-session-with-write-lock (session)
         (unless (or (websocket-http2-3-session-closed-p session)
                     (websocket-http2-3-session-local-end-p session))
           (let ((payload (make-websocket-close-payload :code code :reason reason)))
             (%websocket-http2-3-session-write-control
              session 8 payload :end-stream-p t :deadline effective-deadline)
             (setf (websocket-http2-3-session-local-end-p session) t)))
         (setf (websocket-http2-3-session-closed-p session) t)
         session)))))

(defun websocket-http2-session-close
    (session &key (code 1000) (reason "") timeout deadline clock-function)
  (%websocket-http2-3-session-ensure-protocol session :http2)
  (websocket-http2-3-session-close
   session
   :code code
   :reason reason
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-http3-session-close
    (session &key (code 1000) (reason "") timeout deadline clock-function)
  (%websocket-http2-3-session-ensure-protocol session :http3)
  (websocket-http2-3-session-close
   session
   :code code
   :reason reason
   :timeout timeout
   :deadline deadline
   :clock-function clock-function))

(defun websocket-http2-3-session-abort (session)
  "Abort SESSION without writing a WebSocket Close frame."
  (%websocket-http2-3-session-ensure session)
  (%websocket-http2-3-session-call-with-failure
   session
   (lambda ()
     (let ((notify-p nil))
       (%websocket-http2-3-session-with-write-lock (session)
         (unless (websocket-http2-3-session-closed-p session)
           (setf (websocket-http2-3-session-closed-p session) t
                 (websocket-http2-3-session-local-end-p session) t
                 notify-p t)))
       (when notify-p
         (%websocket-http2-3-session-call-close session t))
       session))))

(defun websocket-http2-session-abort (session)
  (%websocket-http2-3-session-ensure-protocol session :http2)
  (websocket-http2-3-session-abort session))

(defun websocket-http3-session-abort (session)
  (%websocket-http2-3-session-ensure-protocol session :http3)
  (websocket-http2-3-session-abort session))
