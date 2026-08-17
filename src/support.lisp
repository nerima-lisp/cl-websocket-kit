(in-package #:websocket-kit)

(defun %websocket-monotonic-time ()
  (/ (float (get-internal-real-time))
     (float internal-time-units-per-second)))

(defun %websocket-network-clock (clock-function)
  (or clock-function #'%websocket-monotonic-time))

(defun %websocket-effective-deadline (timeout deadline clock-function)
  (let ((clock (%websocket-network-clock clock-function)))
    (unless (functionp clock)
      (%websocket-protocol-error
       "CLOCK-FUNCTION must be callable."
       clock))
    (when (and timeout
               (or (not (realp timeout)) (minusp timeout)))
      (%websocket-protocol-error
       "TIMEOUT must be NIL or a non-negative real number."
       timeout))
    (when (and deadline
               (or (not (realp deadline)) (minusp deadline)))
      (%websocket-protocol-error
       "DEADLINE must be NIL or a non-negative real number."
       deadline))
    (let ((relative (and timeout (+ (funcall clock) timeout))))
      (cond ((and relative deadline) (min relative deadline))
            (relative relative)
            (deadline deadline)
            (t nil)))))

(defun %websocket-call-with-deadline
    (thunk deadline clock-function operation)
  (unless (functionp thunk)
    (%websocket-protocol-error
     "A deadline-wrapped operation must be callable."
     thunk))
  (let ((remaining (and deadline
                        (- deadline (funcall clock-function)))))
    (when (and remaining (<= remaining 0))
      (error 'websocket-timeout
             :kind operation
             :operation operation
             :message "The WebSocket operation exceeded its deadline."
             :detail operation))
    #+sbcl
    (if remaining
        (handler-case
            (sb-ext:with-timeout remaining
              (funcall thunk))
          (sb-ext:timeout ()
            (error 'websocket-timeout
                   :kind operation
                   :operation operation
                   :message "The WebSocket operation exceeded its deadline."
                   :detail operation)))
        (funcall thunk))
    #-sbcl
    (funcall thunk)))

(defmacro %websocket-with-cleanup (&body body)
  "Run cleanup code without replacing the original failure with a cleanup error."
  `(handler-case
       (progn ,@body)
     (error (condition)
       (declare (ignore condition))
       nil)))

(defun %websocket-push-utf8-code-point (code result)
  (cond ((<= code #x7f)
         (vector-push-extend code result))
        ((<= code #x7ff)
         (vector-push-extend (+ #xc0 (ldb (byte 5 6) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 0) code)) result))
        ((<= code #xffff)
         (when (<= #xd800 code #xdfff)
           (%websocket-protocol-error
            "UTF-8 cannot encode a surrogate code point."
            code))
         (vector-push-extend (+ #xe0 (ldb (byte 4 12) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 6) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 0) code)) result))
        ((<= code #x10ffff)
         (vector-push-extend (+ #xf0 (ldb (byte 3 18) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 12) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 6) code)) result)
         (vector-push-extend (+ #x80 (ldb (byte 6 0) code)) result))
        (t
         (%websocket-protocol-error
          "A character is outside the Unicode scalar value range."
          code))))

(defun %websocket-utf8-octets (string)
  "Encode STRING as UTF-8 octets without depending on implementation codecs."
  (unless (stringp string)
    (%websocket-protocol-error "UTF-8 encoding requires a string." string))
  (let ((result (make-array 0
                            :element-type '(unsigned-byte 8)
                            :adjustable t
                            :fill-pointer 0)))
    (loop for character across string
          do (%websocket-push-utf8-code-point (char-code character) result))
    (let ((copy (make-array (length result)
                            :element-type '(unsigned-byte 8))))
      (replace copy result)
      copy)))
