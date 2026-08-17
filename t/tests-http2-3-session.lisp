(in-package #:websocket-kit/test)

(defun %session-chunk-reader (wire &optional (chunk-size 2))
  (let ((position 0))
    (lambda ()
      (if (< position (length wire))
          (let ((end (min (length wire) (+ position chunk-size))))
            (prog1 (values (subseq wire position end) nil)
              (setf position end)))
          (values nil t)))))

(describe "stateful HTTP/2 and HTTP/3 WebSocket sessions"
  (it "receives an incrementally fragmented HTTP/2 message"
    (let* ((wire (encode-websocket-http2-message-data-frames
                  (octets 1 2 3) 1 :end-stream-p t))
           (session (make-websocket-http2-session
                     1
                     (%session-chunk-reader wire)
                     (lambda (octets &key end-stream-p)
                       (declare (ignore octets end-stream-p)))))
           (payload nil)
           (opcode nil))
      (multiple-value-setq (payload opcode)
        (websocket-http2-session-receive session))
      (expect payload :to-equalp (octets 1 2 3))
      (expect opcode :to-equalp 2)
      (multiple-value-setq (payload opcode)
        (websocket-http2-session-receive session))
      (expect payload :to-equalp nil)
      (expect opcode :to-equalp :eof)
      (expect (websocket-http2-3-session-remote-end-p session)
              :to-equalp
              t)))

  (it "sends an HTTP/2 message and closes the stream"
    (let* ((writes nil)
          (session (make-websocket-http2-session
                    3
                    (lambda () (values nil t))
                    (lambda (octets &key end-stream-p)
                      (push (list octets end-stream-p) writes)
                      nil))))
      (websocket-http2-session-send session (octets 9 8 7)
                                    :opcode 2
                                    :end-stream-p t)
      (expect (length writes) :to-equalp 1)
      (expect (second (first writes)) :to-equalp t)
      (expect (websocket-http2-3-session-local-end-p session)
              :to-equalp
              t)))

  (it "applies outbound payload transformers and reserved bits to HTTP/2 and HTTP/3 sessions"
    (dolist (protocol '(:http2 :http3))
      (let* ((writes nil)
             (stream-id (if (eq protocol :http2) 1 5))
             (constructor (if (eq protocol :http2)
                              #'make-websocket-http2-session
                              #'make-websocket-http3-session))
             (session
               (funcall
                constructor
                stream-id
                (lambda () (values nil t))
                (lambda (octets &key end-stream-p)
                  (declare (ignore end-stream-p))
                  (push (copy-seq octets) writes)
                  (length octets))
                :max-frame-payload-bytes 2
                :payload-encoder
                (lambda (payload opcode)
                  (declare (ignore opcode))
                  (concatenate '(vector (unsigned-byte 8))
                               payload
                               (octets 99)))
                :reserved-bits #x40)))
        (websocket-http2-3-session-send session (octets 1 2))
        (let* ((transport-wire (first writes))
               (frames
                 (if (eq protocol :http2)
                     (decode-websocket-http2-websocket-data-frames
                      transport-wire
                      :expected-stream-id stream-id
                      :allowed-reserved-bits #x40
                      :require-complete-p t)
                     (decode-websocket-http3-websocket-data-frames
                      transport-wire
                      :expected-stream-id stream-id
                      :allowed-reserved-bits #x40
                      :require-complete-p t))))
          (expect (length frames) :to-equalp 2)
          (expect (websocket-frame-reserved-bits (first frames))
                  :to-equalp #x40)
          (expect (websocket-frame-reserved-bits (second frames))
                  :to-equalp 0)
          (expect (websocket-frame-payload (first frames))
                  :to-equalp (octets 1 2))
          (expect (websocket-frame-payload (second frames))
                  :to-equalp (octets 99))))))

  (it "writes one Close frame and ignores repeated session close"
    (dolist (protocol '(:http2 :http3))
      (let* ((writes nil)
             (stream-id (if (eq protocol :http2) 1 5))
             (constructor (if (eq protocol :http2)
                              #'make-websocket-http2-session
                              #'make-websocket-http3-session))
             (session
               (funcall
                constructor
                stream-id
                (lambda () (values nil t))
                (lambda (octets &key end-stream-p)
                  (push (list (copy-seq octets) end-stream-p) writes)
                  (length octets)))))
        (websocket-http2-3-session-close session :code 1000 :reason "bye")
        (websocket-http2-3-session-close session :code 1001 :reason "again")
        (expect (length writes) :to-equalp 1)
        (expect (second (first writes)) :to-equalp t)
        (let* ((wire (first (first writes)))
               (frames
                 (if (eq protocol :http2)
                     (decode-websocket-http2-websocket-data-frames
                      wire
                      :expected-stream-id stream-id
                      :require-complete-p t)
                     (decode-websocket-http3-websocket-data-frames
                      wire
                      :expected-stream-id stream-id
                      :require-complete-p t))))
          (expect (length frames) :to-equalp 1)
          (expect (websocket-frame-opcode (first frames)) :to-equalp 8)
          (expect (websocket-frame-payload (first frames))
                  :to-equalp
                  (make-websocket-close-payload :code 1000 :reason "bye")))
        (expect (websocket-http2-3-session-local-end-p session)
                :to-equalp
                t)
        (expect (websocket-http2-3-session-closed-p session)
                :to-equalp
                t))))

  (it "accepts an explicit complete write count"
    (let ((session (make-websocket-http2-session
                    1
                    (lambda () (values nil t))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore end-stream-p))
                      (length octets)))))
      (websocket-http2-session-send session (octets 1 2 3))
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              nil)))

  (it "rejects an empty transport read without end-of-stream"
    (let* ((reads 0)
          (session (make-websocket-http2-session
                    1
                    (lambda ()
                      (incf reads)
                      (values (octets) nil))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore octets end-stream-p))))))
      (signals websocket-transport-error
        (websocket-http2-session-receive session))
      (expect reads :to-equalp 1)
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "treats an empty transport read with end-of-stream as EOF"
    (let ((session (make-websocket-http2-session
                    1
                    (lambda () (values (octets) t))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore octets end-stream-p))))))
      (multiple-value-bind (payload opcode)
          (websocket-http2-session-receive session)
        (expect payload :to-equalp nil)
        (expect opcode :to-equalp :eof))
      (expect (websocket-http2-3-session-remote-end-p session)
              :to-equalp
              t)))

  (it "rejects an oversized transport batch before copying it"
    (let ((session (make-websocket-http2-session
                    1
                    (lambda () (values (octets 1 2 3) nil))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore octets end-stream-p)))
                    :max-buffered-wire-bytes 2))
          (condition nil))
      (handler-case
          (websocket-http2-session-receive session)
        (websocket-size-limit-exceeded (caught)
          (setf condition caught)))
      (expect (typep condition 'websocket-size-limit-exceeded)
              :to-equalp
              t)
      (expect (websocket-size-limit-exceeded-limit condition)
              :to-equalp
              2)
      (expect (websocket-size-limit-exceeded-observed condition)
              :to-equalp
              3)
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "terminalizes before a failing abort callback can be retried"
    (let* ((calls 0)
          (session (make-websocket-http2-session
                    1
                    (lambda () (values nil t))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore octets end-stream-p)))
                    :close-function
                    (lambda (&key abort-p)
                      (declare (ignore abort-p))
                      (incf calls)
                      (error "close callback failed")))))
      (signals websocket-transport-error
        (websocket-http2-session-abort session))
      (expect calls :to-equalp 1)
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "runs an abort callback after releasing the write lock"
    (let ((calls 0)
          session)
      (setf session
            (make-websocket-http2-session
             1
             (lambda () (values nil t))
             (lambda (octets &key end-stream-p)
               (declare (ignore octets end-stream-p)))
             :close-function
             (lambda (&key abort-p)
               (declare (ignore abort-p))
               (incf calls)
               (websocket-http2-session-abort session))))
      (websocket-http2-session-abort session)
      (expect calls :to-equalp 1)
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "terminalizes a session after partial transport acceptance"
    (let* ((aborts nil)
          (session (make-websocket-http2-session
                    1
                    (lambda () (values nil t))
                    (lambda (octets &key end-stream-p)
                      (declare (ignore octets end-stream-p))
                      1)
                    :close-function
                    (lambda (&key abort-p)
                      (push abort-p aborts)))))
      (signals websocket-transport-error
        (websocket-http2-session-send session (octets 1 2 3)))
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)
      (expect aborts :to-equalp (list t))
      (signals websocket-protocol-error
        (websocket-http2-session-send session (octets 4)))))

  (it "rejects decoded HTTP/2 payloads over the message limit"
    (let ((session
            (make-websocket-http2-session
             1
             (%session-chunk-reader
              (encode-websocket-http2-message-data-frames
               (octets 1) 1 :end-stream-p t))
             (lambda (octets &key end-stream-p)
               (declare (ignore octets end-stream-p)))
             :payload-decoder
             (lambda (payload frame)
               (declare (ignore frame))
               (concatenate '(vector (unsigned-byte 8))
                            payload
                            (octets 2 3)))
             :max-message-bytes 2)))
      (signals websocket-size-limit-exceeded
        (websocket-http2-session-receive session))
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "enforces the aggregate WebSocket frame limit"
    (let* ((wire (encode-websocket-http2-message-data-frames
                  (octets 1 2)
                  1
                  :max-frame-payload-bytes 1
                  :end-stream-p t))
           (session (make-websocket-http2-session
                     1
                     (%session-chunk-reader wire)
                     (lambda (octets &key end-stream-p)
                       (declare (ignore octets end-stream-p)))
                     :max-frames 1)))
      (signals websocket-size-limit-exceeded
        (websocket-http2-session-receive session))
      (expect (websocket-http2-3-session-frame-count session)
              :to-equalp
              2)
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "rejects stream data after a received Close frame"
    (let* ((message-wire
             (concatenate '(vector (unsigned-byte 8))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p t :opcode 8 :payload (octets 3 232)))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p t :opcode 2 :payload (octets 9)))))
           (wire (encode-websocket-http2-data-frames
                  message-wire 1 :end-stream-p t))
           (session (make-websocket-http2-session
                     1
                     (%session-chunk-reader wire 2)
                     (lambda (octets &key end-stream-p)
                       (declare (ignore octets end-stream-p))))))
      (signals websocket-protocol-error
        (websocket-http2-session-receive session))
      (expect (websocket-http2-3-session-closed-p session)
              :to-equalp
              t)))

  (it "runs control callbacks after releasing the read lock"
    (let* ((wire (encode-websocket-http2-data-frames
                  (serialize-websocket-frame
                   (make-websocket-frame
                    :fin-p t
                    :opcode 9
                    :payload (octets 1 2)))
                  1
                  :end-stream-p t))
           (nested-result nil)
           (control-opcodes nil)
           (session (make-websocket-http2-session
                     1
                     (%session-chunk-reader wire)
                     (lambda (octets &key end-stream-p)
                       (declare (ignore octets end-stream-p))))))
      (multiple-value-bind (payload opcode)
          (websocket-http2-session-receive
           session
           :on-control
           (lambda (frame)
             (push (websocket-frame-opcode frame) control-opcodes)
             (setf nested-result
                   (multiple-value-list
                    (websocket-http2-session-receive session)))))
        (expect payload :to-equalp nil)
        (expect opcode :to-equalp :eof))
      (expect control-opcodes :to-equalp (list 9))
      (expect nested-result :to-equalp (list nil :eof))))

  (it "receives an incrementally fragmented HTTP/3 message"
    (let* ((wire (encode-websocket-http3-message-data-frames
                  "hello" 5
                  :opcode 1
                  :max-frame-payload-bytes 3))
           (session (make-websocket-http3-session
                     5
                     (%session-chunk-reader wire 1)
                     (lambda (octets &key end-stream-p)
                       (declare (ignore octets end-stream-p)))))
           (payload nil)
           (opcode nil))
      (multiple-value-setq (payload opcode)
        (websocket-http3-session-receive session))
      (expect payload :to-equalp (octets 104 101 108 108 111))
      (expect opcode :to-equalp 1)))

  (it "forwards absolute deadlines to session callbacks"
    (let* ((read-deadline nil)
           (write-deadline nil)
           (session
             (make-websocket-http2-session
              1
              (lambda (&key deadline)
                (setf read-deadline deadline)
                (values (octets) t))
              (lambda (octets &key end-stream-p deadline)
                (declare (ignore end-stream-p))
                (setf write-deadline deadline)
                (length octets)))))
      (websocket-http2-session-send
       session (octets 1 2 3)
       :timeout 2
       :clock-function (lambda () 5))
      (expect write-deadline :to-equalp 7)
      (websocket-http2-session-receive
       session
       :deadline 12
       :clock-function (lambda () 3))
      (expect read-deadline :to-equalp 12))))
