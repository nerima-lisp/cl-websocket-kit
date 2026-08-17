(in-package #:websocket-kit/test)

(defun %large-http-header (size)
  (make-http-header "x-large" (make-string size :initial-element #\a)))

(describe "HTTP/2 and HTTP/3 extended CONNECT"
  (it "builds and recognizes extended CONNECT headers"
    (let ((headers (make-websocket-http2-connect-headers
                    "example.test"
                    :headers (list (make-http-header "x-test" "ok")))))
      (expect (websocket-http2-extended-connect-p headers)
              :to-equalp
              t)
      (expect (websocket-http3-extended-connect-p headers)
              :to-equalp
              t)
      (expect (http-header-content
               (find ":protocol" headers
                     :key #'http-header-name
                     :test #'string-equal))
              :to-equalp
              "websocket")
      (signals websocket-http-error
        (make-websocket-http2-connect-headers ""))
      (signals websocket-http-error
        (make-websocket-http2-connect-headers "example.test" :scheme "ws"))
      (signals websocket-http-error
        (make-http-pseudo-header ":Upper" "value"))
      (expect
       (websocket-http2-extended-connect-p
        (list (make-http-pseudo-header ":method" "connect")
              (make-http-pseudo-header ":protocol" "websocket")
              (make-http-pseudo-header ":scheme" "https")
              (make-http-pseudo-header ":authority" "example.test")
              (make-http-pseudo-header ":path" "/")))
       :to-equalp
       nil)))

  (it "emits the HTTP/2 connection preface with CRLF octets"
    (expect (coerce (websocket-http2-connection-preface) 'list)
            :to-equalp
            '(80 82 73 32 42 32 72 84 84 80 47 50 46 48
              13 10 13 10 83 77 13 10 13 10)))

  (it "round trips HPACK and QPACK header blocks"
    (let* ((headers (make-websocket-http2-connect-headers "example.test"))
           (hpack-wire (encode-websocket-http2-headers headers))
           (qpack-wire (encode-websocket-http3-headers headers 0)))
      (multiple-value-bind (decoded consumed)
          (decode-websocket-http2-headers hpack-wire)
        (expect consumed :to-equalp (length hpack-wire))
        (expect (websocket-http2-extended-connect-p decoded)
                :to-equalp
                t))
      (multiple-value-bind (decoded consumed)
          (decode-websocket-http3-headers qpack-wire 0)
        (expect consumed :to-equalp (length qpack-wire))
        (expect (websocket-http3-extended-connect-p decoded)
                :to-equalp
                t))))

  (it "round trips stateful HPACK blocks and reuses the dynamic table"
    (let* ((headers
             (make-websocket-http2-connect-headers
              "example.test"
              :headers (list (make-http-header "x-dynamic" "one"))))
           (encoder (make-websocket-http2-hpack-context))
           (decoder (make-websocket-http2-hpack-context))
           (first-wire
             (encode-websocket-http2-headers headers :context encoder))
           (second-wire
             (encode-websocket-http2-headers headers :context encoder)))
      (multiple-value-bind (decoded consumed)
          (decode-websocket-http2-headers first-wire :context decoder)
        (expect consumed :to-equalp (length first-wire))
        (expect (websocket-http2-extended-connect-p decoded)
                :to-equalp
                t))
      (multiple-value-bind (decoded consumed)
          (decode-websocket-http2-headers second-wire :context decoder)
        (expect consumed :to-equalp (length second-wire))
        (expect (websocket-http2-extended-connect-p decoded)
                :to-equalp
                t))
      (expect (websocket-http2-hpack-context-size encoder)
              :to-equalp
              (websocket-http2-hpack-context-size decoder))
      (expect (> (websocket-http2-hpack-context-size encoder) 0)
              :to-equalp
              t)
      (expect (< (length second-wire) (length first-wire))
              :to-equalp
              t)))

  (it "updates the HPACK table size and never-indexes sensitive fields"
    (let* ((headers
             (make-websocket-http2-connect-response-headers
              :headers (list (make-http-header "authorization" "secret"))))
           (encoder (make-websocket-http2-hpack-context))
           (decoder (make-websocket-http2-hpack-context)))
      (set-websocket-http2-hpack-context-max-size encoder 0)
      (set-websocket-http2-hpack-context-max-size decoder 0)
      (let ((wire (encode-websocket-http2-headers
                   headers
                   :context encoder
                   :request-p nil)))
        (expect (aref wire 0) :to-equalp #x20)
        (multiple-value-bind (decoded consumed)
            (decode-websocket-http2-headers
             wire
             :context decoder
             :request-p nil)
          (expect consumed :to-equalp (length wire))
          (expect (websocket-http2-connect-response-p decoded)
                  :to-equalp
                  t))
        (expect (websocket-http2-hpack-context-size encoder)
                :to-equalp
                0)
        (expect (websocket-http2-hpack-context-size decoder)
                :to-equalp
                0))))

  (it "rejects unsupported HTTP/2 HPACK dynamic contexts"
    (signals websocket-http-error
      (encode-websocket-http2-headers
       (make-websocket-http2-connect-headers "example.test")
       :context :dynamic-table)))

  (it "reassembles fragmented HTTP/2 HEADERS"
    (let* ((headers (make-websocket-http2-connect-headers
                     "example.test"
                     :headers (list (%large-http-header 30000))))
           (wire (encode-websocket-http2-headers-frames headers 1)))
      (expect (> (length wire) 16384) :to-equalp t)
      (multiple-value-bind (decoded consumed stream-id end-stream-p)
          (decode-websocket-http2-headers-frames
           wire :expected-stream-id 1)
        (expect consumed :to-equalp (length wire))
        (expect stream-id :to-equalp 1)
        (expect end-stream-p :to-equalp nil)
        (expect (websocket-http2-extended-connect-p decoded)
                :to-equalp
                t))))

  (it "reports END_STREAM from the initial HTTP/2 HEADERS fragment"
    (let* ((headers (make-websocket-http2-connect-headers
                     "example.test"
                     :headers (list (%large-http-header 30000))))
           (wire (encode-websocket-http2-headers-frames
                  headers 1 :end-stream-p t)))
      (multiple-value-bind (decoded consumed stream-id end-stream-p)
          (decode-websocket-http2-headers-frames
           wire :expected-stream-id 1)
        (expect consumed :to-equalp (length wire))
        (expect stream-id :to-equalp 1)
        (expect end-stream-p :to-equalp t)
        (expect (websocket-http2-extended-connect-p decoded)
                :to-equalp
                t))))

  (it "enforces decoded HTTP/2 and HTTP/3 HEADERS frame limits"
    (let ((headers (make-websocket-http2-connect-headers
                    "example.test"
                    :headers (list (%large-http-header 30000)))))
      (let ((http2-wire
              (encode-websocket-http2-headers-frames
               headers 1 :max-frame-size 32768))
            (http3-wire
              (encode-websocket-http3-headers-frame
               headers 0 :max-frame-size 32768)))
        (signals websocket-size-limit-exceeded
          (decode-websocket-http2-headers-frames
           http2-wire :expected-stream-id 1))
        (signals websocket-size-limit-exceeded
          (decode-websocket-http3-headers-frame
           http3-wire :expected-stream-id 0))
        (signals websocket-size-limit-exceeded
          (encode-websocket-http2-headers-frames
           headers 1 :max-header-block-bytes 1))
        (signals websocket-size-limit-exceeded
          (encode-websocket-http3-headers-frame
           headers 0 :max-header-block-bytes 1)))))

  (it "splits and decodes HTTP/2 DATA"
    (let* ((payload (make-array 20000
                                :element-type '(unsigned-byte 8)
                                :initial-element 7))
           (wire (encode-websocket-http2-data-frames
                  payload 1 :end-stream-p t)))
      (multiple-value-bind (first used stream-id end-stream-p)
          (decode-websocket-http2-data-frame
           wire :expected-stream-id 1)
        (multiple-value-bind (second used-next stream-id-next end-stream-next-p)
            (decode-websocket-http2-data-frame
             (subseq wire used) :expected-stream-id 1)
          (expect first
                  :to-equalp
                  (subseq payload 0 +websocket-http2-default-max-frame-size+))
          (expect second
                  :to-equalp
                  (subseq payload +websocket-http2-default-max-frame-size+))
          (expect (+ used used-next) :to-equalp (length wire))
          (expect stream-id :to-equalp 1)
          (expect stream-id-next :to-equalp 1)
          (expect end-stream-p :to-equalp nil)
          (expect end-stream-next-p :to-equalp t)))))

  (it "bridges fragmented masked WebSocket messages through HTTP/2 DATA"
    (let ((payload (make-array 20000 :element-type '(unsigned-byte 8))))
      (loop for index below (length payload)
            do (setf (aref payload index) (mod index 251)))
      (let ((key-counter 0))
        (let ((wire
                (encode-websocket-http2-message-data-frames
                 payload 1
                 :max-frame-payload-bytes 4096
                 :mask-p t
                 :masking-key-function
                 (lambda ()
                   (incf key-counter)
                   (octets key-counter 2 3 4))
                 :end-stream-p t
                 :max-frame-size 16384)))
          (multiple-value-bind (frames consumed stream-id end-stream-p)
              (decode-websocket-http2-websocket-data-frames
               wire
               :expected-stream-id 1
               :require-mask-p t
               :allow-unmasked-p nil)
            (expect consumed :to-equalp (length wire))
            (expect stream-id :to-equalp 1)
            (expect end-stream-p :to-equalp t)
            (expect (length frames) :to-equalp 5)
            (let ((position 0))
              (dolist (frame frames)
                (let* ((frame-payload (websocket-frame-payload frame))
                       (end (+ position (length frame-payload))))
                  (expect (websocket-frame-mask-p frame) :to-equalp t)
                  (expect frame-payload
                          :to-equalp
                          (subseq payload position end))
                  (setf position end)))
              (expect position :to-equalp (length payload)))
            (expect (websocket-frame-opcode (first frames))
                    :to-equalp
                    2)
            (expect (websocket-frame-opcode (second frames))
                    :to-equalp
                    0)
            (expect (websocket-frame-fin-p (car (last frames)))
                    :to-equalp
                    t))
          (signals websocket-size-limit-exceeded
            (decode-websocket-http2-websocket-data-frames
             wire :expected-stream-id 1 :max-data-bytes 1))
          (signals websocket-size-limit-exceeded
            (decode-websocket-http2-websocket-data-frames
             wire :expected-stream-id 1 :max-data-frames 1))
          (signals websocket-size-limit-exceeded
            (encode-websocket-http2-message-data-frames
             payload 1 :max-message-bytes 1))
          (signals websocket-http-error
            (decode-websocket-http2-websocket-data-frames
             wire :expected-stream-id 3))))))

  (it "bridges fragmented WebSocket messages through HTTP/3 DATA"
    (let ((wire
            (encode-websocket-http3-message-data-frames
             "hello" 0
             :opcode 1
             :max-frame-payload-bytes 2
             :max-frame-size 7)))
      (multiple-value-bind (frames consumed stream-id)
          (decode-websocket-http3-websocket-data-frames
           wire :expected-stream-id 0)
        (expect consumed :to-equalp (length wire))
        (expect stream-id :to-equalp 0)
        (expect (length frames) :to-equalp 3)
        (expect (websocket-frame-opcode (first frames)) :to-equalp 1)
        (expect (websocket-frame-opcode (second frames)) :to-equalp 0)
        (expect (websocket-frame-fin-p (first frames)) :to-equalp nil)
        (expect (websocket-frame-fin-p (second frames)) :to-equalp nil)
        (expect (websocket-frame-fin-p (car (last frames))) :to-equalp t)
        (expect (websocket-frame-payload (first frames))
                :to-equalp
                (octets 104 101))
        (expect (websocket-frame-payload (second frames))
                :to-equalp
                (octets 108 108))
        (expect (websocket-frame-payload (car (last frames)))
                :to-equalp
                (octets 111)))
      (signals websocket-size-limit-exceeded
        (decode-websocket-http3-websocket-data-frames
         wire :expected-stream-id 0 :max-data-bytes 1))
      (signals websocket-size-limit-exceeded
        (encode-websocket-http3-message-data-frames
         "hello" 0 :opcode 1 :max-message-bytes 1))
      (signals websocket-http-error
        (decode-websocket-http3-websocket-data-frames
         wire :expected-stream-id -1))))

  (it "rejects invalid WebSocket message frame sequences in HTTP/2"
    (let ((continuation-wire
            (encode-websocket-http2-data-frames
             (serialize-websocket-frame
              (make-websocket-frame
               :fin-p t :opcode 0 :payload (octets 1 2)))
             1)))
      (signals websocket-protocol-error
        (decode-websocket-http2-websocket-data-frames
         continuation-wire :expected-stream-id 1)))
    (let ((overlapping-wire
            (encode-websocket-http2-data-frames
             (concatenate '(vector (unsigned-byte 8))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p nil :opcode 2 :payload (octets 1)))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p t :opcode 1 :payload (octets 2))))
             1)))
      (signals websocket-protocol-error
        (decode-websocket-http2-websocket-data-frames
         overlapping-wire :expected-stream-id 1)))
    (let ((close-then-data-wire
            (encode-websocket-http2-data-frames
             (concatenate '(vector (unsigned-byte 8))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p t :opcode 8 :payload (octets 3 232)))
                          (serialize-websocket-frame
                           (make-websocket-frame
                            :fin-p t :opcode 2 :payload (octets 9))))
             1)))
      (signals websocket-protocol-error
        (decode-websocket-http2-websocket-data-frames
         close-then-data-wire :expected-stream-id 1))))

  (it "validates HTTP/2 stream identifiers and header flags"
    (let ((wire (encode-websocket-http2-headers-frames
                 (make-websocket-http2-connect-headers "example.test")
                 1)))
      (signals websocket-http-error
        (decode-websocket-http2-headers-frames
         wire :expected-stream-id 0))
      (signals websocket-http-error
        (decode-websocket-http2-headers-frames
         wire :expected-stream-id "1")))
    (signals websocket-http-error
      (websocket-kit::%websocket-http2-3-validate-header-section
       (list (make-http-header "X-Invalid" "ok"))
       :http2)))

  (it "rejects an HTTP/2 HEADERS priority self-dependency"
    (let* ((block (encode-websocket-http2-headers
                   (make-websocket-http2-connect-headers "example.test")))
           (payload (concatenate '(vector (unsigned-byte 8))
                                 (octets 0 0 0 1 0)
                                 block))
           (wire (websocket-kit::%websocket-http2-3-encode-http2-frame
                  :headers #x24 1 payload)))
      (signals websocket-http-error
        (decode-websocket-http2-headers-frames
         wire :expected-stream-id 1))))

  (it "ignores reserved HTTP/2 stream bits and unknown frame flags"
    (let ((wire (encode-websocket-http2-data-frame (octets 1) 1)))
      (setf (aref wire 4) (logior (aref wire 4) #x40))
      (multiple-value-bind (payload used stream-id)
          (decode-websocket-http2-data-frame wire :expected-stream-id 1)
        (expect payload :to-equalp (octets 1))
        (expect used :to-equalp (length wire))
        (expect stream-id :to-equalp 1)))
    (let ((wire (encode-websocket-http2-data-frame (octets 1) 1)))
      (setf (aref wire 5) (logior (aref wire 5) #x80))
      (multiple-value-bind (payload used stream-id)
          (decode-websocket-http2-data-frame wire :expected-stream-id 1)
        (expect payload :to-equalp (octets 1))
        (expect used :to-equalp (length wire))
        (expect stream-id :to-equalp 1)))
    (let ((wire (encode-websocket-http2-headers-frames
                 (make-websocket-http2-connect-headers "example.test")
                 1)))
      (setf (aref wire 5) (logior (aref wire 5) #x80))
      (multiple-value-bind (headers used stream-id)
          (decode-websocket-http2-headers-frames
           wire :expected-stream-id 1)
        (expect (websocket-http2-extended-connect-p headers) :to-equalp t)
        (expect used :to-equalp (length wire))
        (expect stream-id :to-equalp 1)))
    (let ((wire (encode-websocket-http2-headers-frames
                 (make-websocket-http2-connect-headers "example.test")
                 1)))
      (setf (aref wire 4) (logior (aref wire 4) #x40))
      (multiple-value-bind (headers used stream-id)
          (decode-websocket-http2-headers-frames
           wire :expected-stream-id 1)
        (expect (websocket-http2-extended-connect-p headers) :to-equalp t)
        (expect used :to-equalp (length wire))
        (expect stream-id :to-equalp 1))))

  (it "round trips HTTP/3 HEADERS, DATA, and settings"
    (let* ((headers (make-websocket-http3-connect-headers "example.test"))
           (headers-wire (encode-websocket-http3-headers-frame headers 0))
           (data-wire (encode-websocket-http3-data-frame (octets 1 2 3) 0))
           (http2-settings (encode-websocket-http2-connect-settings))
           (http3-settings (encode-websocket-http3-connect-settings)))
      (multiple-value-bind (decoded consumed stream-id)
          (decode-websocket-http3-headers-frame
           headers-wire :expected-stream-id 0)
        (expect consumed :to-equalp (length headers-wire))
        (expect stream-id :to-equalp 0)
        (expect (websocket-http3-extended-connect-p decoded)
                :to-equalp
                t))
      (multiple-value-bind (payload consumed stream-id)
          (decode-websocket-http3-data-frame
           data-wire :expected-stream-id 0)
        (expect consumed :to-equalp (length data-wire))
        (expect stream-id :to-equalp 0)
        (expect payload :to-equalp (octets 1 2 3)))
      (expect (websocket-http2-connect-protocol-enabled-p
               (decode-websocket-http2-connect-settings http2-settings))
              :to-equalp
              t)
      (expect (websocket-http3-connect-protocol-enabled-p
               (decode-websocket-http3-connect-settings http3-settings))
              :to-equalp
              t)
      (expect (websocket-http2-connect-protocol-enabled-p
               (list (cons 8 "1")))
              :to-equalp
              nil)
      (expect (websocket-http3-connect-protocol-enabled-p
               (list (cons :enable-connect-protocol "1")))
              :to-equalp
              nil)
      (signals websocket-http-error
        (encode-websocket-http3-data-frame (octets 1) 2))
      (signals websocket-http-error
        (encode-websocket-http3-data-frame (octets 1) 6))
      (signals websocket-http-error
        (encode-websocket-http3-headers-frame
         (make-websocket-http3-connect-headers "example.test")
         2))))

  (it "rejects invalid HTTP/2 ENABLE_CONNECT_PROTOCOL settings"
    (let ((wire (encode-websocket-http2-connect-settings)))
      (setf (aref wire (1- (length wire))) 2)
      (signals websocket-http-error
        (decode-websocket-http2-connect-settings wire))))

  (it "rejects invalid HTTP/2 setting values"
    (labels ((setting-wire (identifier value)
               (let ((payload (make-array 6 :element-type '(unsigned-byte 8))))
                 (setf (aref payload 0) (ldb (byte 8 8) identifier)
                       (aref payload 1) (ldb (byte 8 0) identifier)
                       (aref payload 2) (ldb (byte 8 24) value)
                       (aref payload 3) (ldb (byte 8 16) value)
                       (aref payload 4) (ldb (byte 8 8) value)
                       (aref payload 5) (ldb (byte 8 0) value))
                 (websocket-kit::%websocket-http2-3-encode-http2-frame
                  :settings 0 0 payload))))
      (dolist (setting '((0 0) (2 2) (4 #x80000000) (5 #x3fff)))
        (signals websocket-http-error
          (decode-websocket-http2-connect-settings
           (setting-wire (first setting) (second setting)))))))

  (it "rejects duplicate HTTP/2 settings and invalid DATA padding"
    (let* ((wire (encode-websocket-http2-connect-settings))
           (payload (subseq wire 9))
           (duplicate-wire
             (websocket-kit::%websocket-http2-3-encode-http2-frame
              :settings 0 0
              (concatenate '(vector (unsigned-byte 8))
                           payload payload))))
      (signals websocket-http-error
        (decode-websocket-http2-connect-settings duplicate-wire)))
    (let ((wire (websocket-kit::%websocket-http2-3-encode-http2-frame
                 :data #x8 1 (octets 2 0))))
      (signals websocket-http-error
        (decode-websocket-http2-data-frame
         wire :expected-stream-id 1))))

  (it "rejects invalid HTTP/3 ENABLE_CONNECT settings"
    (let ((wire (encode-websocket-http3-connect-settings)))
      (setf (aref wire (1- (length wire))) 2)
      (signals websocket-http-error
        (decode-websocket-http3-connect-settings wire)))
    (let ((wire (encode-websocket-http3-connect-settings)))
      (setf (aref wire 2) 3)
      (signals websocket-http-error
        (decode-websocket-http3-connect-settings wire)))))
