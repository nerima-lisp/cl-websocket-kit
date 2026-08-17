(in-package #:websocket-kit/test)

(defun %connection-test-writer (writes)
  (lambda (octets &key stream-id end-stream-p)
    (push (list (copy-seq octets) stream-id end-stream-p) (car writes))
    (length octets)))

(describe "HTTP/2 and HTTP/3 WebSocket connections"
  (it "waits for peer HTTP/2 SETTINGS before opening a stream"
    (let* ((writes (list nil))
          (connection
            (make-websocket-http2-connection
             :role :client
             :write-function (%connection-test-writer writes))))
      (signals websocket-http-error
        (websocket-http2-connection-open-stream
         connection :authority "example.test"))
      (websocket-http2-3-connection-feed
       connection (encode-websocket-http2-connect-settings))
      (let ((stream
              (websocket-http2-connection-open-stream
               connection :authority "example.test")))
        (expect (websocket-http2-3-stream-p stream) :to-equalp t)
        (expect (websocket-http2-3-stream-id stream) :to-equalp 1)
        (expect (some (lambda (write) (= (second write) 1)) (car writes))
                :to-equalp
                t))))

  (it "ignores reserved HTTP/2 stream bits and unknown frame flags"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http2-connection
              :role :server
              :write-function (%connection-test-writer writes)))
           (settings (encode-websocket-http2-connect-settings))
           (headers (encode-websocket-http2-headers-frames
                     (make-websocket-http2-connect-headers "example.test")
                     1))
           (data (encode-websocket-http2-data-frame (octets 1) 1)))
      (setf (aref settings 4) (logior (aref settings 4) #x40)
            (aref headers 5) (logior (aref headers 5) #x80)
            (aref data 4) (logior (aref data 4) #x40))
      (websocket-http2-3-connection-feed
       connection
       (concatenate '(vector (unsigned-byte 8))
                    (websocket-http2-connection-preface)
                    settings headers data))
      (expect
       (websocket-http2-3-stream-p
        (websocket-http2-3-connection-stream connection 1))
       :to-equalp
       t)))

  (it "keeps reading HTTP/2 until the requested stream has data"
    (let* ((writes (list nil))
           (reads
             (list
              (encode-websocket-http2-data-frame (octets 3) 3)
              (encode-websocket-http2-data-frame (octets 1) 1)))
           (connection
             (make-websocket-http2-connection
              :role :server
              :read-function
              (lambda (&key deadline)
                (declare (ignore deadline))
                (let ((octets (pop reads)))
                  (if octets
                      (values octets nil)
                      (values :eof nil))))
              :write-function (%connection-test-writer writes)))
           (wire
             (concatenate
              '(vector (unsigned-byte 8))
              (websocket-http2-connection-preface)
              (encode-websocket-http2-connect-settings)
              (encode-websocket-http2-headers-frames
               (make-websocket-http2-connect-headers "one.test")
               1)
              (encode-websocket-http2-headers-frames
               (make-websocket-http2-connect-headers "two.test")
               3))))
      (websocket-http2-3-connection-feed connection wire)
      (let ((stream (websocket-http2-3-connection-stream connection 1)))
        (multiple-value-bind (payload endp)
            (websocket-kit::%websocket-http2-3-connection-stream-read stream)
          (expect
           payload
           :to-equalp
           (encode-websocket-http2-data-frame (octets 1) 1))
          (expect endp :to-equalp nil)))))

  (it "rejects an empty HTTP/2 connection read without end-of-stream"
    (let* ((reads 0)
           (connection
             (make-websocket-http2-connection
              :role :server
              :read-function
              (lambda (&key deadline)
                (declare (ignore deadline))
                (incf reads)
                (values (octets) nil))
              :write-function
              (lambda (octets &key stream-id end-stream-p)
                (declare (ignore stream-id end-stream-p))
                (length octets)))))
      (websocket-http2-3-connection-feed
       connection
       (concatenate
        '(vector (unsigned-byte 8))
        (websocket-http2-connection-preface)
        (encode-websocket-http2-connect-settings)
        (encode-websocket-http2-headers-frames
         (make-websocket-http2-connect-headers "example.test")
         1)))
      (let ((stream (websocket-http2-3-connection-stream connection 1)))
        (signals websocket-transport-error
          (websocket-kit::%websocket-http2-3-connection-stream-read stream))
        (expect reads :to-equalp 1))))

  (it "negotiates the per-connection HPACK table size"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http2-connection
              :role :client
              :write-function (%connection-test-writer writes)))
           (encoder
             (websocket-http2-3-connection-hpack-encoder-context connection))
           (decoder
             (websocket-http2-3-connection-hpack-decoder-context connection)))
      (expect (websocket-http2-hpack-context-p encoder)
              :to-equalp
              t)
      (expect (websocket-http2-hpack-context-p decoder)
              :to-equalp
              t)
      (websocket-http2-3-connection-start connection)
      (expect
       (cdr (assoc 1
                   (websocket-kit::%websocket-http2-3-connection-local-http2-settings
                    connection)))
       :to-equalp
       +websocket-http2-default-hpack-table-size+)
      (websocket-http2-3-connection-feed
       connection
       (websocket-kit::%websocket-http2-3-connection-encode-settings
        (list (cons 1 0))))
      (expect (websocket-http2-hpack-context-maximum-size encoder)
              :to-equalp
              0)
      (expect (websocket-http2-hpack-context-max-size encoder)
              :to-equalp
              0)
      (expect (websocket-http2-hpack-context-maximum-size decoder)
              :to-equalp
              +websocket-http2-default-hpack-table-size+)))

  (it "rejects an HTTP/2 SETTINGS ACK that is not pending"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http2-connection
              :role :client
              :write-function (%connection-test-writer writes)))
           (ack
             (websocket-kit::%websocket-http2-3-connection-encode-settings
              nil :ack-p t)))
      (websocket-http2-3-connection-start connection)
      (websocket-http2-3-connection-feed
       connection (encode-websocket-http2-connect-settings))
      (websocket-http2-3-connection-feed connection ack)
      (signals websocket-http-error
        (websocket-http2-3-connection-feed connection ack))))

  (it "stops opening HTTP/2 streams after peer GOAWAY"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http2-connection
              :role :client
              :write-function (%connection-test-writer writes)))
           (goaway
             (websocket-kit::%websocket-http2-3-encode-http2-frame
              :goaway 0 0
              (websocket-kit::%websocket-http2-3-append-octets
               (list (websocket-kit::%websocket-http2-3-connection-u32 0)
                     (websocket-kit::%websocket-http2-3-connection-u32 0))))))
      (websocket-http2-3-connection-start connection)
      (websocket-http2-3-connection-feed
       connection (encode-websocket-http2-connect-settings))
      (websocket-http2-3-connection-feed connection goaway)
      (signals websocket-http-error
        (websocket-http2-3-connection-open-stream
         connection :authority "example.test"))))

  (it "bounds queued HTTP/2 DATA until the application consumes it"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http2-connection
              :role :server
              :max-data-bytes 3
              :max-data-frames 1
              :write-function (%connection-test-writer writes)))
           (wire
             (concatenate
              '(vector (unsigned-byte 8))
              (websocket-http2-connection-preface)
              (encode-websocket-http2-connect-settings)
              (encode-websocket-http2-headers-frames
               (make-websocket-http2-connect-headers "example.test")
               1))))
      (websocket-http2-3-connection-feed connection wire)
      (let ((stream (websocket-http2-3-connection-stream connection 1)))
        (expect (websocket-http2-3-stream-p stream) :to-equalp t)
        (websocket-http2-3-connection-feed
         connection (encode-websocket-http2-data-frames (octets 1 2 3) 1))
        (signals websocket-size-limit-exceeded
          (websocket-http2-3-connection-feed
           connection (encode-websocket-http2-data-frames (octets 4) 1)))
        (expect
         (websocket-kit::websocket-http2-3-stream-unconsumed-receive-bytes
          stream)
         :to-equalp
         3)
        (multiple-value-bind (payload endp)
            (websocket-kit::%websocket-http2-3-connection-stream-read stream)
          (expect (length payload) :to-equalp 12)
          (expect endp :to-equalp nil))
        (let ((writes-before (length (car writes))))
          (websocket-http2-3-connection-consume connection stream 3)
          (let ((new-writes
                  (subseq (car writes)
                          0
                          (- (length (car writes)) writes-before))))
            (expect (length new-writes) :to-equalp 2)
            (expect
             (mapcar
              (lambda (entry)
                (websocket-kit::%websocket-http2-3-connection-http2-frame-stream-id
                 (first entry)))
              new-writes)
             :to-equalp
             '(1 0))
            (dolist (entry new-writes)
              (let ((frame (first entry)))
                (expect
                 (websocket-kit::%websocket-http2-3-connection-http2-frame-type
                  frame)
                 :to-equalp
                 8)
                (expect
                 (websocket-kit::%websocket-http2-3-connection-frame-payload
                  frame)
                 :to-equalp
                 (octets 0 0 0 3))))))
        (expect
         (websocket-kit::websocket-http2-3-stream-unconsumed-receive-bytes
          stream)
         :to-equalp
         0)
        (websocket-http2-3-connection-feed
         connection (encode-websocket-http2-data-frames (octets 4) 1)
         )
        (expect
         (websocket-kit::websocket-http2-3-stream-unconsumed-receive-bytes
          stream)
         :to-equalp
         1))))

  (it "keeps HTTP/3 control and bidirectional streams separate"
    (let* ((writes (list nil))
          (connection
            (make-websocket-http3-connection
             :role :client
             :write-function (%connection-test-writer writes))))
      (websocket-http2-3-connection-start connection)
      (expect (websocket-http2-3-connection-h3-control-stream-id connection)
              :to-equalp
              2)
      (signals websocket-http-error
        (websocket-http3-connection-feed-stream
         connection 2 (octets)))
      (websocket-http3-connection-feed-stream
       connection 3 (encode-websocket-http3-connect-settings))
      (let ((stream
              (websocket-http3-connection-open-stream
               connection :authority "example.test")))
        (expect (websocket-http2-3-stream-p stream) :to-equalp t)
        (expect (websocket-http2-3-stream-id stream) :to-equalp 0)
        (expect (some (lambda (write) (= (second write) 0)) (car writes))
                :to-equalp
                t))))

  (it "ignores unknown HTTP/3 unidirectional streams"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http3-connection
              :role :client
              :write-function (%connection-test-writer writes))))
      (expect
       (eq
        (websocket-http3-connection-feed-stream
         connection 14 (octets 1 2 3) :fin-p t)
        connection)
       :to-equalp t)))

  (it "forwards deadlines to HTTP/2 connection reads"
    (let* ((seen-deadline nil)
           (connection
             (make-websocket-http2-connection
              :read-function
              (lambda (&key deadline)
                (setf seen-deadline deadline)
                (values (encode-websocket-http2-connect-settings) nil))
              :write-function
              (lambda (octets &key stream-id end-stream-p)
                (declare (ignore stream-id end-stream-p))
                (length octets)))))
      (websocket-http2-3-connection-pump
       connection
       :timeout 2
       :clock-function (lambda () 5))
      (expect seen-deadline :to-equalp 7)))

  (it "accepts explicit HTTP/3 transport stream identifiers"
    (let* ((writes (list nil))
           (connection
             (make-websocket-http3-connection
              :role :client
              :h3-control-stream-id 14
              :h3-peer-control-stream-id 19
              :h3-qpack-encoder-stream-id 22
              :h3-qpack-decoder-stream-id 26
              :h3-qpack-peer-encoder-stream-id 27
              :h3-qpack-peer-decoder-stream-id 31
              :write-function (%connection-test-writer writes))))
      (expect (websocket-http2-3-connection-h3-control-stream-id connection)
              :to-equalp
              14)
      (expect
       (websocket-http2-3-connection-h3-peer-control-stream-id connection)
       :to-equalp
       19)
      (websocket-http2-3-connection-start connection)
      (signals websocket-http-error
        (websocket-http3-connection-feed-stream
         connection 14 (octets)))
      (websocket-http3-connection-feed-stream
       connection 19 (encode-websocket-http3-connect-settings))
      (let ((stream
              (websocket-http3-connection-open-stream
               connection :authority "example.test")))
        (expect (websocket-http2-3-stream-id stream) :to-equalp 0))))

  (it "rejects invalid HTTP/3 transport stream identifiers"
    (signals websocket-http-error
      (make-websocket-http3-connection
       :role :client
       :h3-control-stream-id 15
       :write-function
       (lambda (octets &key stream-id end-stream-p)
         (declare (ignore octets stream-id end-stream-p))
         0)))
    (signals websocket-http-error
      (make-websocket-http3-connection
       :role :client
       :h3-control-stream-id 14
       :h3-peer-control-stream-id 14
       :write-function
       (lambda (octets &key stream-id end-stream-p)
         (declare (ignore octets stream-id end-stream-p))
         0))))

  (it "stops opening HTTP/3 streams after peer GOAWAY"
    (let ((connection
            (make-websocket-http3-connection
             :role :client
             :write-function
             (lambda (octets &key stream-id end-stream-p)
               (declare (ignore stream-id end-stream-p))
               (length octets)))))
      (websocket-http2-3-connection-start connection)
      (websocket-http3-connection-feed-stream
       connection 3 (encode-websocket-http3-connect-settings))
      (websocket-http3-connection-feed-stream
       connection 3
       (websocket-kit::%websocket-http2-3-encode-http3-frame
        http-kit/http3:+http3-goaway-type+
        (http-kit/http3:http3-varint-encode 0)))
      (signals websocket-http-error
        (websocket-http3-connection-open-stream
         connection :authority "example.test"))))

  (it "validates HTTP/3 GOAWAY stream identifiers by role"
    (let ((connection
            (make-websocket-http3-connection
             :role :client
             :write-function
             (lambda (octets &key stream-id end-stream-p)
               (declare (ignore stream-id end-stream-p))
               (length octets)))))
      (websocket-http2-3-connection-start connection)
      (websocket-http3-connection-feed-stream
       connection 3 (encode-websocket-http3-connect-settings))
      (signals websocket-http-error
        (websocket-http3-connection-feed-stream
         connection 3
         (websocket-kit::%websocket-http2-3-encode-http3-frame
          http-kit/http3:+http3-goaway-type+
          (http-kit/http3:http3-varint-encode 1)))))
    (let ((connection
            (make-websocket-http3-connection
             :role :server
             :write-function
             (lambda (octets &key stream-id end-stream-p)
               (declare (ignore stream-id end-stream-p))
               (length octets)))))
      (signals websocket-http-error
        (websocket-http2-3-connection-close
         connection :last-stream-id 1))))

  (it "writes one GOAWAY and notifies the HTTP/2 close callback once"
    (let* ((writes (list nil))
           (close-calls 0)
           (connection
             (make-websocket-http2-connection
              :role :client
              :write-function (%connection-test-writer writes)
              :close-function
              (lambda (&key abort-p)
                (declare (ignore abort-p))
                (incf close-calls)))))
      (websocket-http2-3-connection-close
       connection :code 7 :last-stream-id 5)
      (websocket-http2-3-connection-close
       connection :code 9 :last-stream-id 3)
      (let ((entry (first (car writes))))
        (expect (second entry) :to-equalp 0)
        (expect
         (websocket-kit::%websocket-http2-3-connection-http2-frame-type
          (first entry))
         :to-equalp
         7)
        (expect
         (subseq (first entry) 9)
         :to-equalp
         (concatenate
          '(vector (unsigned-byte 8))
          (websocket-kit::%websocket-http2-3-connection-u32 5)
          (websocket-kit::%websocket-http2-3-connection-u32 7))))
      (expect close-calls :to-equalp 1)
      (expect (websocket-http2-3-connection-closed-p connection)
              :to-equalp
              t)))

  (it "writes one HTTP/3 GOAWAY and notifies the close callback once"
    (let* ((writes (list nil))
           (close-calls 0)
           (connection
             (make-websocket-http3-connection
              :role :client
              :write-function (%connection-test-writer writes)
              :close-function
              (lambda (&key abort-p)
                (declare (ignore abort-p))
                (incf close-calls)))))
      (websocket-http2-3-connection-close
       connection :code 7 :last-stream-id 4)
      (websocket-http2-3-connection-close
       connection :code 9 :last-stream-id 2)
      (let ((entry (first (car writes))))
        (expect (second entry)
                :to-equalp
                (websocket-http2-3-connection-h3-control-stream-id
                 connection))
        (multiple-value-bind (type payload end)
            (websocket-kit::%websocket-http2-3-decode-http3-frame
             (first entry))
          (declare (ignore end))
          (expect type :to-equalp http-kit/http3:+http3-goaway-type+)
          (expect payload :to-equalp (http-kit/http3:http3-varint-encode 4))))
      (expect close-calls :to-equalp 1)
      (expect (websocket-http2-3-connection-closed-p connection)
              :to-equalp
              t)))

  (it "rejects a closed HTTP/3 control stream"
    (let ((connection
            (make-websocket-http3-connection
             :role :client
             :write-function
             (lambda (octets &key stream-id end-stream-p)
               (declare (ignore stream-id end-stream-p))
               (length octets)))))
      (signals websocket-http-error
        (websocket-http3-connection-feed-stream
         connection 3 (octets) :fin-p t)))))
