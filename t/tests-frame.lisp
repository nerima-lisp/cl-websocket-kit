(in-package #:websocket-kit/test)

(describe "websocket frames"
  (it "round trips an unmasked text frame"
    (let* ((wire (serialize-websocket-frame
                  (make-websocket-frame :opcode 1 :payload (octets 72 105))))
           (parsed (parse-websocket-frame wire)))
      (expect (websocket-frame-payload parsed) :to-equalp (octets 72 105))
      (expect (websocket-frame-opcode parsed) :to-equalp 1)
      (expect (and (websocket-frame-fin-p parsed) t) :to-equalp t)
      ;; Two header octets plus the payload; no extended length, no key.
      (expect (length wire) :to-equalp 4)))

  (it "unmasks a masked payload on parse"
    (let* ((wire (serialize-websocket-frame
                  (make-websocket-frame :opcode 2
                                        :payload (octets 1 2 3)
                                        :mask-p t
                                        :masking-key (octets 1 2 3 4))))
           (parsed (parse-websocket-frame wire)))
      (expect (websocket-frame-payload parsed) :to-equalp (octets 1 2 3))
      (expect (and (websocket-frame-mask-p parsed) t) :to-equalp t)
      ;; Two header octets, the four-octet key, then the payload.
      (expect (length wire) :to-equalp 9)))

  ;; A payload above 125 octets moves to the sixteen-bit extended length form.
  (it "round trips a payload that needs the extended length form"
    (let ((payload (make-array 200 :element-type '(unsigned-byte 8)
                                   :initial-element 7)))
      (expect (websocket-frame-payload
               (parse-websocket-frame
                (serialize-websocket-frame
                 (make-websocket-frame :opcode 2 :payload payload))))
              :to-equalp payload)))

  (it "writes ping and pong control frames"
    (multiple-value-bind (ignored ping-wire)
        (with-binary-two-way
         (octets)
         (lambda (stream)
           (websocket-ping stream :payload (octets 1 2 3))))
      (declare (ignore ignored))
      (let ((frame (parse-websocket-frame ping-wire)))
        (expect (websocket-frame-fin-p frame) :to-equalp t)
        (expect (websocket-frame-opcode frame) :to-equalp 9)
        (expect (websocket-frame-payload frame) :to-equalp (octets 1 2 3))))
    (multiple-value-bind (ignored pong-wire)
        (with-binary-two-way
         (octets)
         (lambda (stream)
           (websocket-pong stream :payload (octets 4 5 6))))
      (declare (ignore ignored))
      (let ((frame (parse-websocket-frame pong-wire)))
        (expect (websocket-frame-fin-p frame) :to-equalp t)
        (expect (websocket-frame-opcode frame) :to-equalp 10)
        (expect (websocket-frame-payload frame) :to-equalp (octets 4 5 6)))))

  (it "rejects non-minimal and high-bit extended payload lengths"
    (dolist (wire
              (list (octets #x82 #x7e 0 1 65)
                    (octets #x82 #x7f 0 0 0 0 0 0 0 1 65)
                    (octets #x82 #x7f #x80 0 0 0 0 0 0 0)))
      (signals websocket-protocol-error
        (parse-websocket-frame wire))))

  ;; Masking keys are never generated implicitly, so an ill-sized one is a
  ;; caller error rather than something to paper over.
  (it "rejects a masking key that is not four octets"
    (signals websocket-error
      (make-websocket-frame :opcode 1 :payload (octets 1)
                            :mask-p t :masking-key (octets 1 2))))

  (it "rejects a masking key on an unmasked frame"
    (signals websocket-error
      (make-websocket-frame :opcode 1 :payload (octets 1)
                            :masking-key (octets 1 2 3 4))))

  (it "rejects malformed control headers before reading their payload"
    (signals websocket-error
      (parse-websocket-frame (octets #x88 #x7e)))
    (signals websocket-error
      (parse-websocket-frame (octets #x09 0)))
    (signals websocket-error
      (parse-websocket-frame (octets #x8b 0))))

  (it "reports EOF before a complete frame as transport failure"
    (dolist (wire (list (octets)
                        (octets #x81)
                        (octets #x81 #x7e 0)))
      (signals websocket-transport-error
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-frame stream))))))

  (it "does not write a close frame after transport EOF"
    (multiple-value-bind (ignored output)
        (with-binary-two-way
         (octets)
         (lambda (stream)
           (handler-case
               (serve-websocket-session
                stream
                (lambda (stream payload opcode)
                  (declare (ignore stream payload opcode)))
                :close-stream nil)
             (websocket-transport-error (condition)
              (declare (ignore condition))))))
      (declare (ignore ignored))
      (expect output :to-equalp (octets))))

  (it "rejects extension RSV bits unless explicitly enabled"
    (signals websocket-error
      (parse-websocket-frame (octets #xc1 0))))

  (it "preserves negotiated extension RSV bits when explicitly enabled"
    (let* ((wire (octets #xc1 #x01 #x41))
           (frame (parse-websocket-frame
                   wire :allowed-reserved-bits #x40)))
      (expect (websocket-frame-reserved-bits frame) :to-equalp #x40)
      (expect (serialize-websocket-frame frame) :to-equalp wire))))

(describe "close payloads"
  (it "accepts a registered close code"
    (expect (and (websocket-valid-close-code-p 1000) t) :to-equalp t))

  (it "accepts close codes in the registered and private-use ranges"
    (expect (and (websocket-valid-close-code-p 1012) t) :to-equalp t)
    (expect (and (websocket-valid-close-code-p 4000) t) :to-equalp t))

  (it "rejects unassigned protocol close codes"
    (expect (and (websocket-valid-close-code-p 1016) t) :to-equalp nil)
    (expect (and (websocket-valid-close-code-p 2999) t) :to-equalp nil))

  ;; 1005 and 1006 are reserved for local use and must never reach the wire.
  (it "rejects a close code reserved for local use"
    (expect (and (websocket-valid-close-code-p 1005) t) :to-equalp nil))

  (it "round trips a code and reason"
    (let ((payload (make-websocket-close-payload :code 1000 :reason "bye")))
      (expect (nth-value 0 (parse-websocket-close-payload payload))
              :to-equalp 1000)
      (expect (nth-value 1 (parse-websocket-close-payload payload))
              :to-equalp "bye")))

  (it "reports invalid peer UTF-8 as invalid data"
    (signals websocket-invalid-data
      (parse-websocket-close-payload
       (octets 3 232 #xe0 #x80))))

  (it "validates raw close payloads before writing them"
    (signals websocket-invalid-data
      (websocket-close nil :payload (octets 3 232 #xe0 #x80))))

  (it "rejects a close reason that cannot fit before encoding it"
    (signals websocket-size-limit-exceeded
      (make-websocket-close-payload
       :reason (make-string 124 :initial-element #\a)))))

(describe "websocket messages"
  (it "assembles a masked fragmented UTF-8 text message"
    (let* ((first (serialize-websocket-frame
                   (make-websocket-frame :fin-p nil
                                         :opcode 1
                                         :payload (octets 104 195)
                                         :mask-p t
                                         :masking-key (octets 1 2 3 4))))
           (second (serialize-websocket-frame
                    (make-websocket-frame :fin-p t
                                          :opcode 0
                                          :payload (octets 169 33)
                                          :mask-p t
                                          :masking-key (octets 5 6 7 8)))))
      (with-binary-input
       (concatenate '(vector (unsigned-byte 8)) first second)
       (lambda (stream)
         (multiple-value-bind (payload opcode)
             (read-websocket-message stream
                                     :require-mask-p t
                                     :allow-unmasked-p nil)
           (expect payload :to-equalp (octets 104 195 169 33))
           (expect opcode :to-equalp 1))))))

  (it "rejects invalid UTF-8 in a masked text message"
    (let ((wire (serialize-websocket-frame
                 (make-websocket-frame :opcode 1
                                       :payload (octets #xe0 #x80)
                                       :mask-p t
                                       :masking-key (octets 1 2 3 4)))))
      (signals websocket-invalid-data
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-message stream
                                   :require-mask-p t
                                   :allow-unmasked-p nil))))))

  (it "rejects invalid UTF-8 in an outbound text message"
    (signals websocket-error
      (write-websocket-message
       nil (octets #xe0 #x80) :opcode 1)))

  (it "passes negotiated RSV permissions through message reading"
    (let ((wire (serialize-websocket-frame
                 (make-websocket-frame :opcode 1
                                       :reserved-bits #x40
                                       :payload (octets 65)))))
      (with-binary-input
       wire
       (lambda (stream)
         (multiple-value-bind (payload opcode)
             (read-websocket-message stream :allowed-reserved-bits #x40)
           (expect payload :to-equalp (octets 65))
           (expect opcode :to-equalp 1))))))

  (it "runs frame validators before payload decoding"
    (let ((validator-called-p nil)
          (decoder-saw-validator-p nil)
          (wire (serialize-websocket-frame
                 (make-websocket-frame :opcode 1 :payload (octets 65)))))
      (with-binary-input
       wire
       (lambda (stream)
         (multiple-value-bind (payload opcode)
             (read-websocket-message
              stream
              :frame-validator
              (lambda (frame)
                (declare (ignore frame))
                (setf validator-called-p t))
              :payload-decoder
              (lambda (payload frame)
                (declare (ignore frame))
                (setf decoder-saw-validator-p validator-called-p)
                payload))
           (expect payload :to-equalp (octets 65))
           (expect opcode :to-equalp 1)
           (expect validator-called-p :to-be t)
           (expect decoder-saw-validator-p :to-be t))))))

  (it "decodes extension payloads before assembling a message"
    (let* ((first (serialize-websocket-frame
                   (make-websocket-frame :fin-p nil
                                         :opcode 1
                                         :reserved-bits #x40
                                         :payload (octets 65))))
           (second (serialize-websocket-frame
                    (make-websocket-frame :fin-p t
                                          :opcode 0
                                          :payload (octets 66))))
           (seen-reserved-bits nil)
           (wire (concatenate '(vector (unsigned-byte 8)) first second)))
      (with-binary-input
       wire
       (lambda (stream)
         (multiple-value-bind (payload opcode)
             (read-websocket-message
              stream
              :allowed-reserved-bits #x40
              :payload-decoder
              (lambda (payload frame)
                (setf seen-reserved-bits
                      (append seen-reserved-bits
                              (list (websocket-frame-reserved-bits frame))))
                (concatenate '(vector (unsigned-byte 8))
                             payload
                             (octets 33))))
           (expect payload :to-equalp (octets 65 33 66 33))
           (expect opcode :to-equalp 1)
           (expect seen-reserved-bits :to-equalp (list #x40 0)))))))

  (it "rejects decoded payloads that exceed the message limit"
    (let ((wire (serialize-websocket-frame
                 (make-websocket-frame :opcode 2 :payload (octets 1)))))
      (signals websocket-size-limit-exceeded
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-message
            stream
            :max-message-bytes 2
            :payload-decoder
            (lambda (payload frame)
              (declare (ignore frame))
              (concatenate '(vector (unsigned-byte 8))
                           payload
                           (octets 2 3)))))))))

  (it "encodes a message before fragmentation and marks only its first frame"
    (multiple-value-bind (ignored output)
        (with-binary-two-way
         (octets)
         (lambda (stream)
           (write-websocket-message
            stream "AB"
            :opcode 1
            :max-frame-payload-bytes 1
            :reserved-bits #x40
            :payload-encoder
            (lambda (payload opcode)
              (declare (ignore opcode))
              (concatenate '(vector (unsigned-byte 8))
                           payload
                           (octets 33)))
            :finish-output-p nil)))
      (declare (ignore ignored))
      (multiple-value-bind (first first-size)
          (parse-websocket-frame output :allowed-reserved-bits #x40)
        (multiple-value-bind (second second-size)
            (parse-websocket-frame
             (subseq output first-size)
             :allowed-reserved-bits #x40)
          (multiple-value-bind (third third-size)
              (parse-websocket-frame
               (subseq output (+ first-size second-size))
               :allowed-reserved-bits #x40)
            (expect (+ first-size second-size third-size)
                    :to-equalp
                    (length output))
            (expect (websocket-frame-fin-p first) :to-be nil)
            (expect (websocket-frame-opcode first) :to-equalp 1)
            (expect (websocket-frame-reserved-bits first) :to-equalp #x40)
            (expect (websocket-frame-payload first) :to-equalp (octets 65))
            (expect (websocket-frame-fin-p second) :to-be nil)
            (expect (websocket-frame-opcode second) :to-equalp 0)
            (expect (websocket-frame-reserved-bits second) :to-equalp 0)
            (expect (websocket-frame-payload second) :to-equalp (octets 66))
            (expect (websocket-frame-fin-p third) :to-be t)
            (expect (websocket-frame-opcode third) :to-equalp 0)
            (expect (websocket-frame-reserved-bits third) :to-equalp 0)
            (expect (websocket-frame-payload third) :to-equalp (octets 33)))))))

  (it "limits the encoded outbound message before writing frames"
    (signals websocket-size-limit-exceeded
      (write-websocket-message
       nil "AB"
       :opcode 1
       :max-message-bytes 2
       :payload-encoder
       (lambda (payload opcode)
         (declare (ignore opcode))
         (concatenate '(vector (unsigned-byte 8)) payload (octets 33))))))

  (it "validates a close frame before delivering its control callback"
    (let ((wire (serialize-websocket-frame
                 (make-websocket-frame :opcode 8
                                       :payload (octets 3 232 #xe0 #x80)
                                       :mask-p t
                                       :masking-key (octets 1 2 3 4)))))
      (signals websocket-invalid-data
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-message
            stream :require-mask-p t :allow-unmasked-p nil
            :on-control (lambda (frame)
                          (declare (ignore frame))))))))))

  (it "stops after a close even when a control callback is supplied"
    (let* ((close-wire
             (serialize-websocket-frame
              (make-websocket-frame
               :opcode 8
               :payload (make-websocket-close-payload :code 1000))))
           (data-wire
             (serialize-websocket-frame
              (make-websocket-frame :opcode 1 :payload (octets 65))))
           (calls 0))
      (with-binary-input
       (concatenate '(vector (unsigned-byte 8)) close-wire data-wire)
       (lambda (stream)
         (multiple-value-bind (payload opcode)
             (read-websocket-message
              stream
              :on-control (lambda (frame)
                            (declare (ignore frame))
                            (incf calls)))
           (expect payload :to-equalp
                   (make-websocket-close-payload :code 1000))
           (expect opcode :to-equalp :close)
           (expect calls :to-equalp 1))))))

  (it "limits the number of data fragments in a message"
    (let ((wire (concatenate
                 '(vector (unsigned-byte 8))
                 (serialize-websocket-frame
                  (make-websocket-frame :fin-p nil
                                        :opcode 1
                                        :payload (octets 65)))
                 (serialize-websocket-frame
                  (make-websocket-frame :fin-p t
                                        :opcode 0
                                        :payload (octets 66))))))
      (signals websocket-size-limit-exceeded
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-message stream :max-fragments 1)))))

  (it "limits control frames consumed while reading a message"
    (let ((wire (concatenate
                 '(vector (unsigned-byte 8))
                 (serialize-websocket-frame
                  (make-websocket-frame :opcode 9 :payload (octets 1)))
                 (serialize-websocket-frame
                  (make-websocket-frame :opcode 10 :payload (octets 2)))
                 (serialize-websocket-frame
                  (make-websocket-frame :opcode 1 :payload (octets 65))))))
      (signals websocket-size-limit-exceeded
        (with-binary-input
         wire
         (lambda (stream)
           (read-websocket-message stream :max-control-frames 1))))))

  (it "rejects an expired message deadline before reading"
    (signals websocket-timeout
      (with-binary-input
       (octets 129 1 65)
       (lambda (stream)
         (read-websocket-message
          stream
          :deadline 10.0
          :clock-function (lambda () 10.0)))))))
