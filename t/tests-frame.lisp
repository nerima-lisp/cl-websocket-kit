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

  ;; Masking keys are never generated implicitly, so an ill-sized one is a
  ;; caller error rather than something to paper over.
  (it "rejects a masking key that is not four octets"
    (signals websocket-error
      (make-websocket-frame :opcode 1 :payload (octets 1)
                            :mask-p t :masking-key (octets 1 2))))

  (it "rejects a masking key on an unmasked frame"
    (signals websocket-error
      (make-websocket-frame :opcode 1 :payload (octets 1)
                            :masking-key (octets 1 2 3 4)))))

(describe "close payloads"
  (it "accepts a registered close code"
    (expect (and (websocket-valid-close-code-p 1000) t) :to-equalp t))

  ;; 1005 and 1006 are reserved for local use and must never reach the wire.
  (it "rejects a close code reserved for local use"
    (expect (and (websocket-valid-close-code-p 1005) t) :to-equalp nil))

  (it "round trips a code and reason"
    (let ((payload (make-websocket-close-payload :code 1000 :reason "bye")))
      (expect (nth-value 0 (parse-websocket-close-payload payload))
              :to-equalp 1000)
      (expect (nth-value 1 (parse-websocket-close-payload payload))
              :to-equalp "bye"))))
