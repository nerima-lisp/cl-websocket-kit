(in-package #:websocket-kit/test)

(describe "permessage-deflate codec"
  (it "round trips empty and stored-block payloads across the 65535 boundary"
    (let* ((empty (octets))
           (boundary (make-array 65536
                                 :element-type '(unsigned-byte 8)
                                 :initial-element 97)))
      (expect (websocket-permessage-deflate-decompress
               (websocket-permessage-deflate-compress empty))
              :to-equalp empty)
      (expect (websocket-permessage-deflate-decompress
               (websocket-permessage-deflate-compress boundary))
              :to-equalp boundary)))

  (it "decodes fixed and dynamic raw DEFLATE streams"
    (let* ((fixed-wire
             (octets 203 72 205 201 201 87 40 79 77 42 206 79 206 78 45 1 0))
           (fixed-expected
             (octets 104 101 108 108 111 32 119 101 98 115 111 99 107 101 116))
           (dynamic-wire
             (octets 237 196 49 1 0 0 4 0 176 76 72 132 254 29 132 240
                     110 199 122 54 178 218 182 109 219 182 109 219 182 109
                     63 62))
           (dynamic-expected (make-array 6000
                                         :element-type '(unsigned-byte 8)))
           (pattern (octets 97 98 99 49 50 51)))
      (loop for index below (length dynamic-expected)
            do (setf (aref dynamic-expected index)
                     (aref pattern (mod index (length pattern)))))
      (expect (websocket-permessage-deflate-decompress fixed-wire)
              :to-equalp fixed-expected)
      (expect (websocket-permessage-deflate-decompress dynamic-wire)
              :to-equalp dynamic-expected)))

  (it "enforces the decompressed size limit"
    (signals websocket-size-limit-exceeded
      (websocket-permessage-deflate-decompress
       (websocket-permessage-deflate-compress (octets 1 2 3))
       :max-output-bytes 2)))

  (it "rejects malformed raw DEFLATE data"
    (signals websocket-protocol-error
      (websocket-permessage-deflate-decompress (octets 0))))

  (it "decodes a fragmented compressed message and resets its context"
    (let* ((message (octets 104 101 108 108 111 32 119 111 114 108 100))
           (wire (websocket-permessage-deflate-compress message))
           (split (max 1 (floor (length wire) 2)))
           (first-frame
             (make-websocket-frame
              :fin-p nil
              :opcode 1
              :reserved-bits +websocket-permessage-deflate-rsv1+
              :payload (subseq wire 0 split)))
           (second-frame
             (make-websocket-frame
              :fin-p t
              :opcode 0
              :payload (subseq wire split)))
           (decoder (make-websocket-permessage-deflate-decoder))
           (validator
             (make-websocket-permessage-deflate-frame-validator
              :payload-decoder decoder)))
      (expect (eq (funcall validator first-frame) first-frame) :to-be t)
      (expect (eq (funcall validator second-frame) second-frame) :to-be t)
      (expect (funcall decoder (websocket-frame-payload first-frame)
                       first-frame)
              :to-equalp (octets))
      (expect (funcall decoder (websocket-frame-payload second-frame)
                       second-frame)
              :to-equalp message)
      (expect (funcall decoder wire
              (make-websocket-frame
                       :fin-p t
                       :opcode 1
                       :reserved-bits +websocket-permessage-deflate-rsv1+))
              :to-equalp message))))

  (it "requires a decoder for RSV1 and rejects RSV1 on continuations"
    (let ((compressed-frame
            (make-websocket-frame
             :opcode 1
             :reserved-bits +websocket-permessage-deflate-rsv1+))
          (continuation
            (make-websocket-frame :opcode 0 :reserved-bits
                                  +websocket-permessage-deflate-rsv1+)))
      (signals websocket-protocol-error
        (funcall (make-websocket-permessage-deflate-frame-validator)
                 compressed-frame))
      (let ((validator
              (make-websocket-permessage-deflate-frame-validator
               :payload-decoder (constantly (octets)))))
        (signals websocket-protocol-error
          (funcall validator continuation))))

  (it "exposes a no-context-takeover codec bundle and extension offer"
    (let ((codec (make-websocket-permessage-deflate)))
      (expect (websocket-permessage-deflate-p codec) :to-be t)
      (expect (not (null (search "client_no_context_takeover"
                                 (websocket-permessage-deflate-extension))))
              :to-be t)
      (expect (not (null (search "server_no_context_takeover"
                                 (websocket-permessage-deflate-extension))))
              :to-be t)
      (let* ((message (octets 65 66 67))
             (wire (funcall (websocket-permessage-deflate-encoder codec)
                            message 1))
             (frame (make-websocket-frame
                     :opcode 1
                     :reserved-bits +websocket-permessage-deflate-rsv1+
                     :payload wire)))
        (expect (funcall (websocket-permessage-deflate-decoder codec)
                         wire frame)
                :to-equalp message)))))
