(in-package #:websocket-kit)

(defconstant +websocket-permessage-deflate-rsv1+ #x40)

(defstruct (%websocket-pmd-bit-reader
            (:constructor %make-websocket-pmd-bit-reader
                (octets)))
  octets
  (position 0)
  (buffer 0)
  (bits 0))

(defun %websocket-pmd-output ()
  (make-array 0
              :element-type '(unsigned-byte 8)
              :adjustable t
              :fill-pointer 0))

(defun %websocket-pmd-push (output octet)
  (vector-push-extend (logand octet #xff) output)
  output)

(defun %websocket-pmd-append (output octets)
  (loop for octet across octets
        do (%websocket-pmd-push output octet))
  output)

(defun %websocket-pmd-read-bits (reader count)
  (when (or (< count 0) (> count 24))
    (%websocket-protocol-error
     "The permessage-deflate bit reader received an invalid width."
     count))
  (loop while (< (%websocket-pmd-bit-reader-bits reader) count)
        do (let ((position (%websocket-pmd-bit-reader-position reader))
                 (octets (%websocket-pmd-bit-reader-octets reader)))
             (when (>= position (length octets))
               (%websocket-protocol-error
                "A permessage-deflate stream ended before its final block."))
             (setf (%websocket-pmd-bit-reader-buffer reader)
                   (logior (%websocket-pmd-bit-reader-buffer reader)
                           (ash (aref octets position)
                                (%websocket-pmd-bit-reader-bits reader)))
                   (%websocket-pmd-bit-reader-position reader) (1+ position)
                   (%websocket-pmd-bit-reader-bits reader)
                   (+ (%websocket-pmd-bit-reader-bits reader) 8))))
  (let* ((mask (if (zerop count) 0 (1- (ash 1 count))))
         (value (logand (%websocket-pmd-bit-reader-buffer reader) mask)))
    (setf (%websocket-pmd-bit-reader-buffer reader)
          (ash (%websocket-pmd-bit-reader-buffer reader) (- count))
          (%websocket-pmd-bit-reader-bits reader)
          (- (%websocket-pmd-bit-reader-bits reader) count))
    value))

(defun %websocket-pmd-align-byte (reader)
  (setf (%websocket-pmd-bit-reader-buffer reader) 0
        (%websocket-pmd-bit-reader-bits reader) 0)
  reader)

(defun %websocket-pmd-reverse-bits (value width)
  (loop with result = 0
        for index below width
        do (setf result
                 (logior (ash result 1)
                         (ldb (byte 1 index) value)))
        finally (return result)))

(defun %websocket-pmd-huffman-table (lengths)
  (let* ((max-length (loop for length across lengths maximize length))
         (counts (make-array (1+ max-length) :initial-element 0))
         (next-code (make-array (1+ max-length) :initial-element 0))
         (table (make-hash-table :test #'equal)))
    (loop for length across lengths
          do (when (or (< length 0) (> length 15))
               (%websocket-protocol-error
                "A permessage-deflate Huffman code length is invalid."
                length))
             (unless (zerop length)
               (incf (aref counts length))))
    (loop with code = 0
          for bits from 1 to max-length
          do (setf code
                   (ash (+ code (aref counts (1- bits))) 1)
                   (aref next-code bits) code))
    (loop for symbol below (length lengths)
          for length = (aref lengths symbol)
          unless (zerop length)
            do (let ((code (aref next-code length)))
                 (incf (aref next-code length))
                 (setf (gethash (cons (%websocket-pmd-reverse-bits
                                       code length)
                                      length)
                                table)
                       symbol)))
    (values table max-length)))

(defun %websocket-pmd-decode-symbol (reader table max-length)
  (let ((code 0))
    (loop for length from 1 to max-length
          do (setf code
                   (logior code
                          (ash (%websocket-pmd-read-bits reader 1)
                               (1- length))))
             (multiple-value-bind (symbol found-p)
                 (gethash (cons code length) table)
               (when found-p
                 (return-from %websocket-pmd-decode-symbol symbol))))
    (%websocket-protocol-error
     "A permessage-deflate stream contains an invalid Huffman code.")))

(defun %websocket-pmd-fixed-tables ()
  (let ((literal-lengths (make-array 288 :initial-element 0))
        (distance-lengths (make-array 32 :initial-element 5)))
    (loop for symbol from 0 to 143
          do (setf (aref literal-lengths symbol) 8))
    (loop for symbol from 144 to 255
          do (setf (aref literal-lengths symbol) 9))
    (loop for symbol from 256 to 279
          do (setf (aref literal-lengths symbol) 7))
    (loop for symbol from 280 to 287
          do (setf (aref literal-lengths symbol) 8))
    (multiple-value-bind (literal-table literal-max)
        (%websocket-pmd-huffman-table literal-lengths)
      (multiple-value-bind (distance-table distance-max)
          (%websocket-pmd-huffman-table distance-lengths)
        (values literal-table literal-max distance-table distance-max)))))

(defparameter +websocket-pmd-code-length-order+
  #(16 17 18 0 8 7 9 6 10 5 11 4 12 3 13 2 14 1 15))

(defun %websocket-pmd-dynamic-tables (reader)
  (let* ((literal-count (+ 257 (%websocket-pmd-read-bits reader 5)))
         (distance-count (+ 1 (%websocket-pmd-read-bits reader 5)))
         (code-length-count (+ 4 (%websocket-pmd-read-bits reader 4)))
         (code-length-lengths (make-array 19 :initial-element 0)))
    (loop for index below code-length-count
          do (setf (aref code-length-lengths
                         (aref +websocket-pmd-code-length-order+ index))
                   (%websocket-pmd-read-bits reader 3)))
    (multiple-value-bind (code-length-table code-length-max)
        (%websocket-pmd-huffman-table code-length-lengths)
      (let ((lengths (make-array (+ literal-count distance-count)
                                 :initial-element 0))
            (position 0)
            (previous 0))
        (loop while (< position (length lengths))
              do (let ((symbol
                         (%websocket-pmd-decode-symbol
                          reader code-length-table code-length-max)))
                   (cond
                     ((<= symbol 15)
                      (setf (aref lengths position) symbol
                            previous symbol)
                      (incf position))
                     ((= symbol 16)
                      (when (zerop position)
                        (%websocket-protocol-error
                         "A permessage-deflate repeat code has no previous length."))
                      (let ((repeat (+ 3 (%websocket-pmd-read-bits reader 2))))
                        (when (> (+ position repeat) (length lengths))
                          (%websocket-protocol-error
                           "A permessage-deflate length repeat exceeds its table."))
                        (loop repeat repeat
                              do
                          (setf (aref lengths position) previous)
                          (incf position))))
                     ((= symbol 17)
                      (let ((repeat (+ 3 (%websocket-pmd-read-bits reader 3))))
                        (when (> (+ position repeat) (length lengths))
                          (%websocket-protocol-error
                           "A permessage-deflate zero repeat exceeds its table."))
                        (loop repeat repeat
                              do
                          (setf (aref lengths position) 0
                                previous 0)
                          (incf position))))
                     ((= symbol 18)
                      (let ((repeat (+ 11 (%websocket-pmd-read-bits reader 7))))
                        (when (> (+ position repeat) (length lengths))
                          (%websocket-protocol-error
                           "A permessage-deflate long zero repeat exceeds its table."))
                        (loop repeat repeat
                              do
                          (setf (aref lengths position) 0
                                previous 0)
                          (incf position))))
                     (t
                      (%websocket-protocol-error
                       "A permessage-deflate code-length symbol is invalid."
                       symbol)))))
        (let ((literal-lengths (subseq lengths 0 literal-count))
              (distance-lengths (subseq lengths literal-count)))
          (unless (plusp (aref literal-lengths 256))
            (%websocket-protocol-error
             "A permessage-deflate literal table has no end-of-block symbol."))
          (multiple-value-bind (literal-table literal-max)
              (%websocket-pmd-huffman-table literal-lengths)
            (multiple-value-bind (distance-table distance-max)
                (%websocket-pmd-huffman-table distance-lengths)
              (values literal-table literal-max
                      distance-table distance-max))))))))

(defparameter +websocket-pmd-length-bases+
  #(3 4 5 6 7 8 9 10 11 13 15 17 19 23 27 31
    35 43 51 59 67 83 99 115 131 163 195 227 258))

(defparameter +websocket-pmd-length-extra-bits+
  #(0 0 0 0 0 0 0 0 1 1 1 1 2 2 2 2
    3 3 3 3 4 4 4 4 5 5 5 5 0))

(defparameter +websocket-pmd-distance-bases+
  #(1 2 3 4 5 7 9 13 17 25 33 49 65 97 129 193
    257 385 513 769 1025 1537 2049 3073 4097 6145 8193 12289
    16385 24577))

(defparameter +websocket-pmd-distance-extra-bits+
  #(0 0 0 0 1 1 2 2 3 3 4 4 5 5 6 6
    7 7 8 8 9 9 10 10 11 11 12 12 13 13))

(defun %websocket-pmd-copy-match (output distance length max-output-bytes)
  (when (or (zerop distance) (> distance (fill-pointer output)))
    (%websocket-protocol-error
     "A permessage-deflate distance points before the output stream."
     distance))
  (when (> (+ (fill-pointer output) length) max-output-bytes)
    (%websocket-size-error
     "A permessage-deflate message exceeded its decompressed size limit."
     max-output-bytes (+ (fill-pointer output) length)))
  (let ((source (- (fill-pointer output) distance)))
    (dotimes (index length)
      (vector-push-extend
       (aref output (+ source index))
       output)))
  output)

(defun %websocket-pmd-inflate-huffman-block
    (reader output literal-table literal-max distance-table distance-max
     max-output-bytes)
  (loop
    (let ((symbol (%websocket-pmd-decode-symbol
                   reader literal-table literal-max)))
      (cond
        ((< symbol 256)
         (when (>= (fill-pointer output) max-output-bytes)
           (%websocket-size-error
            "A permessage-deflate message exceeded its decompressed size limit."
            max-output-bytes (1+ (fill-pointer output))))
         (vector-push-extend symbol output))
        ((= symbol 256)
         (return output))
        ((<= 257 symbol 285)
         (let* ((index (- symbol 257))
                (base (aref +websocket-pmd-length-bases+ index))
                (extra (aref +websocket-pmd-length-extra-bits+ index))
                (length (+ base (if (zerop extra)
                                    0
                                    (%websocket-pmd-read-bits reader extra))))
                (distance-symbol
                  (%websocket-pmd-decode-symbol
                   reader distance-table distance-max)))
           (when (>= distance-symbol (length +websocket-pmd-distance-bases+))
             (%websocket-protocol-error
              "A permessage-deflate distance symbol is reserved."
              distance-symbol))
           (let* ((distance-base
                    (aref +websocket-pmd-distance-bases+ distance-symbol))
                  (distance-extra
                    (aref +websocket-pmd-distance-extra-bits+ distance-symbol))
                  (distance
                    (+ distance-base
                       (if (zerop distance-extra)
                           0
                           (%websocket-pmd-read-bits reader distance-extra)))))
             (%websocket-pmd-copy-match
              output distance length max-output-bytes))))
        (t
         (%websocket-protocol-error
          "A permessage-deflate literal/length symbol is invalid."
          symbol))))))

(defun %websocket-pmd-inflate-raw (octets max-output-bytes)
  (%websocket-validate-limit max-output-bytes "MAX-OUTPUT-BYTES")
  (let ((reader (%make-websocket-pmd-bit-reader octets))
        (output (%websocket-pmd-output))
        (final-p nil))
    (loop until final-p
          do (let ((block-final (= 1 (%websocket-pmd-read-bits reader 1)))
                   (block-type (%websocket-pmd-read-bits reader 2)))
               (setf final-p block-final)
               (case block-type
                 (0
                  (%websocket-pmd-align-byte reader)
                  (let* ((length (%websocket-pmd-read-bits reader 16))
                         (inverse (%websocket-pmd-read-bits reader 16)))
                    (unless (= (logxor length inverse) #xffff)
                      (%websocket-protocol-error
                       "A permessage-deflate stored block has an invalid length."))
                    (when (> (+ (fill-pointer output) length)
                             max-output-bytes)
                      (%websocket-size-error
                       "A permessage-deflate message exceeded its decompressed size limit."
                       max-output-bytes (+ (fill-pointer output) length)))
                    (loop repeat length
                          do
                      (vector-push-extend
                       (%websocket-pmd-read-bits reader 8)
                       output))))
                 (1
                  (multiple-value-bind (literal-table literal-max
                                         distance-table distance-max)
                      (%websocket-pmd-fixed-tables)
                    (%websocket-pmd-inflate-huffman-block
                     reader output literal-table literal-max
                     distance-table distance-max max-output-bytes)))
                 (2
                  (multiple-value-bind (literal-table literal-max
                                         distance-table distance-max)
                      (%websocket-pmd-dynamic-tables reader)
                    (%websocket-pmd-inflate-huffman-block
                     reader output literal-table literal-max
                     distance-table distance-max max-output-bytes)))
                 (t
                  (%websocket-protocol-error
                   "A permessage-deflate block uses the reserved block type.")))))
    (subseq output 0 (fill-pointer output))))

(defun websocket-permessage-deflate-compress (octets &optional opcode)
  "Encode OCTETS as a raw DEFLATE message suitable for RFC 7692.

The codec deliberately uses stored blocks and therefore prioritizes bounded,
portable behavior over compression ratio. The returned stream omits the
RFC 7692 trailing empty stored block; it is restored by the decoder. OPCODE
is accepted for direct use as a WebSocket payload encoder."
  (declare (ignore opcode))
  (unless (%websocket-octet-vector-p octets)
    (%websocket-protocol-error
     "A permessage-deflate encoder requires a vector of octets."
     octets))
  (let ((output (%websocket-pmd-output))
        (position 0))
    (loop while (< position (length octets))
          do (let ((chunk (min #xffff (- (length octets) position))))
               (%websocket-pmd-push output 0)
               (%websocket-pmd-push output (ldb (byte 8 0) chunk))
               (%websocket-pmd-push output (ldb (byte 8 8) chunk))
               (%websocket-pmd-push output
                                    (ldb (byte 8 0) (logxor chunk #xffff)))
               (%websocket-pmd-push output
                                    (ldb (byte 8 8) (logxor chunk #xffff)))
               (loop for index below chunk
                     do (%websocket-pmd-push
                         output (aref octets (+ position index))))
               (incf position chunk)))
    (%websocket-pmd-push output 1)
    (%websocket-pmd-push output 0)
    (%websocket-pmd-push output 0)
    (%websocket-pmd-push output #xff)
    (%websocket-pmd-push output #xff)
    (subseq output 0 (- (fill-pointer output) 4))))

(defun websocket-permessage-deflate-decompress
    (octets &optional frame &rest arguments)
  "Decode a raw RFC 7692 DEFLATE message.

FRAME is accepted for the payload-transformer calling convention and is not
otherwise inspected. MAX-OUTPUT-BYTES bounds decompression expansion."
  (let* ((options (if (and frame (keywordp frame))
                      (list* frame arguments)
                      arguments))
         (max-output-bytes
           (getf options :max-output-bytes
                +websocket-default-max-payload-bytes+)))
    (when (oddp (length options))
      (%websocket-protocol-error
       "PERMESSAGE-DEFLATE decoder options must be keyword/value pairs."))
    (loop for (key value) on options by #'cddr
          do (unless (eq key :max-output-bytes)
               (%websocket-protocol-error
                "PERMESSAGE-DEFLATE decoder received an unknown option."
                key)))
    (%websocket-validate-limit max-output-bytes "MAX-OUTPUT-BYTES")
    (unless (%websocket-octet-vector-p octets)
      (%websocket-protocol-error
       "A permessage-deflate decoder requires a vector of octets."
       octets))
    (let ((input (make-array (+ (length octets) 4)
                             :element-type '(unsigned-byte 8))))
      (replace input octets)
      (setf (aref input (length octets)) 0
            (aref input (+ (length octets) 1)) 0
            (aref input (+ (length octets) 2)) #xff
            (aref input (+ (length octets) 3)) #xff)
      (%websocket-pmd-inflate-raw input max-output-bytes))))

(defun make-websocket-permessage-deflate-decoder
    (&key (max-message-bytes +websocket-default-max-payload-bytes+))
  "Return a stateful decoder for one RFC 7692 WebSocket message stream.

The returned function accepts the PAYLOAD and FRAME arguments used by
READ-WEBSOCKET-MESSAGE. It supports fragmented compressed messages and keeps
no compression context between messages."
  (%websocket-validate-limit max-message-bytes "MAX-MESSAGE-BYTES")
  (let ((message-open-p nil)
        (compressed-p nil)
        (compressed (%websocket-pmd-output)))
    (labels ((reset ()
               (setf message-open-p nil
                     compressed-p nil
                     compressed (%websocket-pmd-output)))
             (append-compressed (payload)
               (when (> (+ (fill-pointer compressed) (length payload))
                        max-message-bytes)
                 (%websocket-size-error
                  "A permessage-deflate message exceeded its compressed size limit."
                  max-message-bytes
                  (+ (fill-pointer compressed) (length payload))))
               (%websocket-pmd-append compressed payload)))
      (lambda (payload frame)
        (let ((opcode (websocket-frame-opcode frame))
              (fin-p (websocket-frame-fin-p frame))
              (reserved-bits (websocket-frame-reserved-bits frame)))
          (cond
            ((member opcode '(1 2) :test #'=)
             (when message-open-p
               (%websocket-protocol-error
                "A permessage-deflate decoder received a new message before the prior one ended."))
             (setf compressed-p
                   (not (zerop (logand reserved-bits
                                       +websocket-permessage-deflate-rsv1+)))
                   message-open-p (not fin-p))
             (if compressed-p
                 (progn
                   (append-compressed payload)
                   (if fin-p
                       (prog1
                           (websocket-permessage-deflate-decompress
                            compressed nil
                            :max-output-bytes max-message-bytes)
                         (reset))
                       (%websocket-empty-octets)))
                 (progn
                   (when fin-p
                     (reset))
                   payload)))
            ((zerop opcode)
             (unless message-open-p
               (%websocket-protocol-error
                "A permessage-deflate decoder received a continuation without an open message."))
             (when (not (zerop (logand reserved-bits
                                       +websocket-permessage-deflate-rsv1+)))
               (%websocket-protocol-error
                "RSV1 is only valid on the first frame of a compressed message."))
             (if compressed-p
                 (progn
                   (append-compressed payload)
                   (if fin-p
                       (prog1
                           (websocket-permessage-deflate-decompress
                            compressed nil
                            :max-output-bytes max-message-bytes)
                         (reset))
                       (%websocket-empty-octets)))
                 (progn
                   (when fin-p
                     (reset))
                   payload)))
            (t
             payload)))))))

(defun make-websocket-permessage-deflate-frame-validator
    (&key payload-decoder)
  "Return a frame validator for the RSV1 rules of RFC 7692.

The validator permits RSV1 only on an initial data frame and rejects it on
continuations and control frames. PAYLOAD-DECODER is required when a frame
uses RSV1 so a negotiated extension cannot silently discard compression."
  (when (and payload-decoder (not (functionp payload-decoder)))
    (%websocket-protocol-error
     "PERMESSAGE-DEFLATE PAYLOAD-DECODER must be a function or NIL."
     payload-decoder))
  (let ((message-open-p nil)
        (decoder payload-decoder))
    (lambda (frame)
      (let* ((opcode (websocket-frame-opcode frame))
             (reserved-bits (websocket-frame-reserved-bits frame))
             (rsv1-p (not (zerop (logand reserved-bits
                                         +websocket-permessage-deflate-rsv1+)))))
        (when (not (zerop (logand reserved-bits #x30)))
          (%websocket-protocol-error
           "RSV2 and RSV3 are not owned by permessage-deflate."
           reserved-bits))
        (cond
          ((%websocket-control-opcode-p opcode)
           (when rsv1-p
             (%websocket-protocol-error
              "RSV1 is not valid on a WebSocket control frame."
              opcode)))
          ((member opcode '(1 2) :test #'=)
           (when message-open-p
             (%websocket-protocol-error
              "A WebSocket data frame arrived before the prior message ended."
              opcode))
           (when (and rsv1-p (null decoder))
             (%websocket-protocol-error
              "A compressed WebSocket frame has no permessage-deflate decoder."))
           (setf message-open-p
                 (not (websocket-frame-fin-p frame))))
          ((zerop opcode)
           (when rsv1-p
             (%websocket-protocol-error
              "RSV1 is not valid on a WebSocket continuation frame."))
           (unless message-open-p
             (%websocket-protocol-error
              "A WebSocket continuation frame has no open data message."))
           (when (websocket-frame-fin-p frame)
             (setf message-open-p nil)))
          (t
           (%websocket-protocol-error
            "A WebSocket frame has an invalid opcode."
            opcode)))
        frame))))

(defstruct (websocket-permessage-deflate
            (:constructor %make-websocket-permessage-deflate
                (&key encoder decoder frame-validator)))
  encoder
  decoder
  frame-validator)

(defun make-websocket-permessage-deflate
    (&key (max-message-bytes +websocket-default-max-payload-bytes+))
  "Construct a stateless RFC 7692 codec bundle.

The bundle uses no-context-takeover semantics on both directions. Its
ENCODER, DECODER, and FRAME-VALIDATOR accessors can be passed directly to the
WebSocket message and transport APIs."
  (let ((decoder
          (make-websocket-permessage-deflate-decoder
           :max-message-bytes max-message-bytes)))
    (%make-websocket-permessage-deflate
     :encoder #'websocket-permessage-deflate-compress
     :decoder decoder
     :frame-validator
     (make-websocket-permessage-deflate-frame-validator
      :payload-decoder decoder))))

(defun websocket-permessage-deflate-extension ()
  "Return the extension offer supported by the bundled codec.

Both context-takeover parameters are disabled because the bundled codec is
intentionally stateless."
  "permessage-deflate; client_no_context_takeover; server_no_context_takeover")
