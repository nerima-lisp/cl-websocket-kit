(in-package #:websocket-kit)

(defconstant +websocket-http2-default-max-frame-size+ #x4000)
(defconstant +websocket-http3-default-max-frame-size+ #x4000)
(defconstant +websocket-http3-default-qpack-max-table-capacity+ 0)
(defconstant +websocket-http3-default-qpack-encoder-table-capacity+ 4096)
(defconstant +websocket-http3-default-qpack-blocked-streams+ 0)
(defconstant +websocket-http2-3-default-initial-window-size+ 65535)
(defconstant +websocket-http2-default-hpack-table-size+ 4096)
(defconstant +websocket-http2-enable-connect-protocol-setting+ 8)
(defconstant +websocket-http3-enable-connect-protocol-setting+ 8)

(defun %websocket-http2-3-fail (message &key detail)
  (error 'websocket-http-error
         :message message
         :operation :http2-3
         :detail detail))

(defun %websocket-http2-3-token-character-p (character)
  (or (and (char>= character #\a) (char<= character #\z))
      (and (char>= character #\A) (char<= character #\Z))
      (and (char>= character #\0) (char<= character #\9))
      (member character
              '(#\! #\# #\$ #\% #\& #\' #\* #\+ #\- #\. #\^ #\_ #\` #\| #\~)
              :test #'char=)))

(defun %websocket-http2-3-header-name-p (name)
  (and (stringp name)
       (plusp (length name))
       (string= name (string-downcase name))
       (every #'%websocket-http2-3-token-character-p name)))

(defun %websocket-http2-3-pseudo-header-name-p (name)
  (and (stringp name)
       (> (length name) 1)
       (char= (char name 0) #\:)
       (%websocket-http2-3-header-name-p (subseq name 1))))

(defun http-pseudo-header-p (header)
  (and (http-header-p header)
       (%websocket-http2-3-pseudo-header-name-p
        (http-header-name header))))

(defun make-http-pseudo-header (name content)
  (unless (and (%websocket-http2-3-pseudo-header-name-p name)
               (%websocket-http2-3-header-value-p content))
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 pseudo-header requires a colon-prefixed name and string value."
     :detail (list name content)))
  ;; cl-http-message-kit deliberately rejects pseudo-header names in its
  ;; public constructor, while HPACK/QPACK still use the same header value
  ;; object.  Construct the validated representation after applying this
  ;; protocol's stricter pseudo-header checks.
  (http-message-kit::%make-http-header
   :name name
   :content content))

(defun %websocket-http2-3-octet-vector-p (octets)
  (and (vectorp octets)
       (= 1 (array-rank octets))
       (every (lambda (octet)
                (and (integerp octet) (<= 0 octet 255)))
              octets)))

(defun %websocket-http2-3-copy-octets (octets)
  (unless (%websocket-http2-3-octet-vector-p octets)
    (%websocket-http2-3-fail
     "WebSocket HTTP/2 and HTTP/3 data must be octet vectors."
     :detail (type-of octets)))
  (let ((copy (make-array (length octets)
                          :element-type '(unsigned-byte 8))))
    (replace copy octets)
    copy))

(defun %websocket-http2-3-append-octets (parts)
  (let* ((parts (remove nil parts))
         (result (make-array (reduce #'+ parts
                                     :key #'length
                                     :initial-value 0)
                             :element-type '(unsigned-byte 8)))
         (position 0))
    (dolist (part parts result)
      (replace result part :start1 position)
      (incf position (length part)))))

(defun %websocket-http2-3-ensure-text (value field)
  (unless (and (stringp value) (plusp (length value)))
    (%websocket-http2-3-fail
     "A WebSocket extended CONNECT pseudo-header must be a non-empty string."
     :detail field))
  value)

(defun %websocket-http2-3-ensure-additional-headers (headers)
  (unless (listp headers)
    (%websocket-http2-3-fail
     "Additional WebSocket HTTP/2 or HTTP/3 headers must be a list."
     :detail headers))
  (dolist (header headers headers)
    (unless (and (http-header-p header)
                 (not (http-pseudo-header-p header)))
      (%websocket-http2-3-fail
       "Additional WebSocket HTTP/2 or HTTP/3 headers must be regular headers."
       :detail header))))

(defun %websocket-http2-3-header-content (headers name)
  (let ((header (find name headers
                      :key #'http-header-name
                      :test #'string-equal)))
    (and header (http-header-content header))))

(defun %websocket-http2-3-string-equal-p (value expected)
  (and (stringp value) (string-equal value expected)))

(defun %websocket-http2-3-header-value-p (value)
  (and (stringp value)
       (every (lambda (character)
                (let ((code (char-code character)))
                  (or (= code #x09)
                      (and (<= #x20 code)
                           (not (= code #x7f))))))
              value)))

(defun %websocket-http2-3-forbidden-header-name-p (name)
  (member name
          '("connection" "keep-alive" "proxy-connection"
            "transfer-encoding" "upgrade")
          :test #'string=))

(defun %websocket-http2-3-websocket-request-p (headers)
  (and (string= (%websocket-http2-3-header-content headers ":method")
               "CONNECT")
       (string= (%websocket-http2-3-header-content headers ":protocol")
                "websocket")
       (let ((scheme (%websocket-http2-3-header-content headers ":scheme"))
             (authority (%websocket-http2-3-header-content headers ":authority"))
             (path (%websocket-http2-3-header-content headers ":path")))
         (and (member scheme '("http" "https") :test #'string-equal)
              (stringp authority) (plusp (length authority))
              (stringp path) (plusp (length path))))))

(defun %websocket-http2-3-websocket-response-p (headers)
  (%websocket-http2-3-string-equal-p
   (%websocket-http2-3-header-content headers ":status")
   "200"))

(defun %websocket-http2-3-validate-header-section
    (headers protocol &key (request-p t) trailers-p)
  (unless (listp headers)
    (%websocket-http2-3-fail
     "An HTTP/2 or HTTP/3 header section must be a list."
     :detail headers))
  (let ((regular-seen-p nil)
        (pseudo-names nil)
        (allowed-pseudo-names
          (if trailers-p
              nil
              (if request-p
                  '(":method" ":protocol" ":scheme" ":authority" ":path")
                  '(":status")))))
    (dolist (header headers)
      (unless (http-header-p header)
        (%websocket-http2-3-fail
         "An HTTP/2 or HTTP/3 header section contains a non-header object."
         :detail header))
      (let ((name (http-header-name header))
            (value (http-header-content header)))
        (unless (%websocket-http2-3-header-value-p value)
          (%websocket-http2-3-fail
           "An HTTP/2 or HTTP/3 header value contains a forbidden character."
           :detail name))
        (if (http-pseudo-header-p header)
            (progn
              (unless (and (stringp value) (plusp (length value)))
                (%websocket-http2-3-fail
                 "HTTP/2 and HTTP/3 pseudo-header values must be non-empty."
                 :detail name))
              (when regular-seen-p
                (%websocket-http2-3-fail
                 "Pseudo-headers must precede regular HTTP/2 or HTTP/3 headers."
                 :detail name))
              (unless (and (%websocket-http2-3-pseudo-header-name-p name)
                           (member name allowed-pseudo-names :test #'string=))
                (%websocket-http2-3-fail
                 "The HTTP/2 or HTTP/3 header section contains an invalid pseudo-header."
                 :detail name))
              (when (member name pseudo-names :test #'string=)
                (%websocket-http2-3-fail
                 "An HTTP/2 or HTTP/3 header section contains a duplicate pseudo-header."
                 :detail name))
              (push name pseudo-names))
            (progn
              (setf regular-seen-p t)
              (unless (%websocket-http2-3-header-name-p name)
                (%websocket-http2-3-fail
                 "HTTP/2 and HTTP/3 regular header names must be lowercase tokens."
                 :detail name))
              (when (%websocket-http2-3-forbidden-header-name-p name)
                (%websocket-http2-3-fail
                 "Connection-specific headers are forbidden in HTTP/2 and HTTP/3."
                 :detail name))
              (when (and (string= name "te")
                         (not (string-equal
                               (string-trim '(#\Space #\Tab) value)
                               "trailers")))
                (%websocket-http2-3-fail
                 "The HTTP/2 and HTTP/3 TE header may only contain trailers."
                 :detail value)))))))
  (unless (or trailers-p
              (if request-p
                  (%websocket-http2-3-websocket-request-p headers)
                  (%websocket-http2-3-websocket-response-p headers)))
    (%websocket-http2-3-fail
     "The header section is not a WebSocket extended CONNECT section."
     :detail (list protocol headers)))
  headers)

(defun %websocket-http2-3-headers->pairs (headers)
  (mapcar (lambda (header)
            (cons (http-header-name header)
                  (http-header-content header)))
          headers))

(defun %websocket-http2-3-pairs->headers (pairs)
  (mapcar (lambda (pair)
            (unless (and (consp pair)
                         (stringp (car pair))
                         (stringp (cdr pair)))
              (%websocket-http2-3-fail
               "An HPACK or QPACK decoder returned an invalid header field."
               :detail pair))
            (if (and (plusp (length (car pair)))
                     (char= (char (car pair) 0) #\:))
                (make-http-pseudo-header (car pair) (cdr pair))
                (make-http-header (car pair) (cdr pair))))
          pairs))

(defun %websocket-http2-3-check-http2-stream-id (stream-id)
  (unless (and (integerp stream-id)
               (<= 1 stream-id #x7fffffff))
    (%websocket-http2-3-fail
     "HTTP/2 WebSocket frames require a positive stream identifier."
     :detail stream-id))
  stream-id)

(defun %websocket-http2-3-check-http3-stream-id (stream-id)
  (unless (and (integerp stream-id)
               (<= 0 stream-id)
               (member (logand stream-id 3) '(0 1) :test #'=))
    (%websocket-http2-3-fail
     "HTTP/3 WebSocket frames require a bidirectional stream identifier."
     :detail stream-id))
  stream-id)

(defun %websocket-http2-3-check-http3-transport-stream-id (stream-id)
  (unless (and (integerp stream-id)
               (<= 0 stream-id #x3fffffffffffffff))
    (%websocket-http2-3-fail
     "An HTTP/3 QUIC stream identifier must fit in 62 bits."
     :detail stream-id))
  stream-id)

(defun %websocket-http2-3-check-http2-max-frame-size (max-frame-size)
  (unless (and (integerp max-frame-size)
               (<= #x4000 max-frame-size #xffffff))
    (%websocket-http2-3-fail
     "HTTP/2 MAX_FRAME_SIZE must be between 16384 and 16777215."
     :detail max-frame-size))
  max-frame-size)

(defun %websocket-http2-3-check-http3-max-frame-size (max-frame-size)
  (unless (and (integerp max-frame-size)
               (<= 1 max-frame-size #x3fffffffffffffff))
    (%websocket-http2-3-fail
     "HTTP/3 frame sizes must be positive QUIC varint integers."
     :detail max-frame-size))
  max-frame-size)

(defun %websocket-http2-3-payload-fragments (payload max-frame-size)
  (let ((copy (%websocket-http2-3-copy-octets payload))
        (position 0)
        (fragments nil))
    (if (zerop (length copy))
        (list copy)
        (loop while (< position (length copy))
              for end = (min (length copy) (+ position max-frame-size))
              do (push (subseq copy position end) fragments)
                 (setf position end)
              finally (return (nreverse fragments))))))

(defun %websocket-http2-3-http2-type-code (type)
  (case type
    (:data 0)
    (:headers 1)
    (:rst-stream 3)
    (:settings 4)
    (:ping 6)
    (:goaway 7)
    (:window-update 8)
    (:continuation 9)
    (otherwise
     (%websocket-http2-3-fail
      "The requested HTTP/2 frame type is not supported."
      :detail type))))

(defstruct (%websocket-http2-frame
            (:constructor %make-websocket-http2-frame
                (type flags stream-id payload)))
  type
  flags
  stream-id
  payload)

(defun %websocket-http2-3-encode-http2-frame
    (type flags stream-id payload)
  (unless (and (integerp flags) (<= 0 flags #xff))
    (%websocket-http2-3-fail
     "HTTP/2 frame flags must fit in one octet."
     :detail flags))
  (unless (and (integerp stream-id) (<= 0 stream-id #x7fffffff))
    (%websocket-http2-3-fail
     "HTTP/2 frame stream identifiers must fit in 31 bits."
     :detail stream-id))
  (let* ((payload (%websocket-http2-3-copy-octets payload))
         (length (length payload)))
    (when (> length #xffffff)
      (%websocket-http2-3-fail
       "An HTTP/2 frame payload exceeds the wire-format limit."
       :detail length))
    (let ((result (make-array (+ 9 length)
                              :element-type '(unsigned-byte 8))))
      (setf (aref result 0) (ldb (byte 8 16) length)
            (aref result 1) (ldb (byte 8 8) length)
            (aref result 2) (ldb (byte 8 0) length)
            (aref result 3) (%websocket-http2-3-http2-type-code type)
            (aref result 4) flags
            (aref result 5) (ldb (byte 8 24) stream-id)
            (aref result 6) (ldb (byte 8 16) stream-id)
            (aref result 7) (ldb (byte 8 8) stream-id)
            (aref result 8) (ldb (byte 8 0) stream-id))
      (replace result payload :start1 9)
      result)))

(defun %websocket-http2-3-decode-http2-frame
    (octets &key max-payload-bytes)
  (let ((octets (%websocket-http2-3-copy-octets octets)))
    (when (< (length octets) 9)
      (%websocket-http2-3-fail
       "An HTTP/2 frame header is incomplete."
       :detail (length octets)))
    (let* ((length (logior (ash (aref octets 0) 16)
                           (ash (aref octets 1) 8)
                           (aref octets 2)))
           (end (+ 9 length)))
      (when (and max-payload-bytes
                 (> length max-payload-bytes))
        (%websocket-size-error
         "An HTTP/2 frame payload exceeds the selected decode limit."
         max-payload-bytes
         length))
      (when (> end (length octets))
        (%websocket-http2-3-fail
         "An HTTP/2 frame payload is incomplete."
         :detail (list length (- (length octets) 9))))
      (values
       (%make-websocket-http2-frame
        (aref octets 3)
        (aref octets 4)
        (logior (ash (logand (aref octets 5) #x7f) 24)
                (ash (aref octets 6) 16)
                (ash (aref octets 7) 8)
                (aref octets 8))
        (subseq octets 9 end))
       end))))

(defun %websocket-http2-3-header-block-fragment (frame)
  (let* ((flags (%websocket-http2-frame-flags frame))
         (payload (%websocket-http2-frame-payload frame))
         (offset 0)
         (padding 0))
    (when (logtest #x8 flags)
      (when (zerop (length payload))
        (%websocket-http2-3-fail
         "A padded HTTP/2 HEADERS frame is missing its pad length."))
      (setf padding (aref payload 0)
            offset 1))
    (when (logtest #x20 flags)
      (incf offset 5))
    (when (> (+ offset padding) (length payload))
      (%websocket-http2-3-fail
       "An HTTP/2 HEADERS frame has invalid padding or priority data."))
    (when (logtest #x20 flags)
      (let ((dependency (logior (ash (aref payload (- offset 5)) 24)
                                (ash (aref payload (- offset 4)) 16)
                                (ash (aref payload (- offset 3)) 8)
                                (aref payload (- offset 2)))))
        (when (= (logand dependency #x7fffffff)
                 (%websocket-http2-frame-stream-id frame))
          (%websocket-http2-3-fail
           "An HTTP/2 HEADERS frame cannot depend on its own stream."))))
    (subseq payload offset (- (length payload) padding))))

(defun %websocket-http2-3-data-payload (frame)
  (let* ((flags (%websocket-http2-frame-flags frame))
         (payload (%websocket-http2-frame-payload frame))
         (offset 0)
         (padding 0))
    (when (logtest #x8 flags)
      (when (zerop (length payload))
        (%websocket-http2-3-fail
         "A padded HTTP/2 DATA frame is missing its pad length."))
      (setf padding (aref payload 0)
            offset 1))
    (when (> (+ offset padding) (length payload))
      (%websocket-http2-3-fail
       "An HTTP/2 DATA frame has invalid padding."))
    (subseq payload offset (- (length payload) padding))))

(defun %websocket-http2-3-decode-http3-varint (octets position)
  (handler-case
      (http-kit/http3:http3-varint-decode octets :position position)
    (error (condition)
      (%websocket-http2-3-fail
       "An HTTP/3 frame variable-length integer is invalid or incomplete."
       :detail condition))))

(defun %websocket-http2-3-encode-http3-frame (type payload)
  (http-kit/http3:encode-http3-frame
   (http-kit/http3:make-http3-frame
    :type type
    :payload (%websocket-http2-3-copy-octets payload))))

(defun %websocket-http2-3-decode-http3-frame
    (octets &key max-payload-bytes)
  (let ((octets (%websocket-http2-3-copy-octets octets)))
    (multiple-value-bind (type after-type)
        (%websocket-http2-3-decode-http3-varint octets 0)
      (multiple-value-bind (length after-length)
          (%websocket-http2-3-decode-http3-varint octets after-type)
        (let ((end (+ after-length length)))
          (when (and max-payload-bytes
                     (> length max-payload-bytes))
            (%websocket-size-error
             "An HTTP/3 frame payload exceeds the selected decode limit."
             max-payload-bytes
             length))
          (when (> end (length octets))
            (%websocket-http2-3-fail
             "An HTTP/3 frame payload is incomplete."
             :detail (list length (- (length octets) after-length))))
          (values type (subseq octets after-length end) end))))))

(defun websocket-http2-connection-preface ()
  "Return the HTTP/2 client connection preface octets."
  (make-array 24
              :element-type '(unsigned-byte 8)
              :initial-contents
              '(80 82 73 32 42 32 72 84 84 80 47 50 46 48
                13 10 13 10 83 77 13 10 13 10)))

(defun make-websocket-http2-connect-headers
    (authority &key (scheme "https") (path "/") headers)
  (let ((authority (%websocket-http2-3-ensure-text authority :authority))
        (scheme (%websocket-http2-3-ensure-text scheme :scheme))
        (path (%websocket-http2-3-ensure-text path :path)))
    (unless (member scheme '("http" "https") :test #'string-equal)
      (%websocket-http2-3-fail
       "The WebSocket extended CONNECT scheme must be HTTP or HTTPS."
       :detail scheme))
    (append
     (list (make-http-pseudo-header ":method" "CONNECT")
           (make-http-pseudo-header ":protocol" "websocket")
           (make-http-pseudo-header ":scheme" scheme)
           (make-http-pseudo-header ":authority" authority)
           (make-http-pseudo-header ":path" path))
     (%websocket-http2-3-ensure-additional-headers headers))))

(defun make-websocket-http3-connect-headers
    (authority &key (scheme "https") (path "/") headers)
  (make-websocket-http2-connect-headers
   authority :scheme scheme :path path :headers headers))

(defun make-websocket-http2-connect-response-headers
    (&key (status 200) headers)
  (let ((status (typecase status
                  (integer (princ-to-string status))
                  (string status)
                  (otherwise
                   (%websocket-http2-3-fail
                    "An HTTP/2 WebSocket response status must be an integer or string."
                    :detail status)))))
    (unless (string= status "200")
      (%websocket-http2-3-fail
       "An extended CONNECT WebSocket response must have status 200."
       :detail status))
    (cons (make-http-pseudo-header ":status" status)
          (%websocket-http2-3-ensure-additional-headers headers))))

(defun make-websocket-http3-connect-response-headers
    (&key (status 200) headers)
  (make-websocket-http2-connect-response-headers
   :status status :headers headers))

(defun websocket-http2-extended-connect-p (headers)
  (handler-case
      (not (null (%websocket-http2-3-validate-header-section
                  headers :http/2 :request-p t)))
    (error () nil)))

(defun websocket-http3-extended-connect-p (headers)
  (handler-case
      (not (null (%websocket-http2-3-validate-header-section
                  headers :http/3 :request-p t)))
    (error () nil)))

(defun websocket-http2-connect-response-p (headers)
  (handler-case
      (not (null (%websocket-http2-3-validate-header-section
                  headers :http/2 :request-p nil)))
    (error () nil)))

(defun websocket-http3-connect-response-p (headers)
  (handler-case
      (not (null (%websocket-http2-3-validate-header-section
                  headers :http/3 :request-p nil)))
    (error () nil)))

(defstruct (websocket-http2-hpack-context
             (:constructor %make-websocket-http2-hpack-context)
             (:conc-name %websocket-http2-hpack-context-))
  table
  maximum-size
  max-size
  pending-max-size)

(defun %websocket-http2-hpack-size-p (size)
  (and (integerp size) (<= 0 size #xffffffff)))

(defun %websocket-http2-hpack-check-size (size label)
  (unless (%websocket-http2-hpack-size-p size)
    (%websocket-http2-3-fail
     "An HTTP/2 HPACK table size must be an unsigned 32-bit integer."
     :detail (list label size)))
  size)

(defun %websocket-http2-hpack-context-table-for (context)
  (cond
    ((websocket-http2-hpack-context-p context)
     (%websocket-http2-hpack-context-table context))
    ((http-kit/http2::%hpack-context-p context)
     context)
    (t
     (%websocket-http2-3-fail
      "The HTTP/2 HPACK context is not a supported context object."
      :detail context))))

(defun %websocket-http2-hpack-context-wrapper-p (context)
  (websocket-http2-hpack-context-p context))

(defun %websocket-http2-hpack-context-sync (context)
  (when (%websocket-http2-hpack-context-wrapper-p context)
    (let ((table (%websocket-http2-hpack-context-table context)))
      (setf (%websocket-http2-hpack-context-maximum-size context)
            (http-kit/http2::%hpack-context-maximum-size table)
            (%websocket-http2-hpack-context-max-size context)
            (http-kit/http2::%hpack-context-max-size table))))
  context)

(defun make-websocket-http2-hpack-context
    (&key (maximum-size +websocket-http2-default-hpack-table-size+)
          (max-size maximum-size))
  (%websocket-http2-hpack-check-size maximum-size :maximum-size)
  (%websocket-http2-hpack-check-size max-size :max-size)
  (when (> max-size maximum-size)
    (%websocket-http2-3-fail
     "An HTTP/2 HPACK current table size cannot exceed its maximum size."
     :detail (list :max-size max-size :maximum-size maximum-size)))
  (%make-websocket-http2-hpack-context
   :table (http-kit/http2::%make-hpack-context
           :max-size max-size
           :maximum-size maximum-size)
   :maximum-size maximum-size
   :max-size max-size
   :pending-max-size nil))

(defun websocket-http2-hpack-context-size (context)
  (let ((table (%websocket-http2-hpack-context-table-for context)))
    (http-kit/http2::%hpack-context-size table)))

(defun websocket-http2-hpack-context-max-size (context)
  (let ((table (%websocket-http2-hpack-context-table-for context)))
    (http-kit/http2::%hpack-context-max-size table)))

(defun websocket-http2-hpack-context-maximum-size (context)
  (let ((table (%websocket-http2-hpack-context-table-for context)))
    (http-kit/http2::%hpack-context-maximum-size table)))

(defun set-websocket-http2-hpack-context-maximum-size (context size)
  (unless (websocket-http2-hpack-context-p context)
    (%websocket-http2-3-fail
     "HPACK table-size limits can only be changed on a WebSocket HPACK context."
     :detail context))
  (%websocket-http2-hpack-check-size size :maximum-size)
  (let* ((table (%websocket-http2-hpack-context-table context))
         (old-max (http-kit/http2::%hpack-context-max-size table)))
    (http-kit/http2::%hpack-set-maximum-size table size)
    (%websocket-http2-hpack-context-sync context)
    (when (/= old-max (http-kit/http2::%hpack-context-max-size table))
      (setf (%websocket-http2-hpack-context-pending-max-size context)
            (http-kit/http2::%hpack-context-max-size table)))
    context))

(defun set-websocket-http2-hpack-context-max-size (context size)
  (unless (websocket-http2-hpack-context-p context)
    (%websocket-http2-3-fail
     "HPACK table-size limits can only be changed on a WebSocket HPACK context."
     :detail context))
  (%websocket-http2-hpack-check-size size :max-size)
  (let* ((table (%websocket-http2-hpack-context-table context))
         (old-max (http-kit/http2::%hpack-context-max-size table)))
    (http-kit/http2::%hpack-set-max-size table size)
    (%websocket-http2-hpack-context-sync context)
    (when (/= old-max (http-kit/http2::%hpack-context-max-size table))
      (setf (%websocket-http2-hpack-context-pending-max-size context)
            (http-kit/http2::%hpack-context-max-size table)))
    context))

(defun %websocket-http2-hpack-static-index (name &optional value)
  (loop with table = http-kit/http2::*hpack-static-table*
        for index from 1 to (length table)
        for entry = (aref table (1- index))
        when (and (string= name (car entry))
                  (or (null value) (string= value (cdr entry))))
          do (return index)))

(defun %websocket-http2-hpack-dynamic-index
    (context name &optional value)
  (loop with table = (%websocket-http2-hpack-context-table-for context)
        with static-length = (length http-kit/http2::*hpack-static-table*)
        for entry in (http-kit/http2::%hpack-context-entries table)
        for offset from 1
        when (and (string= name (http-kit/http2::%hpack-entry-name entry))
                  (or (null value)
                      (string= value (http-kit/http2::%hpack-entry-value entry))))
          do (return (+ static-length offset))))

(defun %websocket-http2-hpack-index (context name &optional value)
  (or (%websocket-http2-hpack-static-index name value)
      (%websocket-http2-hpack-dynamic-index context name value)))

(defun %websocket-http2-hpack-sensitive-name-p (name)
  (member name '("authorization"
                 "proxy-authorization"
                 "cookie"
                 "set-cookie"
                 "sec-websocket-key"
                 "sec-websocket-protocol"
                 "www-authenticate"
                 "proxy-authenticate")
          :test #'string=))

(defun %websocket-http2-hpack-literal-field
    (context name value prefix prefix-bits huffman-p)
  (let ((name-index (%websocket-http2-hpack-index context name)))
    (%websocket-http2-3-append-octets
     (list
      (http-kit/http2::%hpack-encode-integer
       (or name-index 0) prefix-bits prefix)
      (unless name-index
        (http-kit/http2::%hpack-encode-string name :huffman-p huffman-p))
      (http-kit/http2::%hpack-encode-string value :huffman-p huffman-p)))))

(defun %websocket-http2-hpack-encode-dynamic-block
    (fields context huffman-p)
  (let* ((wrapper-p (%websocket-http2-hpack-context-wrapper-p context))
         (table (%websocket-http2-hpack-context-table-for context))
         (pending (and wrapper-p
                       (%websocket-http2-hpack-context-pending-max-size context)))
         (parts nil))
    (when pending
      (push (http-kit/http2::%hpack-encode-integer pending 5 #x20) parts))
    (dolist (field fields)
      (let ((name (car field))
            (value (cdr field)))
        (if (%websocket-http2-hpack-sensitive-name-p name)
            (push (%websocket-http2-hpack-literal-field
                   table name value #x10 4 huffman-p)
                  parts)
            (let ((index (%websocket-http2-hpack-index table name value)))
              (if index
                  (push (http-kit/http2::%hpack-encode-integer index 7 #x80)
                        parts)
                  (progn
                    (push (%websocket-http2-hpack-literal-field
                           table name value #x40 6 huffman-p)
                          parts)
                    (http-kit/http2::%hpack-add table name value)))))))
    (let ((result (%websocket-http2-3-append-octets (nreverse parts))))
      (when wrapper-p
        (setf (%websocket-http2-hpack-context-pending-max-size context) nil))
      result)))

(defun encode-websocket-http2-headers
    (headers &key context (request-p t) trailers-p huffman-p
                    (max-header-bytes +websocket-default-max-header-bytes+))
  (%websocket-validate-limit max-header-bytes "MAX-HEADER-BYTES")
  (let* ((normalized (%websocket-http2-3-validate-header-section
                     headers :http/2
                     :request-p request-p
                     :trailers-p trailers-p))
         (pairs (%websocket-http2-3-headers->pairs normalized))
         (block (if context
                    (%websocket-http2-hpack-encode-dynamic-block
                     pairs context huffman-p)
                    (http-kit/http2::%hpack-encode-block
                     pairs :huffman-p huffman-p))))
    (when (> (length block) max-header-bytes)
      (%websocket-size-error
       "The encoded HTTP/2 header block exceeds the selected size limit."
       max-header-bytes
       (length block)))
    block))

(defun decode-websocket-http2-headers
    (octets &key context (request-p t) trailers-p
                    (max-header-bytes +websocket-default-max-header-bytes+))
  (%websocket-validate-limit max-header-bytes "MAX-HEADER-BYTES")
  (let* ((octets (%websocket-http2-3-copy-octets octets))
         (context (or context (http-kit/http2::%make-hpack-context)))
         (table (%websocket-http2-hpack-context-table-for context))
         (headers (%websocket-http2-3-pairs->headers
                   (http-kit/http2::%hpack-decode-block
                    octets table :max-header-bytes max-header-bytes))))
    (%websocket-http2-hpack-context-sync context)
    (values (%websocket-http2-3-validate-header-section
             headers :http/2
             :request-p request-p
             :trailers-p trailers-p)
            (length octets))))

(defun encode-websocket-http3-headers
    (headers stream-id &key context (request-p t) trailers-p huffman-p
                    (max-header-bytes +websocket-default-max-header-bytes+))
  (%websocket-http2-3-check-http3-stream-id stream-id)
  (%websocket-validate-limit max-header-bytes "MAX-HEADER-BYTES")
  (let* ((normalized (%websocket-http2-3-validate-header-section
                     headers :http/3
                     :request-p request-p
                     :trailers-p trailers-p))
         (block (http-kit/http3:qpack-encode-field-section
                 (%websocket-http2-3-headers->pairs normalized)
                 :dynamic-table context
                 :huffman-p huffman-p)))
    (when (> (length block) max-header-bytes)
      (%websocket-size-error
       "The encoded HTTP/3 header block exceeds the selected size limit."
       max-header-bytes
       (length block)))
    block))

(defun decode-websocket-http3-headers
    (octets stream-id &key context (request-p t) trailers-p
                               (max-header-bytes +websocket-default-max-header-bytes+))
  (%websocket-http2-3-check-http3-stream-id stream-id)
  (%websocket-validate-limit max-header-bytes "MAX-HEADER-BYTES")
  (let* ((octets (%websocket-http2-3-copy-octets octets))
         (headers
           (%websocket-http2-3-pairs->headers
            (http-kit/http3:qpack-decode-field-section
             octets
             :dynamic-table context
             :max-table-capacity
             (if context
                 (http-kit/http3:qpack-dynamic-table-max-capacity context)
                 0)
             :max-header-bytes max-header-bytes
             :max-fields 256))))
    (values (%websocket-http2-3-validate-header-section
             headers :http/3
             :request-p request-p
             :trailers-p trailers-p)
            (length octets))))

(defun encode-websocket-http2-headers-frames
    (headers stream-id &key context (request-p t) trailers-p end-stream-p huffman-p
                         (max-frame-size +websocket-http2-default-max-frame-size+)
                         (max-header-block-bytes +websocket-default-max-header-bytes+)
                         (max-continuation-frames +websocket-default-max-fragments+))
  (%websocket-http2-3-check-http2-stream-id stream-id)
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (%websocket-validate-limit max-header-block-bytes "MAX-HEADER-BLOCK-BYTES")
  (%websocket-validate-limit max-continuation-frames "MAX-CONTINUATION-FRAMES")
  (let* ((block (encode-websocket-http2-headers
                 headers :context context
                        :request-p request-p
                        :trailers-p trailers-p
                        :huffman-p huffman-p
                        :max-header-bytes max-header-block-bytes))
         (fragments (%websocket-http2-3-payload-fragments
                     block max-frame-size))
         (frames nil)
         (last-index (1- (length fragments)))
         (continuation-count (max 0 (1- (length fragments)))))
    (when (> (length block) max-header-block-bytes)
      (%websocket-size-error
       "An HTTP/2 header block exceeded its selected size limit."
       max-header-block-bytes
       (length block)))
    (when (> continuation-count max-continuation-frames)
      (%websocket-size-error
       "An HTTP/2 header block exceeded its CONTINUATION-frame limit."
       max-continuation-frames
       continuation-count))
    (loop for fragment in fragments
          for index from 0
          for type = (if (zerop index) :headers :continuation)
          for flags = (logior
                       (if (= index last-index) #x4 0)
                       (if (and end-stream-p (zerop index)) #x1 0))
          do (push (%websocket-http2-3-encode-http2-frame
                    type flags stream-id fragment)
                   frames)
          finally (return (%websocket-http2-3-append-octets
                          (nreverse frames))))))

(defun decode-websocket-http2-headers-frames
    (octets &key context (request-p t) trailers-p expected-stream-id
                   (max-frame-size +websocket-http2-default-max-frame-size+)
                   (max-header-block-bytes +websocket-default-max-header-bytes+)
                   (max-continuation-frames +websocket-default-max-fragments+))
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (%websocket-validate-limit max-header-block-bytes "MAX-HEADER-BLOCK-BYTES")
  (%websocket-validate-limit max-continuation-frames "MAX-CONTINUATION-FRAMES")
  (let ((position 0)
        (fragments nil)
        (first-frame nil)
        (finished-p nil)
        (header-block-bytes 0)
        (continuation-count 0))
    (flet ((accept-fragment (fragment)
             (incf header-block-bytes (length fragment))
             (when (> header-block-bytes max-header-block-bytes)
               (%websocket-size-error
                "An HTTP/2 header block exceeded its selected size limit."
                max-header-block-bytes
                header-block-bytes))
             (push fragment fragments)))
      (multiple-value-bind (frame used)
          (%websocket-http2-3-decode-http2-frame
           octets :max-payload-bytes max-frame-size)
        (unless (= (%websocket-http2-frame-type frame) 1)
          (%websocket-http2-3-fail
           "An HTTP/2 WebSocket header sequence must start with HEADERS."))
        (%websocket-http2-3-check-http2-stream-id
         (%websocket-http2-frame-stream-id frame))
        (when expected-stream-id
          (%websocket-http2-3-check-http2-stream-id expected-stream-id)
          (when (/= expected-stream-id (%websocket-http2-frame-stream-id frame))
            (%websocket-http2-3-fail
             "An HTTP/2 WebSocket header sequence used the wrong stream.")))
        (setf first-frame frame
              position used)
        (accept-fragment (%websocket-http2-3-header-block-fragment frame))
        (setf finished-p (logtest #x4 (%websocket-http2-frame-flags frame))))
      (loop until finished-p
            do (multiple-value-bind (frame used)
                   (%websocket-http2-3-decode-http2-frame
                    (subseq octets position)
                    :max-payload-bytes max-frame-size)
                 (unless (and (= (%websocket-http2-frame-type frame) 9)
                              (= (%websocket-http2-frame-stream-id frame)
                                 (%websocket-http2-frame-stream-id first-frame)))
                   (%websocket-http2-3-fail
                    "An HTTP/2 WebSocket header sequence has an invalid CONTINUATION frame."))
                 (incf continuation-count)
                 (when (> continuation-count max-continuation-frames)
                   (%websocket-size-error
                    "An HTTP/2 header block exceeded its CONTINUATION-frame limit."
                    max-continuation-frames
                    continuation-count))
                 (incf position used)
                 (accept-fragment (%websocket-http2-frame-payload frame))
                 (setf finished-p
                       (logtest #x4 (%websocket-http2-frame-flags frame)))))
      (let ((block (%websocket-http2-3-append-octets (nreverse fragments))))
        (multiple-value-bind (headers end)
            (decode-websocket-http2-headers
             block :context context :request-p request-p :trailers-p trailers-p
             :max-header-bytes max-header-block-bytes)
          (declare (ignore end))
          (values headers
                  position
                  (%websocket-http2-frame-stream-id first-frame)
                  (logtest #x1 (%websocket-http2-frame-flags first-frame))))))))

(defun encode-websocket-http2-data-frame
    (payload stream-id &key end-stream-p
                            (max-frame-size +websocket-http2-default-max-frame-size+))
  (%websocket-http2-3-check-http2-stream-id stream-id)
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (let ((payload (%websocket-http2-3-copy-octets payload)))
    (when (> (length payload) max-frame-size)
      (%websocket-http2-3-fail
       "The HTTP/2 DATA payload exceeds the selected frame size."
       :detail (length payload)))
    (%websocket-http2-3-encode-http2-frame
     :data (if end-stream-p #x1 0) stream-id payload)))

(defun encode-websocket-http2-data-frames
    (payload stream-id &key end-stream-p
                            (max-frame-size +websocket-http2-default-max-frame-size+))
  (%websocket-http2-3-check-http2-stream-id stream-id)
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (let* ((fragments (%websocket-http2-3-payload-fragments
                     payload max-frame-size))
         (last-index (1- (length fragments)))
         (frames nil))
    (loop for fragment in fragments
          for index from 0
          do (push (%websocket-http2-3-encode-http2-frame
                    :data
                    (if (and end-stream-p (= index last-index)) #x1 0)
                    stream-id
                    fragment)
                   frames)
          finally (return (%websocket-http2-3-append-octets
                          (nreverse frames))))))

(defun decode-websocket-http2-data-frame
    (octets &key expected-stream-id
                   (max-frame-size +websocket-http2-default-max-frame-size+))
  (%websocket-http2-3-check-http2-max-frame-size max-frame-size)
  (multiple-value-bind (frame used)
      (%websocket-http2-3-decode-http2-frame
       octets :max-payload-bytes max-frame-size)
    (unless (= (%websocket-http2-frame-type frame) 0)
      (%websocket-http2-3-fail
       "The HTTP/2 WebSocket data sequence must contain a DATA frame."))
    (%websocket-http2-3-check-http2-stream-id
     (%websocket-http2-frame-stream-id frame))
    (when expected-stream-id
      (%websocket-http2-3-check-http2-stream-id expected-stream-id)
      (when (/= expected-stream-id (%websocket-http2-frame-stream-id frame))
        (%websocket-http2-3-fail
         "An HTTP/2 WebSocket DATA frame used the wrong stream.")))
    (values (%websocket-http2-3-data-payload frame)
            used
            (%websocket-http2-frame-stream-id frame)
            (logtest #x1 (%websocket-http2-frame-flags frame)))))

(defun encode-websocket-http3-headers-frame
    (headers stream-id &key context (request-p t) trailers-p huffman-p
                         (max-frame-size +websocket-http3-default-max-frame-size+)
                         (max-header-block-bytes +websocket-default-max-header-bytes+))
  (%websocket-http2-3-check-http3-stream-id stream-id)
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (%websocket-validate-limit max-header-block-bytes "MAX-HEADER-BLOCK-BYTES")
  (let ((block (encode-websocket-http3-headers
                headers stream-id
                :context context
                :request-p request-p
                :trailers-p trailers-p
                :huffman-p huffman-p
                :max-header-bytes max-header-block-bytes)))
    (when (> (length block) max-header-block-bytes)
      (%websocket-size-error
       "An HTTP/3 header block exceeded its selected size limit."
       max-header-block-bytes
       (length block)))
    (when (> (length block) max-frame-size)
      (%websocket-http2-3-fail
       "The HTTP/3 WebSocket HEADERS block exceeds the selected frame size."
       :detail (length block)))
    (%websocket-http2-3-encode-http3-frame
     http-kit/http3:+http3-headers-type+
     block)))

(defun decode-websocket-http3-headers-frame
    (octets &key context (request-p t) trailers-p expected-stream-id
                   (max-frame-size +websocket-http3-default-max-frame-size+)
                   (max-header-block-bytes +websocket-default-max-header-bytes+))
  (unless (integerp expected-stream-id)
    (%websocket-http2-3-fail
     "HTTP/3 frame decoding requires the caller's stream identifier."
     :detail expected-stream-id))
  (%websocket-http2-3-check-http3-stream-id expected-stream-id)
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (%websocket-validate-limit max-header-block-bytes "MAX-HEADER-BLOCK-BYTES")
  (multiple-value-bind (type payload used)
      (%websocket-http2-3-decode-http3-frame
       octets :max-payload-bytes max-frame-size)
    (unless (= type http-kit/http3:+http3-headers-type+)
      (%websocket-http2-3-fail
       "The HTTP/3 WebSocket header sequence must contain a HEADERS frame."))
    (when (> (length payload) max-header-block-bytes)
      (%websocket-size-error
       "An HTTP/3 header block exceeded its selected size limit."
       max-header-block-bytes
       (length payload)))
    (multiple-value-bind (headers end)
        (decode-websocket-http3-headers
         payload expected-stream-id
         :context context :request-p request-p :trailers-p trailers-p
         :max-header-bytes max-header-block-bytes)
      (declare (ignore end))
      (values headers used expected-stream-id))))

(defun encode-websocket-http3-data-frame
    (payload stream-id &key (max-frame-size +websocket-http3-default-max-frame-size+))
  (%websocket-http2-3-check-http3-stream-id stream-id)
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (let ((payload (%websocket-http2-3-copy-octets payload)))
    (when (> (length payload) max-frame-size)
      (%websocket-http2-3-fail
       "The HTTP/3 WebSocket DATA payload exceeds the selected frame size."
       :detail (length payload)))
    (%websocket-http2-3-encode-http3-frame
     http-kit/http3:+http3-data-type+
     payload)))

(defun encode-websocket-http3-data-frames
    (payload stream-id &key (max-frame-size +websocket-http3-default-max-frame-size+))
  (%websocket-http2-3-check-http3-stream-id stream-id)
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (%websocket-http2-3-append-octets
   (mapcar (lambda (fragment)
             (%websocket-http2-3-encode-http3-frame
              http-kit/http3:+http3-data-type+
              fragment))
           (%websocket-http2-3-payload-fragments payload max-frame-size))))

(defun decode-websocket-http3-data-frame
    (octets &key expected-stream-id
                   (max-frame-size +websocket-http3-default-max-frame-size+))
  (unless (integerp expected-stream-id)
    (%websocket-http2-3-fail
     "HTTP/3 frame decoding requires the caller's stream identifier."
     :detail expected-stream-id))
  (%websocket-http2-3-check-http3-stream-id expected-stream-id)
  (%websocket-http2-3-check-http3-max-frame-size max-frame-size)
  (multiple-value-bind (type payload used)
      (%websocket-http2-3-decode-http3-frame
       octets :max-payload-bytes max-frame-size)
    (unless (= type http-kit/http3:+http3-data-type+)
      (%websocket-http2-3-fail
       "The HTTP/3 WebSocket data sequence must contain a DATA frame."))
    (values payload used expected-stream-id)))

(defun %websocket-http2-3-read-u16 (octets position)
  (logior (ash (aref octets position) 8)
          (aref octets (1+ position))))

(defun %websocket-http2-3-read-u32 (octets position)
  (logior (ash (aref octets position) 24)
          (ash (aref octets (+ position 1)) 16)
          (ash (aref octets (+ position 2)) 8)
          (aref octets (+ position 3))))

(defun encode-websocket-http2-connect-settings ()
  (let ((payload (make-array 6 :element-type '(unsigned-byte 8))))
    (setf (aref payload 0) 0
          (aref payload 1) +websocket-http2-enable-connect-protocol-setting+
          (aref payload 2) 0
          (aref payload 3) 0
          (aref payload 4) 0
          (aref payload 5) 1)
    (%websocket-http2-3-encode-http2-frame :settings 0 0 payload)))

(defun %websocket-http2-3-validate-http2-setting-value (identifier value)
  (case identifier
    (0
     (%websocket-http2-3-fail
      "An HTTP/2 SETTINGS identifier of zero is invalid."
      :detail identifier))
    (2
     (unless (member value '(0 1) :test #'=)
       (%websocket-http2-3-fail
        "HTTP/2 ENABLE_PUSH must be 0 or 1."
        :detail value)))
    (4
     (when (> value #x7fffffff)
       (%websocket-http2-3-fail
        "HTTP/2 INITIAL_WINDOW_SIZE exceeds the signed 31-bit limit."
        :detail value)))
    (5
     (unless (<= #x4000 value #xffffff)
       (%websocket-http2-3-fail
        "HTTP/2 MAX_FRAME_SIZE must be between 16384 and 16777215."
        :detail value)))
    (8
     (unless (member value '(0 1) :test #'=)
       (%websocket-http2-3-fail
        "HTTP/2 ENABLE_CONNECT_PROTOCOL must be 0 or 1."
        :detail value))))
  value)

(defun decode-websocket-http2-connect-settings (octets)
  (multiple-value-bind (frame used)
      (%websocket-http2-3-decode-http2-frame octets)
    (unless (and (= (%websocket-http2-frame-type frame) 4)
                 (zerop (%websocket-http2-frame-flags frame))
                 (zerop (%websocket-http2-frame-stream-id frame)))
      (%websocket-http2-3-fail
       "An HTTP/2 CONNECT settings input must be an unacknowledged connection SETTINGS frame."))
    (let ((payload (%websocket-http2-frame-payload frame))
          (position 0)
          (settings nil))
      (unless (zerop (mod (length payload) 6))
        (%websocket-http2-3-fail
         "An HTTP/2 SETTINGS payload must contain six-byte entries."))
      (loop while (< position (length payload))
            do (let ((identifier (%websocket-http2-3-read-u16 payload position))
                     (value (%websocket-http2-3-read-u32 payload (+ position 2))))
                 (when (assoc identifier settings)
                   (%websocket-http2-3-fail
                    "An HTTP/2 SETTINGS payload contains a duplicate identifier."
                    :detail identifier))
                 (%websocket-http2-3-validate-http2-setting-value
                  identifier value)
                 (push (cons identifier value) settings)
                 (incf position 6)))
      (values (nreverse settings) used))))

(defun %websocket-http2-3-setting-value (settings identifier legacy-key)
  (when (listp settings)
    (let ((entry (or (assoc identifier settings)
                     (assoc legacy-key settings))))
      (and entry (cdr entry)))))

(defun websocket-http2-connect-protocol-enabled-p (settings)
  (let ((value (%websocket-http2-3-setting-value
                settings
                +websocket-http2-enable-connect-protocol-setting+
                :enable-connect-protocol)))
    (and (integerp value) (= 1 value))))

(defun encode-websocket-http3-connect-settings
    (&key (qpack-max-table-capacity
            +websocket-http3-default-qpack-max-table-capacity+)
          (max-field-section-size +websocket-default-max-header-bytes+)
          (qpack-blocked-streams +websocket-http3-default-qpack-blocked-streams+)
          (enable-connect 1))
  (http-kit/http3:encode-http3-frame
   (http-kit/http3:make-http3-settings-frame
    :qpack-max-table-capacity qpack-max-table-capacity
    :max-field-section-size max-field-section-size
    :qpack-blocked-streams qpack-blocked-streams
    :enable-connect enable-connect)))

(defun %websocket-http2-3-validate-http3-setting-identifiers (settings)
  (dolist (entry settings)
    (when (member (car entry) '(2 3 4 5) :test #'=)
      (%websocket-http2-3-fail
       "An HTTP/3 SETTINGS payload contains an HTTP/2-only identifier."
       :detail (car entry))))
  settings)

(defun decode-websocket-http3-connect-settings (octets)
  (multiple-value-bind (type payload used)
      (%websocket-http2-3-decode-http3-frame octets)
    (unless (= type http-kit/http3:+http3-settings-type+)
      (%websocket-http2-3-fail
       "An HTTP/3 CONNECT settings input must be a SETTINGS frame."))
    (let ((settings
            (http-kit/http3:decode-http3-settings
             (http-kit/http3:make-http3-frame :type type :payload payload))))
      (%websocket-http2-3-validate-http3-setting-identifiers settings)
      (let ((entry (assoc +websocket-http3-enable-connect-protocol-setting+
                          settings)))
        (when entry
          (unless (and (integerp (cdr entry))
                       (member (cdr entry) '(0 1) :test #'=))
            (%websocket-http2-3-fail
             "HTTP/3 ENABLE_CONNECT_PROTOCOL must be 0 or 1."
             :detail (cdr entry)))))
      (dolist (entry (list
                      (assoc http-kit/http3:+http3-setting-qpack-max-table-capacity+
                             settings)
                      (assoc http-kit/http3:+http3-setting-max-field-section-size+
                             settings)
                      (assoc http-kit/http3:+http3-setting-qpack-blocked-streams+
                             settings)))
        (when (and entry
                   (or (not (integerp (cdr entry)))
                       (< (cdr entry) 0)))
          (%websocket-http2-3-fail
           "HTTP/3 QPACK and field-section settings must be non-negative integers."
           :detail entry)))
      (values settings used))))

(defun websocket-http3-connect-protocol-enabled-p (settings)
  (let ((value (%websocket-http2-3-setting-value
                settings
                +websocket-http3-enable-connect-protocol-setting+
                :enable-connect-protocol)))
    (and (integerp value) (= 1 value))))
