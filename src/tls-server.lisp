(in-package #:websocket-kit)

(defconstant +websocket-tls-maximum-config-bytes+ (* 1024 1024))
(defconstant +websocket-tls-maximum-handshake-message-bytes+ (* 1024 1024))
(defconstant +websocket-tls-maximum-certificate-count+ 16)

(defstruct (websocket-tls-context
             (:constructor %make-websocket-tls-context (driver provider)))
  driver
  provider
  suite
  alpn
  alert
  (handshake-complete-p nil)
  (read-states (make-hash-table :test #'equal))
  (write-states (make-hash-table :test #'equal)))

(defun %websocket-tls-fail (message &optional detail)
  (%websocket-network-failure message :tls :detail detail))

(defun %websocket-tls-read-file (path element-type limit)
  (with-open-file (stream path :direction :input :element-type element-type)
    (let* ((buffer (make-array (1+ limit) :element-type element-type))
           (count (read-sequence buffer stream)))
      (when (> count limit)
        (%websocket-protocol-error
         "A TLS certificate or key file exceeds the configured size limit."
         path))
      (subseq buffer 0 count))))

(defun %websocket-tls-ascii-string (octets)
  (unless (every (lambda (octet) (< octet 128)) octets)
    (%websocket-protocol-error
     "A TLS PEM file must contain ASCII text."
     :pem-encoding))
  (map 'string #'code-char octets))

(defun %websocket-tls-pem-text-p (text)
  (and (stringp text)
       (>= (length text) 11)
       (string= "-----BEGIN " text :end2 11)))

(defun %websocket-tls-pem-octets-p (octets)
  (and (>= (length octets) 11)
       (equalp (subseq octets 0 11)
               #(45 45 45 45 45 66 69 71 73 78 32))))

(defun %websocket-tls-validate-certificate-chain (chain)
  (let ((count (and (listp chain) (list-length chain))))
    (unless (and count
                 (plusp count)
                 (<= count +websocket-tls-maximum-certificate-count+)
                 (every #'%websocket-byte-vector-p chain))
      (%websocket-protocol-error
       "TLS certificate chains must contain between one and sixteen DER certificates."
       :certificate))
  (when (> (loop for der in chain sum (length der))
           +websocket-tls-maximum-config-bytes+)
    (%websocket-protocol-error
     "A TLS certificate chain exceeds the configured size limit."
     :certificate))
  chain))

(defun %websocket-tls-certificate-chain-from-octets (octets)
  (when (> (length octets) +websocket-tls-maximum-config-bytes+)
    (%websocket-protocol-error
     "A TLS certificate chain exceeds the configured size limit."
     :certificate))
  (let ((chain
          (if (%websocket-tls-pem-octets-p octets)
              (let* ((blocks (cl-tls-kit:pem-decode
                              (%websocket-tls-ascii-string octets)))
                     (certificates
                       (loop for block in blocks
                             when (string= (cl-tls-kit:pem-block-label block)
                                           "CERTIFICATE")
                               collect (cl-tls-kit:pem-block-der block))))
                (unless certificates
                  (%websocket-protocol-error
                   "The TLS PEM file does not contain a certificate."
                   :certificate))
                certificates)
              (list (copy-seq octets)))))
    (%websocket-tls-validate-certificate-chain chain)))

(defun %websocket-tls-certificate-chain (certificate)
  (cond
    ((pathnamep certificate)
     (%websocket-tls-certificate-chain-from-octets
      (%websocket-tls-read-file
       certificate (quote (unsigned-byte 8)) +websocket-tls-maximum-config-bytes+)))
    ((stringp certificate)
     (if (%websocket-tls-pem-text-p certificate)
         (progn
           (when (> (length certificate) +websocket-tls-maximum-config-bytes+)
             (%websocket-protocol-error
              "A TLS certificate chain exceeds the configured size limit."
              :certificate))
           (unless (every (lambda (character) (< (char-code character) 128))
                          certificate)
             (%websocket-protocol-error
              "A TLS PEM file must contain ASCII text."
              :certificate))
           (%websocket-tls-certificate-chain-from-octets
            (map (quote (vector (unsigned-byte 8)))
                 (function char-code) certificate)))
         (%websocket-tls-certificate-chain-from-octets
          (%websocket-tls-read-file
           certificate (quote (unsigned-byte 8))
           +websocket-tls-maximum-config-bytes+))))
    ((%websocket-byte-vector-p certificate)
     (%websocket-tls-validate-certificate-chain (list certificate))
     (list (copy-seq certificate)))
    ((and (listp certificate) certificate)
     (mapcar (function copy-seq)
             (%websocket-tls-validate-certificate-chain certificate)))
    (t
     (%websocket-protocol-error
      "TLS CERTIFICATE must be a PEM path, DER octets, or a DER chain."
      :certificate))))

(defun %websocket-tls-der-sequence-children (node)
  (unless (and (cl-tls-kit:der-node-p node)
               (= (cl-tls-kit:der-node-tag node) 16)
               (cl-tls-kit:der-node-constructed-p node))
    (%websocket-protocol-error "A TLS private key has an invalid DER sequence."
                               :private-key))
  (cl-tls-kit:der-node-children node))

(defun %websocket-tls-der-integer (node expected)
  (unless (and (cl-tls-kit:der-node-p node)
               (= (cl-tls-kit:der-node-tag node) 2)
               (= (cl-tls-kit:der-integer-value node) expected))
    (%websocket-protocol-error "A TLS private key has an invalid DER version."
                               :private-key)))

(defun %websocket-tls-der-octets (node expected-length)
  (unless (and (cl-tls-kit:der-node-p node)
               (= (cl-tls-kit:der-node-tag node) 4)
               (= (length (cl-tls-kit:der-node-value node)) expected-length))
    (%websocket-protocol-error "A TLS private key has invalid DER octets."
                               :private-key))
  (cl-tls-kit:der-node-value node))

(defun %websocket-tls-der-oid-p (node oid)
  (and (cl-tls-kit:der-node-p node)
       (= (cl-tls-kit:der-node-tag node) 6)
       (equal (cl-tls-kit:der-oid-value node) oid)))

(defun %websocket-tls-parse-p256-sec1-key (der &key require-curve-p)
  (let* ((node (cl-tls-kit:der-decode der))
         (children (%websocket-tls-der-sequence-children node))
         (version (first children))
         (scalar-node (second children))
         (parameters (find #xa0 (cddr children)
                           :key #'cl-tls-kit:der-node-tag)))
    (%websocket-tls-der-integer version 1)
    (let ((scalar (%websocket-tls-der-octets scalar-node 32)))
      (when (and require-curve-p (null parameters))
        (%websocket-protocol-error
         "An EC private key without named-curve parameters is unsupported."
         :private-key))
      (when parameters
        (let ((curve (first (cl-tls-kit:der-node-children parameters))))
          (unless (%websocket-tls-der-oid-p curve '(1 2 840 10045 3 1 7))
            (%websocket-protocol-error
             "The TLS server supports only P-256 EC private keys."
             :private-key))))
      (crypto-kit:make-ec-private-key :p256 scalar))))

(defun %websocket-tls-parse-pkcs8-key (der)
  (let* ((node (cl-tls-kit:der-decode der))
         (children (%websocket-tls-der-sequence-children node))
         (algorithm (second children))
         (private-key (third children))
         (algorithm-fields (%websocket-tls-der-sequence-children algorithm)))
    (unless (= (length children) 3)
      (%websocket-protocol-error
       "The TLS server accepts version 0 PKCS#8 private keys only."
       :private-key))
    (%websocket-tls-der-integer (first children) 0)
    (unless (and (cl-tls-kit:der-node-p private-key)
                 (= (cl-tls-kit:der-node-tag private-key) 4))
      (%websocket-protocol-error "A PKCS#8 private key has invalid DER octets."
                                 :private-key))
    (cond
      ((and (= (length algorithm-fields) 2)
            (%websocket-tls-der-oid-p (first algorithm-fields)
                                      '(1 2 840 10045 2 1))
            (%websocket-tls-der-oid-p (second algorithm-fields)
                                      '(1 2 840 10045 3 1 7)))
       (%websocket-tls-parse-p256-sec1-key
        (cl-tls-kit:der-node-value private-key)))
      ((and (= (length algorithm-fields) 1)
            (%websocket-tls-der-oid-p (first algorithm-fields)
                                      '(1 3 101 112)))
       (let* ((inner (cl-tls-kit:der-decode
                      (cl-tls-kit:der-node-value private-key)))
              (seed (%websocket-tls-der-octets inner 32)))
         (crypto-kit:make-ed25519-private-key seed)))
      (t
       (%websocket-protocol-error
        "The TLS server supports only P-256 and Ed25519 private keys."
        :private-key)))))

(defun %websocket-tls-private-key-from-der (der &optional pem-label)
  (when (> (length der) +websocket-tls-maximum-config-bytes+)
    (%websocket-protocol-error "A TLS private key exceeds the size limit."
                               :private-key))
  (cond
    ((equal pem-label "EC PRIVATE KEY")
     (%websocket-tls-parse-p256-sec1-key der :require-curve-p t))
    ((equal pem-label "PRIVATE KEY")
     (%websocket-tls-parse-pkcs8-key der))
    ((equal pem-label "ENCRYPTED PRIVATE KEY")
     (%websocket-protocol-error
      "Encrypted PEM private keys are not supported by the TLS 1.3 server."
      :private-key))
    (pem-label
     (%websocket-protocol-error
      "The TLS PEM file must contain an EC PRIVATE KEY or PRIVATE KEY block."
      :private-key))
    (t
     (let* ((node (cl-tls-kit:der-decode der))
            (children (%websocket-tls-der-sequence-children node))
            (second-node (second children)))
       (if (and second-node (= (cl-tls-kit:der-node-tag second-node) 16))
           (%websocket-tls-parse-pkcs8-key der)
           (%websocket-tls-parse-p256-sec1-key der :require-curve-p t))))))

(defun %websocket-tls-private-key-from-pem (text password)
  (when password
    (%websocket-protocol-error
     "Encrypted TLS private keys are not supported by the TLS 1.3 server."
     :private-key))
  (when (> (length text) +websocket-tls-maximum-config-bytes+)
    (%websocket-protocol-error
     "A TLS private key exceeds the configured size limit."
     :private-key))
  (unless (every (lambda (character) (< (char-code character) 128)) text)
    (%websocket-protocol-error
     "A TLS PEM file must contain ASCII text."
     :private-key))
  (let* ((blocks (cl-tls-kit:pem-decode text))
         (key-block
           (find-if
            (lambda (block)
              (member (cl-tls-kit:pem-block-label block)
                      (quote ("EC PRIVATE KEY" "PRIVATE KEY"
                              "ENCRYPTED PRIVATE KEY"))
                      :test (function string=)))
            blocks)))
    (unless key-block
      (%websocket-protocol-error
       "The TLS PEM file must contain an EC PRIVATE KEY or PRIVATE KEY block."
       :private-key))
    (%websocket-tls-private-key-from-der
     (cl-tls-kit:pem-block-der key-block)
     (cl-tls-kit:pem-block-label key-block))))

(defun %websocket-tls-private-key (key password)
  (cond
    ((pathnamep key)
     (%websocket-tls-private-key-from-der
      (let ((octets (%websocket-tls-read-file
                     key '(unsigned-byte 8)
                     +websocket-tls-maximum-config-bytes+)))
        (if (%websocket-tls-pem-octets-p octets)
            (return-from %websocket-tls-private-key
              (%websocket-tls-private-key-from-pem
               (%websocket-tls-ascii-string octets) password))
            octets))))
    ((stringp key)
     (if (%websocket-tls-pem-text-p key)
         (%websocket-tls-private-key-from-pem key password)
         (%websocket-tls-private-key
          (pathname key) password)))
    ((%websocket-byte-vector-p key)
     (when password
       (%websocket-protocol-error
        "Encrypted TLS private keys are not supported by the TLS 1.3 server."
        :private-key))
     (%websocket-tls-private-key-from-der key))
    (t
     (when password
       (%websocket-protocol-error
        "PASSWORD must be NIL when KEY is a cl-crypto-kit private-key object."
        :private-key))
     key)))

(defun %websocket-tls-traffic-state (context direction level secret)
  (unless (= (websocket-tls-context-suite context) #x1301)
    (%websocket-tls-fail "The TLS server selected an unsupported cipher suite."
                         (websocket-tls-context-suite context)))
  (setf (gethash (list direction level)
                 (if (eq direction :read)
                     (websocket-tls-context-read-states context)
                     (websocket-tls-context-write-states context)))
        (cl-tls-kit:make-tls13-traffic-state
         (websocket-tls-context-provider context)
         :sha256 :aes-128-gcm secret 16 12)))

(defun %websocket-tls-clear-traffic-states (context)
  (dolist (state-table
           (list (websocket-tls-context-read-states context)
                 (websocket-tls-context-write-states context)))
    (maphash
     (lambda (key state)
       (declare (ignore key))
       (dolist (secret
                (list (cl-tls-kit:tls13-traffic-state-secret state)
                      (cl-tls-kit:tls13-traffic-state-key state)
                      (cl-tls-kit:tls13-traffic-state-iv state)))
         (when secret
           (fill secret 0))))
     state-table)
    (clrhash state-table))
  nil)

(defun %websocket-tls-state (context direction level)
  (or (gethash (list direction level)
               (if (eq direction :read)
                   (websocket-tls-context-read-states context)
                   (websocket-tls-context-write-states context)))
      (%websocket-tls-fail "The TLS peer sent data before its traffic secret."
                           (list direction level))))

(defun %websocket-tls-content-type (value)
  (case value
    (:alert cl-tls-kit:+tls-content-type-alert+)
    (:handshake cl-tls-kit:+tls-content-type-handshake+)
    (:application-data cl-tls-kit:+tls-content-type-application-data+)
    ((20 21 22 23) value)
    (t (%websocket-tls-fail "The TLS server emitted an unknown record type."
                            value))))

(defun %websocket-tls-write-fragment
    (transport context content-type fragment level deadline clock-function)
  (let ((position 0)
        (length (length fragment)))
    (loop while (< position length)
          for end = (min length
                         (+ position cl-tls-kit:+tls-plaintext-limit+))
          for plaintext =
            (cl-tls-kit:make-tls-plaintext
             content-type (subseq fragment position end))
          for wire =
            (if (eq level :initial)
                (cl-tls-kit:encode-tls-plaintext plaintext)
                (cl-tls-kit:encrypt-tls13-traffic-record
                 plaintext (%websocket-tls-state context :write level)))
          do (%websocket-network-write-octets
              transport wire deadline clock-function :tls)
             (setf position end))
  nil))

(defun %websocket-tls-process-events
    (context transport events deadline clock-function)
  (dolist (event events)
    (case (getf event :type)
      (:send
       (%websocket-tls-write-fragment
        transport context
        (%websocket-tls-content-type (getf event :content-type))
        (getf event :wire) (getf event :level) deadline clock-function))
      (:secret
       (%websocket-tls-traffic-state
        context (getf event :direction) (getf event :level)
        (getf event :secret)))
      (:cipher-suite
       (setf (websocket-tls-context-suite context) (getf event :suite)))
      (:alpn
       (setf (websocket-tls-context-alpn context) (getf event :protocol)))
      (:handshake-complete
       (setf (websocket-tls-context-handshake-complete-p context) t))
      (:alert
       (setf (websocket-tls-context-alert context) (getf event :description)))
      ((:ticket-issued :peer-quic-transport-parameters)
       nil)
      (otherwise
       (%websocket-tls-fail "The TLS server driver emitted an unknown event."
                            (getf event :type)))))
  (when (websocket-tls-context-alert context)
    (%websocket-tls-fail "The TLS peer handshake was rejected."
                         (websocket-tls-context-alert context)))
  nil)

(defun %websocket-tls-step
    (context transport message level deadline clock-function)
  (multiple-value-bind (driver events)
      (cl-tls-kit:tls13-server-driver-step
       (websocket-tls-context-driver context) message :level level)
    (setf (websocket-tls-context-driver context) driver)
    (%websocket-tls-process-events
     context transport events deadline clock-function)))

(defun %websocket-tls-feed-handshakes
    (context transport buffer fragment level deadline clock-function)
  (let* ((pending buffer)
         (position 0)
         (old-length (fill-pointer pending))
         (new-length (+ old-length (length fragment)))
         (capacity (array-total-size pending)))
    (when (> new-length +websocket-tls-maximum-handshake-message-bytes+)
      (%websocket-tls-fail "A TLS handshake buffer exceeds the size limit."
                           new-length))
    (when (> new-length capacity)
      (setf pending
            (adjust-array
             pending
             (min +websocket-tls-maximum-handshake-message-bytes+
                  (max new-length 4096 (* 2 capacity)))
             :fill-pointer new-length)))
    (setf (fill-pointer pending) new-length)
    (replace pending fragment :start1 old-length)
    (loop while (<= (+ position 4) (length pending))
          for body-length =
            (+ (ash (aref pending (+ position 1)) 16)
               (ash (aref pending (+ position 2)) 8)
               (aref pending (+ position 3)))
          for message-end = (+ position 4 body-length)
          do (when (> (+ 4 body-length)
                      +websocket-tls-maximum-handshake-message-bytes+)
               (%websocket-tls-fail
                "A TLS handshake message exceeds the size limit."
                body-length))
             (when (> message-end (length pending))
               (return))
             (%websocket-tls-step
              context transport
              (subseq pending position message-end)
              level deadline clock-function)
             (setf position message-end)
             (when (and (websocket-tls-context-handshake-complete-p context)
                        (< position (length pending)))
               (%websocket-tls-fail
                "A TLS record contains data after the client Finished message.")))
    (let ((remaining (- (length pending) position)))
      (when (plusp position)
        (replace pending pending :start1 0 :start2 position))
      (setf (fill-pointer pending) remaining))
    pending))

(defun %websocket-tls-read-record
    (transport deadline clock-function operation)
  (let* ((header (%websocket-network-read-octets
                  transport 5 deadline clock-function operation))
         (content-type (aref header 0))
         (version (+ (ash (aref header 1) 8) (aref header 2)))
         (length (+ (ash (aref header 3) 8) (aref header 4)))
         (maximum
           (case content-type
             (20 1)
             (21 cl-tls-kit:+tls-plaintext-limit+)
             (22 cl-tls-kit:+tls-plaintext-limit+)
             (23 cl-tls-kit:+tls-ciphertext-limit+)
             (t (%websocket-tls-fail
                 "The TLS peer sent an invalid record content type."
                 content-type))))
         (allowed-version-p
           (or (= version cl-tls-kit:+tls-record-version+)
               (and (= content-type cl-tls-kit:+tls-content-type-handshake+)
                    (= version #x0301)))))
    (unless allowed-version-p
      (%websocket-tls-fail "The TLS peer sent an invalid record version."
                           version))
    (when (> length maximum)
      (%websocket-tls-fail "The TLS peer sent an oversized record." length))
    (when (or (and (member content-type '(20 21 22)) (zerop length))
              (and (= content-type 21) (< length 2))
              (and (= content-type 20) (/= length 1))
              (and (= content-type 23) (< length 17)))
      (%websocket-tls-fail "The TLS peer sent a malformed record." content-type))
    (let* ((fragment (%websocket-network-read-octets
                      transport length deadline clock-function operation))
           (wire (concatenate '(vector (unsigned-byte 8)) header fragment)))
      (values content-type version fragment wire))))

(defun %websocket-tls-run-handshake
    (context transport deadline clock-function)
  (let ((handshake-buffer (make-array 0
              :element-type '(unsigned-byte 8)
              :adjustable t
              :fill-pointer 0))
        (compatibility-ccs-count 0))
    (loop until (websocket-tls-context-handshake-complete-p context)
          do (multiple-value-bind (content-type version fragment wire)
                 (%websocket-tls-read-record
                  transport deadline clock-function :tls)
               (cond
                 ((= content-type 20)
                  (unless (and (= version cl-tls-kit:+tls-record-version+)
                               (= (aref fragment 0) 1)
                               (< compatibility-ccs-count 1))
                    (%websocket-tls-fail
                     "The TLS peer sent an invalid compatibility CCS."))
                  (incf compatibility-ccs-count))
                 ((= content-type cl-tls-kit:+tls-content-type-handshake+)
                  (setf handshake-buffer
                        (%websocket-tls-feed-handshakes
                         context transport handshake-buffer fragment :initial
                         deadline clock-function)))
                 ((= content-type cl-tls-kit:+tls-content-type-application-data+)
                  (unless (= version cl-tls-kit:+tls-record-version+)
                    (%websocket-tls-fail
                     "An encrypted TLS record has an invalid version." version))
                  (let* ((state (%websocket-tls-state context :read :handshake))
                         (plaintext
                           (cl-tls-kit:decrypt-tls13-traffic-record wire state))
                         (inner-type (cl-tls-kit:tls-plaintext-content-type
                                      plaintext))
                         (inner-fragment (cl-tls-kit:tls-plaintext-fragment
                                          plaintext)))
                    (cond
                      ((= inner-type cl-tls-kit:+tls-content-type-handshake+)
                       (setf handshake-buffer
                             (%websocket-tls-feed-handshakes
                              context transport handshake-buffer inner-fragment
                              :handshake deadline clock-function)))
                      ((= inner-type cl-tls-kit:+tls-content-type-alert+)
                       (%websocket-tls-fail
                        "The TLS peer sent an alert during the handshake."))
                      (t
                       (%websocket-tls-fail
                        "The TLS peer sent application data before Finished.")))))
                 (t
                  (%websocket-tls-fail
                   "The TLS peer sent an unexpected handshake record."
                   content-type))))))
  nil)

(defun %websocket-tls-new-driver (provider certificate-chain private-key alpn)
  (cl-tls-kit:make-tls13-server-driver
   :provider provider
   :certificate-chain certificate-chain
   :private-key private-key
   :alpn-protocols alpn
   :cipher-suites #(#x1301)))

(defun %websocket-make-tls-server-wrapper
    (&key certificate key password alpn-protocols unwrap-stream-p clock-function)
  (unless (%websocket-valid-certificate-pair-p certificate key t)
    (%websocket-protocol-error
     "TLS server certificates require both CERTIFICATE and KEY."
     (list :certificate certificate :key :redacted)))
  (unless (%websocket-valid-alpn-protocols-p alpn-protocols)
    (%websocket-protocol-error
     "TLS ALPN-PROTOCOLS must be a list of non-empty ASCII protocol names."
     alpn-protocols))
  (when (and alpn-protocols
             (not (member "http/1.1" alpn-protocols :test #'string=)))
    (%websocket-protocol-error
     "TLS server ALPN-PROTOCOLS must include HTTP/1.1."
     alpn-protocols))
  (when password
    (%websocket-protocol-error
     "PASSWORD must be NIL for the TLS 1.3 server."
     :password))
  (when unwrap-stream-p
    (%websocket-protocol-error
     "UNWRAP-STREAM-P must be NIL for the TLS 1.3 server."
     :unwrap-stream-p))
  (let* ((clock (or clock-function #'%websocket-monotonic-time))
         (provider (cl-tls-kit:make-cl-crypto-kit-provider))
         (certificate-chain (%websocket-tls-certificate-chain certificate))
         (private-key (%websocket-tls-private-key key password)))
    (unless (functionp clock)
      (%websocket-protocol-error "TLS CLOCK-FUNCTION must be callable." clock))
    (%websocket-tls-new-driver provider certificate-chain private-key alpn-protocols)
    (lambda (stream &key timeout deadline clock-function &allow-other-keys)
      (unless (streamp stream)
        (%websocket-protocol-error "TLS upgrade requires a Lisp stream." stream))
      (let* ((callback-clock (or clock-function clock))
             (effective-deadline
               (%websocket-effective-deadline
                timeout deadline callback-clock))
             (context
               (%make-websocket-tls-context
                (%websocket-tls-new-driver
                 provider certificate-chain private-key alpn-protocols)
                provider)))
        (let ((tls-stream nil))
          (unwind-protect
               (progn
                 (%websocket-call-with-deadline
                  (lambda ()
                    (%websocket-tls-run-handshake
                     context stream effective-deadline callback-clock))
                  effective-deadline callback-clock :tls)
                 (setf tls-stream
                       (make-instance 'websocket-tls-stream
                                      :transport stream :context context
                                      :clock-function callback-clock))
                 (values tls-stream (websocket-tls-context-alpn context)))
            (unless tls-stream
              (unwind-protect
                   (%websocket-tls-clear-traffic-states context)
                (cl-tls-kit:tls13-server-driver-close
                 (websocket-tls-context-driver context))))))))))

(defun %websocket-tls-stream-read-buffer-available-p (stream)
  (< (websocket-tls-stream-read-position stream)
     (length (websocket-tls-stream-read-buffer stream))))

(defun %websocket-tls-stream-fill-read-buffer (stream)
  (loop
    (when (or (websocket-tls-stream-closed-p stream)
              (websocket-tls-stream-peer-close-notify-p stream))
      (return nil))
    (multiple-value-bind (content-type version fragment wire)
        (%websocket-tls-read-record
         (websocket-tls-stream-transport stream) nil
         (websocket-tls-stream-clock-function stream) :tls)
      (declare (ignore version fragment))
      (unless (= content-type cl-tls-kit:+tls-content-type-application-data+)
        (%websocket-tls-fail
         "The TLS peer sent unencrypted data after the handshake." content-type))
      (let* ((context (websocket-tls-stream-context stream))
             (state (%websocket-tls-state context :read :application))
             (plaintext (cl-tls-kit:decrypt-tls13-traffic-record wire state))
             (inner-type (cl-tls-kit:tls-plaintext-content-type plaintext))
             (inner-fragment (cl-tls-kit:tls-plaintext-fragment plaintext)))
        (cond
          ((= inner-type cl-tls-kit:+tls-content-type-application-data+)
           (cl-tls-kit:tls13-server-driver-note-application-data-received
            (websocket-tls-context-driver context))
           (setf (websocket-tls-stream-read-buffer stream) inner-fragment
                 (websocket-tls-stream-read-position stream) 0)
           (when (plusp (length inner-fragment))
             (return t)))
          ((= inner-type cl-tls-kit:+tls-content-type-handshake+)
           (unless (cl-tls-kit:tls-key-update-p plaintext)
             (%websocket-tls-fail
              "The TLS peer sent an unsupported post-handshake message."))
           (%websocket-tls-step
            context (websocket-tls-stream-transport stream) inner-fragment
            :application nil (websocket-tls-stream-clock-function stream)))
          ((= inner-type cl-tls-kit:+tls-content-type-alert+)
           (if (cl-tls-kit:tls-close-notify-p plaintext)
               (progn
                 (setf (websocket-tls-stream-peer-close-notify-p stream) t
                       (websocket-tls-stream-read-buffer stream)
                       (make-array 0 :element-type '(unsigned-byte 8))
                       (websocket-tls-stream-read-position stream) 0)
                 (return nil))
               (progn
                 (setf (websocket-tls-context-alert context) :peer-fatal-alert)
                 (%websocket-tls-fail "The TLS peer sent a fatal alert."))))
          (t
           (%websocket-tls-fail
            "The TLS peer sent an invalid TLSInnerPlaintext type."
            inner-type)))))))

#+sbcl
(defclass websocket-tls-stream
    (sb-gray:fundamental-binary-input-stream
     sb-gray:fundamental-binary-output-stream)
  ((transport :initarg :transport :reader websocket-tls-stream-transport)
   (context :initarg :context :reader websocket-tls-stream-context)
   (clock-function :initarg :clock-function
                   :reader websocket-tls-stream-clock-function)
   (read-buffer :initform (make-array 0 :element-type '(unsigned-byte 8))
                :accessor websocket-tls-stream-read-buffer)
   (read-position :initform 0 :accessor websocket-tls-stream-read-position)
   (closed-p :initform nil :accessor websocket-tls-stream-closed-p)
   (peer-close-notify-p :initform nil
                        :accessor websocket-tls-stream-peer-close-notify-p)))

#+sbcl
(defmethod stream-element-type ((stream websocket-tls-stream))
  (declare (ignore stream))
  '(unsigned-byte 8))

#+sbcl
(defmethod sb-gray:stream-read-byte ((stream websocket-tls-stream))
  (unless (%websocket-tls-stream-read-buffer-available-p stream)
    (unless (%websocket-tls-stream-fill-read-buffer stream)
      (return-from sb-gray:stream-read-byte :eof)))
  (prog1 (aref (websocket-tls-stream-read-buffer stream)
               (websocket-tls-stream-read-position stream))
    (incf (websocket-tls-stream-read-position stream))))

#+sbcl
(defmethod sb-gray:stream-read-sequence
    ((stream websocket-tls-stream) sequence &optional (start 0) end)
  (let ((end (or end (length sequence)))
        (position start))
    (loop while (< position end)
          do (unless (%websocket-tls-stream-read-buffer-available-p stream)
               (unless (%websocket-tls-stream-fill-read-buffer stream)
                 (return)))
             (let* ((buffer (websocket-tls-stream-read-buffer stream))
                    (read-position (websocket-tls-stream-read-position stream))
                    (count (min (- end position)
                                (- (length buffer) read-position))))
               (loop for offset below count
                     do (setf (elt sequence (+ position offset))
                              (aref buffer (+ read-position offset))))
               (incf position count)
               (incf (websocket-tls-stream-read-position stream) count)))
    position))

(defun %websocket-tls-stream-write-sequence (stream sequence start end)
  (let ((position start)
        (context (websocket-tls-stream-context stream)))
    (unless (and (integerp start) (integerp end)
                 (<= 0 start end (length sequence)))
      (%websocket-protocol-error "TLS stream sequence bounds are invalid."
                                 (list start end)))
    (loop while (< position end)
          for chunk-end =
            (min end (+ position cl-tls-kit:+tls-plaintext-limit+))
          for chunk =
            (make-array (- chunk-end position)
                        :element-type '(unsigned-byte 8))
          do (loop for source-index from position below chunk-end
                   for octet = (elt sequence source-index)
                   unless (typep octet '(unsigned-byte 8))
                     do (%websocket-protocol-error
                         "TLS binary output requires octets." octet)
                   do (setf (aref chunk (- source-index position)) octet))
             (%websocket-tls-write-fragment
              (websocket-tls-stream-transport stream) context
              cl-tls-kit:+tls-content-type-application-data+
              chunk :application nil
              (websocket-tls-stream-clock-function stream))
             (setf position chunk-end))
    sequence))

#+sbcl
(defmethod sb-gray:stream-write-byte ((stream websocket-tls-stream) byte)
  (%websocket-tls-stream-write-sequence stream (vector byte) 0 1)
  byte)

#+sbcl
(defmethod sb-gray:stream-write-sequence
    ((stream websocket-tls-stream) sequence &optional (start 0) end)
  (%websocket-tls-stream-write-sequence
   stream sequence start (or end (length sequence))))

#+sbcl
(defmethod sb-gray:stream-finish-output ((stream websocket-tls-stream))
  (finish-output (websocket-tls-stream-transport stream)))

#+sbcl
(defmethod sb-gray:stream-force-output ((stream websocket-tls-stream))
  (force-output (websocket-tls-stream-transport stream)))

#+sbcl
(defmethod close ((stream websocket-tls-stream) &key abort)
  (unless (websocket-tls-stream-closed-p stream)
    (let* ((context (websocket-tls-stream-context stream))
           (abort-p (or abort (websocket-tls-context-alert context))))
      (unwind-protect
           (unless (or abort-p
                       (websocket-tls-stream-peer-close-notify-p stream))
             (when (websocket-tls-context-handshake-complete-p context)
               (%websocket-tls-write-fragment
                (websocket-tls-stream-transport stream) context
                cl-tls-kit:+tls-content-type-alert+ #(1 0) :application nil
                (websocket-tls-stream-clock-function stream))))
        (setf (websocket-tls-stream-closed-p stream) t)
        (unwind-protect
             (%websocket-tls-clear-traffic-states context)
          (unwind-protect
               (cl-tls-kit:tls13-server-driver-close
                (websocket-tls-context-driver context))
            (close (websocket-tls-stream-transport stream)
                   :abort abort-p))))))
  t)

#-sbcl
(defun %websocket-make-tls-server-wrapper (&rest arguments)
  (declare (ignore arguments))
  (%websocket-network-failure
   "The TLS 1.3 server stream requires SBCL Gray streams."
   :tls))
