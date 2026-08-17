(in-package #:websocket-kit)

#+sbcl
#.(progn (require :sb-bsd-sockets) nil)

#+sbcl
(eval-when (:compile-toplevel :load-toplevel :execute)
  (require :sb-bsd-sockets))

(defparameter +websocket-unspecified+
  (gensym "WEBSOCKET-UNSPECIFIED-"))

(defconstant +websocket-default-handshake-timeout+ 30)

(defstruct (websocket-proxy
            (:constructor %make-websocket-proxy
                (type host port username password headers tls-upgrader)))
  type
  host
  port
  username
  password
  headers
  tls-upgrader)

(defstruct (websocket-connection
            (:constructor %make-websocket-connection
                (stream request response selected-protocol
                 selected-extensions peer-address peer-port
                 local-mask-p peer-mask-required-p
                 payload-encoder payload-decoder payload-reserved-bits)))
  stream
  listener
  request
  response
  selected-protocol
  selected-extensions
  peer-address
  peer-port
  (closed-p nil)
  local-mask-p
  peer-mask-required-p
  (state :open)
  close-code
  close-reason
  close-condition
  payload-encoder
  payload-decoder
  payload-reserved-bits
#+sbcl
  (read-lock (sb-thread:make-mutex :name "websocket-kit-connection-read"))
#-sbcl
  (read-lock nil)
#+sbcl
  (write-lock (sb-thread:make-mutex :name "websocket-kit-connection-write"))
#-sbcl
  (write-lock nil))

(defstruct (websocket-listener
            (:constructor %make-websocket-listener
                (socket address port address-family tls-wrapper)))
  socket
  address
  port
  address-family
  tls-wrapper
  (closed-p nil)
  (active-connections 0)
  (total-connections 0)
  (connections nil)
  (pending-streams nil)
#+sbcl
  (state-lock (sb-thread:make-mutex :name "websocket-kit-listener-state"))
#-sbcl
  (state-lock nil))

(defmacro %websocket-network-with-listener-lock ((listener) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-listener-state-lock ,listener))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defun %websocket-network-register-connection (listener connection)
  (%websocket-network-with-listener-lock (listener)
    (unless (websocket-listener-closed-p listener)
      (setf (websocket-connection-listener connection) listener)
      (push connection (websocket-listener-connections listener))
      (incf (websocket-listener-active-connections listener))
      (incf (websocket-listener-total-connections listener))
      connection)))

(defun %websocket-network-register-pending-stream (listener stream)
  (%websocket-network-with-listener-lock (listener)
    (unless (websocket-listener-closed-p listener)
      (push stream (websocket-listener-pending-streams listener))
      t)))

(defun %websocket-network-replace-pending-stream
    (listener old-stream new-stream)
  (%websocket-network-with-listener-lock (listener)
    (when (member old-stream
                  (websocket-listener-pending-streams listener)
                  :test #'eq)
      (setf (websocket-listener-pending-streams listener)
            (cons new-stream
                  (remove old-stream
                          (websocket-listener-pending-streams listener)
                          :test #'eq)))
      t)))

(defun %websocket-network-unregister-pending-stream (listener stream)
  (%websocket-network-with-listener-lock (listener)
    (setf (websocket-listener-pending-streams listener)
          (remove stream
                  (websocket-listener-pending-streams listener)
                  :test #'eq)))
  nil)

(defun %websocket-network-remove-connection-locked (listener connection)
  (when (member connection
                (websocket-listener-connections listener)
                :test #'eq)
    (setf (websocket-listener-connections listener)
          (remove connection
                  (websocket-listener-connections listener)
                  :test #'eq))
    (when (plusp (websocket-listener-active-connections listener))
      (decf (websocket-listener-active-connections listener)))
    t))

(defun %websocket-network-unregister-connection (connection)
  (let ((listener (websocket-connection-listener connection)))
    (when listener
      (%websocket-network-with-listener-lock (listener)
        (%websocket-network-remove-connection-locked listener connection))))
  nil)

(defun %websocket-network-listener-connections (listener)
  (%websocket-network-with-listener-lock (listener)
    (copy-list (websocket-listener-connections listener))))

(defun %websocket-network-failure (message operation &key detail cause)
  (error 'websocket-transport-error
         :message message
         :operation operation
         :detail detail
         :cause cause))

(defun %websocket-network-validate-port (port)
  (unless (and (integerp port) (<= 0 port 65535))
    (%websocket-protocol-error
     "A network port must be an integer between 0 and 65535."
     port))
  port)

(defun %websocket-network-validate-host (host)
  (unless (and (stringp host) (plusp (length host))
               (not (find-if (lambda (character)
                               (or (<= (char-code character) #x1f)
                                   (= (char-code character) #x7f)))
                             host)))
    (%websocket-protocol-error
     "A network host must be a non-empty string without control characters."
     host))
  host)

(defun %websocket-network-validate-headers (headers)
  (unless (listp headers)
    (%websocket-protocol-error
     "Network extra headers must be supplied as a list."
     headers))
  (dolist (header headers)
    (unless (http-header-p header)
      (%websocket-protocol-error
       "Network extra headers must be HTTP header values."
       header)))
  (copy-list headers))

(defun %websocket-network-validate-tls-upgrader (tls-upgrader name)
  (when tls-upgrader
    (unless (functionp tls-upgrader)
      (%websocket-protocol-error
       (format nil "~A must be callable or NIL." name)
       tls-upgrader)))
  tls-upgrader)

(defun make-http-connect-proxy
    (&key host (port 8080) username password headers tls-upgrader)
  "Create an HTTP CONNECT proxy configuration.

TLS-UPGRADER, when supplied, protects the connection to the proxy before
CONNECT is sent. This is necessary when proxy credentials must not cross the
network in cleartext."
  (%make-websocket-proxy
   :http-connect
   (%websocket-network-validate-host host)
   (%websocket-network-validate-port port)
   (when username
     (unless (stringp username)
       (%websocket-protocol-error
        "An HTTP proxy username must be a string or NIL." username))
     username)
   (when password
     (unless (stringp password)
       (%websocket-protocol-error
        "An HTTP proxy password must be a string or NIL." password))
     password)
   (%websocket-network-validate-headers headers)
   (%websocket-network-validate-tls-upgrader
    tls-upgrader "HTTP proxy TLS-UPGRADER")))

(defun make-socks5-proxy
    (&key host (port 1080) username password tls-upgrader)
  "Create a SOCKS5 proxy configuration.

USERNAME and PASSWORD enable RFC 1929 username/password authentication.
TLS-UPGRADER, when supplied, protects the connection to the proxy before
SOCKS5 negotiation is sent."
  (when (not (eql (null username) (null password)))
    (%websocket-protocol-error
     "SOCKS5 username and password must be supplied together."
     (list username password)))
  (%make-websocket-proxy
   :socks5
   (%websocket-network-validate-host host)
   (%websocket-network-validate-port port)
   (when username
     (unless (stringp username)
       (%websocket-protocol-error
        "A SOCKS5 username must be a string or NIL." username))
     username)
   (when password
     (unless (stringp password)
       (%websocket-protocol-error
        "A SOCKS5 password must be a string or NIL." password))
     password)
   nil
   (%websocket-network-validate-tls-upgrader
    tls-upgrader "SOCKS5 proxy TLS-UPGRADER")))

(defun %websocket-byte-vector-p (value)
  (and (vectorp value)
       (= 1 (array-rank value))
       (subtypep (array-element-type value) '(unsigned-byte 8))))

(defun %websocket-random-octets (count)
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    (or
     (ignore-errors
       (with-open-file (stream #P"/dev/urandom"
                               :direction :input
                               :element-type '(unsigned-byte 8))
         (when (= count (read-sequence result stream))
           result)))
     (let* ((package (or (find-package :ironclad)
                         (ignore-errors (require :ironclad)
                                        (find-package :ironclad))))
            (symbol (and package (find-symbol "RANDOM-DATA" package))))
       (when (and symbol (fboundp symbol))
         (let ((data (funcall symbol count)))
           (when (%websocket-byte-vector-p data)
             data))))
     (%websocket-network-failure
      "No cryptographically secure random-byte source is available."
      :random)) ))

(defun generate-websocket-key (&optional random-function)
  "Return a fresh RFC 6455 Sec-WebSocket-Key value.

When RANDOM-FUNCTION is supplied it receives the requested byte count and
must return a one-dimensional unsigned-byte vector."
  (let ((octets (if random-function
                    (progn
                      (unless (functionp random-function)
                        (%websocket-protocol-error
                         "RANDOM-FUNCTION must be callable."
                         random-function))
                      (funcall random-function 16))
                    (%websocket-random-octets 16))))
    (unless (and (%websocket-byte-vector-p octets)
                 (= 16 (length octets)))
      (%websocket-protocol-error
       "The random-byte source must return exactly 16 octets."
       octets))
    (%websocket-base64-encode octets)))

(defun %websocket-random-masking-key ()
  (%websocket-random-octets 4))

(defun %websocket-uri-scheme (uri)
  (if (http-uri-p uri)
      (string-downcase (http-uri-scheme uri))
      (when (stringp uri)
        (let ((colon (position #\: uri)))
          (and colon (subseq uri 0 colon))))))

(defun %websocket-network-uri (uri)
  (let ((scheme (%websocket-uri-scheme uri)))
    (unless (member (and scheme (string-downcase scheme))
                    '("http" "https" "ws" "wss")
                    :test #'string=)
      (%websocket-protocol-error
       "A WebSocket URI must use http, https, ws, or wss."
       uri))
    (let ((http-uri
            (if (http-uri-p uri)
                uri
                (parse-http-uri (%websocket-http-uri uri)))))
      (unless (and (http-uri-p http-uri)
                   (http-uri-host http-uri)
                   (plusp (length (http-uri-host http-uri))))
        (%websocket-protocol-error
         "A WebSocket URI must contain a host."
         uri))
      http-uri)))

(defun %websocket-network-tls-p (uri)
  (member (string-downcase (%websocket-uri-scheme uri))
          '("https" "wss") :test #'string=))

(defun %websocket-network-port (uri)
  (or (http-uri-port uri)
      (if (member (string-downcase (http-uri-scheme uri))
                  '("https" "wss") :test #'string=)
          443
          80)))

(defun %websocket-network-authority (host port)
  (let ((host (if (and (plusp (length host))
                       (char= (char host 0) #\[))
                  host
                  (if (find #\: host)
                      (format nil "[~A]" host)
                      host))))
    (if port
        (format nil "~A:~D" host port)
        host)))

(defun %websocket-network-proxy-uri (proxy)
  (make-http-uri
   :scheme "https"
   :authority (%websocket-network-authority
               (websocket-proxy-host proxy)
               (websocket-proxy-port proxy))
   :path "/"))

(defun %websocket-network-octets (string)
  (%websocket-utf8-octets string))

#+sbcl
(progn
  (defconstant +websocket-ipv4-address-type+ 2)
  (defconstant +websocket-ipv6-address-type+ 30)

  (defun %websocket-native-address-entries
      (host &optional deadline clock-function)
    (let ((clock (or clock-function #'%websocket-monotonic-time)))
      (%websocket-call-with-deadline
       (lambda ()
         (handler-case
             (multiple-value-bind (first-entry second-entry)
                 (sb-bsd-sockets:get-host-by-name host)
               (let ((entries '()))
                 (dolist (entry (list first-entry second-entry)
                                (nreverse entries))
                   (when entry
                     (let ((type (sb-bsd-sockets:host-ent-address-type entry)))
                       (dolist (address (sb-bsd-sockets:host-ent-addresses entry))
                         (push (list type address) entries)))))))
           (websocket-error (condition)
             (error condition))
           (error (condition)
             (%websocket-network-failure
              "The network host could not be resolved."
              :resolve
              :detail host
              :cause condition))))
       deadline clock :resolve)))

  (defun %websocket-native-address-text (type address)
    (cond
      ((= type +websocket-ipv4-address-type+)
       (format nil "~{~D~^.~}" (coerce address 'list)))
      ((= type +websocket-ipv6-address-type+)
       (format nil "~{~4,'0X~^:~}"
               (loop for index from 0 below (length address) by 2
                     collect (+ (ash (aref address index) 8)
                                (aref address (1+ index))))))
      (t
       (princ-to-string address))))

  (defun %websocket-native-address-family (type)
    (if (= type +websocket-ipv6-address-type+) :ipv6 :ipv4))

  (defun %websocket-native-socket-class (type)
    (if (= type +websocket-ipv6-address-type+)
        'sb-bsd-sockets:inet6-socket
        'sb-bsd-sockets:inet-socket))

  (defun %websocket-native-select-entry
      (host ipv6-p deadline clock-function)
    (if (null host)
        (if ipv6-p
            (list +websocket-ipv6-address-type+
                  (make-array 16 :element-type '(unsigned-byte 8)
                                 :initial-element 0))
            (list +websocket-ipv4-address-type+
                  (make-array 4 :element-type '(unsigned-byte 8)
                                 :initial-element 0)))
        (let* ((entries (%websocket-native-address-entries
                         host deadline clock-function))
               (preferred (if ipv6-p
                              +websocket-ipv6-address-type+
                              (if (find #\: host)
                                  +websocket-ipv6-address-type+
                                  +websocket-ipv4-address-type+))))
          (or (find preferred entries :key #'first)
              (first entries)
              (%websocket-network-failure
               "The network host has no usable address."
               :resolve
               :detail host)))))

  (defun %websocket-native-open-listener
      (host port backlog reuse-address ipv6-p deadline clock-function)
    (let* ((entry (%websocket-native-select-entry
                   host ipv6-p deadline clock-function))
           (type (first entry))
           (address (second entry))
           (socket nil)
           (retained-p nil))
      (unwind-protect
           (handler-case
               (progn
                 (setf socket
                       (make-instance (%websocket-native-socket-class type)
                                      :type :stream
                                      :protocol :tcp))
                 (when reuse-address
                   (setf (sb-bsd-sockets:sockopt-reuse-address socket) t))
                 (%websocket-call-with-deadline
                  (lambda ()
                    (sb-bsd-sockets:socket-bind socket address port)
                    (sb-bsd-sockets:socket-listen socket backlog))
                  deadline clock-function :listen)
                 (multiple-value-bind (bound-address bound-port)
                     (sb-bsd-sockets:socket-name socket)
                   (setf retained-p t)
                   (values socket
                           (%websocket-native-address-text type bound-address)
                           bound-port
                           (%websocket-native-address-family type))))
             (websocket-error (condition)
               (error condition))
             (error (condition)
               (%websocket-network-failure
                "The TCP listener could not be opened."
                :listen
                :detail host
                :cause condition)))
        (unless retained-p
          (when socket
            (%websocket-with-cleanup
              (sb-bsd-sockets:socket-close socket)))))))

  (defun %websocket-native-accept (socket deadline clock-function)
    (let ((accepted nil)
          (stream nil)
          (retained-p nil))
      (unwind-protect
           (handler-case
               (progn
                 (setf accepted
                       (%websocket-call-with-deadline
                        (lambda ()
                          (sb-bsd-sockets:socket-accept socket))
                        deadline clock-function :accept))
                 (setf stream
                       (sb-bsd-sockets:socket-make-stream
                        accepted
                        :input t
                        :output t
                        :element-type '(unsigned-byte 8)
                        :buffering :full))
                 (multiple-value-bind (peer-address peer-port)
                     (sb-bsd-sockets:socket-peername accepted)
                   (let ((peer-type (if (= (length peer-address) 4)
                                        +websocket-ipv4-address-type+
                                        +websocket-ipv6-address-type+)))
                     (setf retained-p t)
                     (values stream
                             (%websocket-native-address-text
                              peer-type peer-address)
                             peer-port))))
             (websocket-error (condition)
               (error condition))
             (error (condition)
               (%websocket-network-failure
                "The TCP listener could not accept a connection."
                :accept
                :cause condition)))
        (unless retained-p
          (when stream
            (%websocket-with-cleanup
              (close stream :abort t)))
          (when accepted
            (%websocket-with-cleanup
              (sb-bsd-sockets:socket-close accepted)))))))

  (defun %websocket-native-connect
      (host port deadline clock-function)
    (let ((last-condition nil))
      (dolist (entry (%websocket-native-address-entries
                      host deadline clock-function))
        (let* ((type (first entry))
               (address (second entry))
               (socket nil)
               (stream nil)
               (retained-p nil))
          (unwind-protect
               (handler-case
                   (progn
                     (setf socket
                           (make-instance (%websocket-native-socket-class type)
                                          :type :stream
                                          :protocol :tcp))
                     (%websocket-call-with-deadline
                      (lambda ()
                        (sb-bsd-sockets:socket-connect socket address port))
                      deadline clock-function :connect)
                     (setf stream
                           (sb-bsd-sockets:socket-make-stream
                            socket
                            :input t
                            :output t
                            :element-type '(unsigned-byte 8)
                            :buffering :full))
                     (setf retained-p t)
                     (return-from %websocket-native-connect
                       (values stream
                               (%websocket-native-address-text type address)
                               port)))
                 (websocket-timeout (condition)
                   (error condition))
                 (websocket-error (condition)
                   (setf last-condition condition))
                 (error (condition)
                   (setf last-condition condition)))
            (unless retained-p
              (when stream
                (%websocket-with-cleanup
                  (close stream :abort t)))
              (when socket
                (%websocket-with-cleanup
                  (sb-bsd-sockets:socket-close socket)))))))
      (%websocket-network-failure
       "The TCP connection could not be opened."
       :connect
       :detail host
       :cause last-condition)))

  (defun %websocket-native-resolve-host (host)
    (mapcar (lambda (entry)
              (destructuring-bind (type address) entry
                (list (%websocket-native-address-family type)
                      (%websocket-native-address-text type address))))
            (%websocket-native-address-entries host)))

  (defun %websocket-native-close-listener (socket)
    (sb-bsd-sockets:socket-close socket)))

#-sbcl
(progn
  (defun %websocket-native-open-listener
      (host port backlog reuse-address ipv6-p deadline clock-function)
    (declare (ignore host port backlog reuse-address ipv6-p deadline clock-function))
    (%websocket-network-failure
     "Native TCP transport is not implemented on this Lisp implementation."
     :listen))

  (defun %websocket-native-accept (socket deadline clock-function)
    (declare (ignore socket deadline clock-function))
    (%websocket-network-failure
     "Native TCP transport is not implemented on this Lisp implementation."
     :accept))

  (defun %websocket-native-connect
      (host port deadline clock-function)
    (declare (ignore host port deadline clock-function))
    (%websocket-network-failure
     "Native TCP transport is not implemented on this Lisp implementation."
     :connect))

  (defun %websocket-native-resolve-host (host)
    (declare (ignore host))
    (%websocket-network-failure
     "Native DNS resolution is not implemented on this Lisp implementation."
     :resolve))

  (defun %websocket-native-close-listener (socket)
    (declare (ignore socket))
    nil))

(defun %websocket-network-read-byte
    (stream deadline clock-function operation)
  (let ((byte (%websocket-call-with-deadline
               (lambda ()
                 (read-byte stream nil +websocket-unspecified+))
               deadline clock-function operation)))
    (if (eq byte +websocket-unspecified+)
        (%websocket-network-failure
         "The peer closed the network stream unexpectedly."
         operation)
        byte)))

(defun %websocket-network-read-octets
    (stream count deadline clock-function operation)
  (unless (and (integerp count) (<= 0 count))
    (%websocket-protocol-error
     "The number of network octets to read must be a non-negative integer."
     count))
  (let ((result (make-array count :element-type '(unsigned-byte 8))))
    (loop with position = 0
          while (< position count)
          do (let ((next-position
                     (%websocket-call-with-deadline
                      (lambda ()
                        (read-sequence result stream
                                       :start position
                                       :end count))
                      deadline clock-function operation)))
               (if (> next-position position)
                   (setf position next-position)
                   (%websocket-network-failure
                    "The peer closed the network stream unexpectedly."
                    operation)))
          finally (return result))))

(defun %websocket-network-write-octets
    (stream octets deadline clock-function operation)
  (unless (%websocket-byte-vector-p octets)
    (%websocket-protocol-error
     "Network output must be a one-dimensional vector of octets."
     octets))
  (%websocket-call-with-deadline
   (lambda ()
     (write-sequence octets stream)
     (force-output stream)
     octets)
   deadline clock-function operation))

(defun %websocket-network-close-stream (stream)
  (when stream
    (%websocket-with-cleanup
      (close stream :abort t)))
  nil)

(defun %websocket-network-header-name-equal-p (header name)
  (and (http-header-p header)
       (string-equal (http-header-name header) name)))

(defun %websocket-network-proxy-header-allowed-p (header)
  (not (some (lambda (name)
               (%websocket-network-header-name-equal-p header name))
             '("Host" "Proxy-Authorization" "Content-Length"
               "Transfer-Encoding" "Connection"))))

(defun %websocket-network-proxy-authorization (proxy)
  (when (or (websocket-proxy-username proxy)
            (websocket-proxy-password proxy))
    (let ((credentials
            (%websocket-network-octets
             (format nil "~A:~A"
                     (or (websocket-proxy-username proxy) "")
                     (or (websocket-proxy-password proxy) "")))))
      (make-http-header
       "Proxy-Authorization"
       (format nil "Basic ~A" (%websocket-base64-encode credentials))))))

(defparameter +websocket-max-informational-responses+ 16)

(defun %websocket-network-read-final-http-response
    (stream request &key deadline max-header-bytes max-fields max-body-bytes
                         clock-function)
  (loop with consumed-total = 0
        for informational-count from 0
        do (multiple-value-bind (response consumed)
               (read-http-response
                stream
                :deadline deadline
                :max-header-bytes max-header-bytes
                :max-fields max-fields
                :max-body-bytes max-body-bytes
                :request-method (http-request-method request)
                :collect-body-p nil
                :clock-function clock-function)
             (incf consumed-total consumed)
             (let ((status (http-response-status response)))
               (if (and (<= 100 status) (< status 200) (/= status 101))
                   (if (> (1+ informational-count)
                          +websocket-max-informational-responses+)
                       (%websocket-http-fail
                        "The peer sent too many informational responses."
                        :detail (1+ informational-count)
                        :operation :response)
                       nil)
                   (return (values response consumed-total)))))))

(defun %websocket-network-http-connect
    (stream proxy target-host target-port deadline clock-function
            &key max-header-bytes max-fields max-body-bytes)
  (let ((extra-headers (websocket-proxy-headers proxy)))
    (dolist (header extra-headers)
      (unless (%websocket-network-proxy-header-allowed-p header)
        (%websocket-protocol-error
         "HTTP proxy headers may not override CONNECT framing headers."
         (http-header-name header))))
    (let* ((authority (%websocket-network-authority target-host target-port))
           (request
             (make-http-request
              :method "CONNECT"
              :uri (parse-http-uri (format nil "http://~A/" authority))
              :request-target authority
              :headers
              (append
               (list (make-http-header "Host" authority))
               (when (%websocket-network-proxy-authorization proxy)
                 (list (%websocket-network-proxy-authorization proxy)))
               extra-headers)
              :body (make-array 0 :element-type '(unsigned-byte 8)))))
      (%websocket-call-with-deadline
       (lambda () (write-http-request request stream))
       deadline clock-function :proxy-connect-write)
      (let ((response
              (%websocket-call-with-deadline
               (lambda ()
                 (%websocket-network-read-final-http-response
                  stream request
                  :deadline deadline
                  :max-header-bytes max-header-bytes
                  :max-fields max-fields
                  :max-body-bytes max-body-bytes
                  :clock-function clock-function))
               deadline clock-function :proxy-connect-read)))
        (unless (and (http-response-p response)
                     (<= 200 (http-response-status response) 299))
          (%websocket-network-failure
           "The HTTP CONNECT proxy rejected the tunnel request."
           :proxy-connect
           :detail (and (http-response-p response)
                        (http-response-status response))
           :cause response)))))
  stream)

(defun %websocket-network-connection-open-p (connection)
  (unless (websocket-connection-p connection)
    (%websocket-protocol-error
     "A WebSocket connection object is required."
     connection))
  (when (or (websocket-connection-closed-p connection)
            (not (eq (websocket-connection-state connection) :open)))
    (%websocket-network-failure
     "The WebSocket connection is already closed."
     :connection-closed))
  (let ((stream (websocket-connection-stream connection)))
    (unless (streamp stream)
      (%websocket-network-failure
       "The WebSocket connection has no usable stream."
       :connection-stream))
    stream))

(defmacro %websocket-network-with-write-lock ((connection) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-connection-write-lock ,connection))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defmacro %websocket-network-with-read-lock ((connection) &body body)
  #+sbcl
  `(sb-thread:with-mutex
       ((websocket-connection-read-lock ,connection))
     ,@body)
  #-sbcl
  `(progn ,@body))

(defun %websocket-network-mark-closed
    (connection &key code reason condition)
  (let ((listener (websocket-connection-listener connection)))
    (if listener
        (%websocket-network-with-listener-lock (listener)
          (unless (websocket-connection-closed-p connection)
            (setf (websocket-connection-state connection) :closed
                  (websocket-connection-closed-p connection) t
                  (websocket-connection-close-code connection) code
                  (websocket-connection-close-reason connection) reason
                  (websocket-connection-close-condition connection) condition)
            (%websocket-network-remove-connection-locked
             listener connection)))
        (unless (websocket-connection-closed-p connection)
          (setf (websocket-connection-state connection) :closed
                (websocket-connection-closed-p connection) t
                (websocket-connection-close-code connection) code
                (websocket-connection-close-reason connection) reason
                (websocket-connection-close-condition connection) condition))))
  connection)

(defun %websocket-network-abort-connection (connection condition)
  (when (websocket-connection-p connection)
    (let ((stream (websocket-connection-stream connection)))
      (%websocket-network-mark-closed
       connection :condition condition)
      (%websocket-network-close-stream stream)))
  nil)

(defun %websocket-network-force-close-connection (connection)
  (when (websocket-connection-p connection)
    (let ((stream (websocket-connection-stream connection)))
      (%websocket-network-mark-closed connection)
      (%websocket-network-close-stream stream)))
  nil)

(defun %websocket-network-output-key-function
    (mask-p masking-key masking-key-function)
  (if (and mask-p (null masking-key) (null masking-key-function))
      #'%websocket-random-masking-key
      masking-key-function))

(defun websocket-send
    (connection payload &key (opcode 2)
                           (max-message-bytes +websocket-default-max-payload-bytes+)
                           (max-frame-payload-bytes 65535)
                           masking-key masking-key-function
                           (finish-output-p t)
                           (payload-encoder +websocket-unspecified+)
                           (reserved-bits +websocket-unspecified+)
                           timeout deadline
                           (clock-function #'%websocket-monotonic-time))
  "Send one text or binary WebSocket message on CONNECTION.

The masking policy is selected when the connection is created.  Client-side
connections mask by default; server-side connections do not.  The encoded
message is limited by MAX-MESSAGE-BYTES before it is written."
  (unless (websocket-connection-p connection)
    (%websocket-protocol-error
     "A WebSocket connection object is required."
     connection))
  (let* ((effective-payload-encoder
           (if (eq payload-encoder +websocket-unspecified+)
               (websocket-connection-payload-encoder connection)
               payload-encoder))
         (effective-reserved-bits
           (if (eq reserved-bits +websocket-unspecified+)
               (websocket-connection-payload-reserved-bits connection)
               reserved-bits))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock-function)))
    (%websocket-validate-payload-transformer
     effective-payload-encoder "PAYLOAD-ENCODER")
    (%websocket-validate-reserved-bits
     effective-reserved-bits "RESERVED-BITS")
    (handler-case
        (%websocket-network-with-write-lock (connection)
          (let* ((stream (%websocket-network-connection-open-p connection))
                 (mask-p (websocket-connection-local-mask-p connection)))
            (write-websocket-message
             stream payload
             :opcode opcode
             :max-message-bytes max-message-bytes
             :max-frame-payload-bytes max-frame-payload-bytes
             :mask-p mask-p
             :masking-key masking-key
             :masking-key-function
             (%websocket-network-output-key-function
              mask-p masking-key masking-key-function)
             :finish-output-p finish-output-p
             :payload-encoder effective-payload-encoder
             :reserved-bits effective-reserved-bits
             :deadline effective-deadline
             :clock-function clock-function)))
      (websocket-transport-error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition))
      (websocket-error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition))
      (error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition)))))

(defun websocket-receive
    (connection &key
                (max-message-bytes +websocket-default-max-payload-bytes+)
                (max-payload-bytes +websocket-default-max-payload-bytes+)
                (max-fragments +websocket-default-max-fragments+)
                (max-control-frames +websocket-default-max-control-frames+)
                (allowed-reserved-bits +websocket-unspecified+)
                (payload-decoder +websocket-unspecified+)
                on-control timeout deadline
                (clock-function #'%websocket-monotonic-time))
  "Receive one data message or a peer Close from CONNECTION.

Ping frames are answered with Pong and a peer Close is echoed before the
connection is closed.  ON-CONTROL is called after the automatic response and
after the receive lock is released.
PAYLOAD-DECODER defaults to the connection's configured decoder and receives
each data-frame payload and frame.  Negotiated permessage-deflate frames are
also checked for their RSV1 placement before decoding.  Concurrent receive
operations on one connection are serialized."
  (unless (websocket-connection-p connection)
    (%websocket-protocol-error
     "A WebSocket connection object is required."
     connection))
  (let ((control-frames nil)
        (result nil))
    (setf result
          (multiple-value-list
           (%websocket-network-with-read-lock (connection)
             (handler-case
                 (let* ((stream (%websocket-network-connection-open-p
                                 connection))
                        (mask-p
                          (websocket-connection-local-mask-p connection))
                        (peer-mask-required-p
                          (websocket-connection-peer-mask-required-p
                           connection))
                        (effective-allowed-reserved-bits
                          (if (eq allowed-reserved-bits
                                  +websocket-unspecified+)
                              (websocket-connection-payload-reserved-bits
                               connection)
                              allowed-reserved-bits))
                        (effective-payload-decoder
                          (if (eq payload-decoder +websocket-unspecified+)
                              (websocket-connection-payload-decoder
                               connection)
                              payload-decoder))
                        (frame-validator
                          (%websocket-network-permessage-deflate-frame-validator
                           (websocket-connection-selected-extensions
                            connection)
                           effective-payload-decoder))
                        (effective-deadline
                          (%websocket-effective-deadline
                           timeout deadline clock-function))
                        (close-tag (gensym "WEBSOCKET-RECEIVE-CLOSE-"))
                        (close-marker
                          (gensym "WEBSOCKET-RECEIVE-CLOSE-MARKER-")))
                   (unless (functionp clock-function)
                     (%websocket-protocol-error
                      "CLOCK-FUNCTION must be callable."
                      clock-function))
                   (when (and on-control (not (functionp on-control)))
                     (%websocket-protocol-error
                      "ON-CONTROL must be callable when supplied."
                      on-control))
                   (%websocket-validate-reserved-bits
                    effective-allowed-reserved-bits "ALLOWED-RESERVED-BITS")
                   (%websocket-validate-payload-transformer
                    effective-payload-decoder "PAYLOAD-DECODER")
                   (labels ((output-key-function (key key-function)
                              (%websocket-network-output-key-function
                               mask-p key key-function))
                            (handle-control (frame)
                              (when on-control
                                (push frame control-frames))
                              (case (websocket-frame-opcode frame)
                                (9
                                 (%websocket-network-with-write-lock
                                     (connection)
                                   (websocket-pong
                                    (%websocket-network-connection-open-p
                                     connection)
                                    :payload
                                    (websocket-frame-payload frame)
                                    :mask-p mask-p
                                    :masking-key-function
                                    (output-key-function nil nil)
                                    :deadline effective-deadline
                                    :clock-function clock-function)))
                                (8
                                 (let ((payload
                                         (websocket-frame-payload frame)))
                                   (multiple-value-bind
                                         (close-code close-reason)
                                       (parse-websocket-close-payload payload)
                                     (unwind-protect
                                          (progn
                                            (%websocket-network-with-write-lock
                                                (connection)
                                              (websocket-close
                                               (%websocket-network-connection-open-p
                                                connection)
                                               :payload payload
                                               :mask-p mask-p
                                               :masking-key-function
                                               (output-key-function nil nil)
                                               :deadline effective-deadline
                                               :clock-function clock-function))
                                            (%websocket-network-mark-closed
                                             connection
                                             :code close-code
                                             :reason close-reason)
                                            (throw close-tag
                                                   (list close-marker payload)))
                                       (%websocket-network-mark-closed
                                        connection
                                        :code close-code
                                        :reason close-reason)
                                       (%websocket-network-close-stream
                                        stream)))))
                                (10 nil))))
                     (let ((read-result
                             (catch close-tag
                               (multiple-value-list
                                (%websocket-call-with-deadline
                                 (lambda ()
                                   (read-websocket-message
                                    stream
                                    :max-message-bytes max-message-bytes
                                    :max-payload-bytes max-payload-bytes
                                    :max-fragments max-fragments
                                    :max-control-frames max-control-frames
                                    :allowed-reserved-bits
                                    effective-allowed-reserved-bits
                                    :require-mask-p peer-mask-required-p
                                    :allow-unmasked-p (not peer-mask-required-p)
                                    :require-unmasked-p nil
                                    :on-control #'handle-control
                                    :payload-decoder effective-payload-decoder
                                    :frame-validator frame-validator))
                                 effective-deadline clock-function
                                 :websocket-receive)))))
                       (if (and (consp read-result)
                                (eq (first read-result) close-marker))
                           (values (second read-result) :close)
                           (values (first read-result)
                                   (second read-result))))))
               (websocket-transport-error (condition)
                 (%websocket-network-abort-connection connection condition)
                 (error condition))
               (websocket-error (condition)
                 (%websocket-network-abort-connection connection condition)
                 (error condition))
               (error (condition)
                 (%websocket-network-abort-connection connection condition)
                 (error condition))))))
    (handler-case
        (progn
          (when on-control
            (dolist (frame (nreverse control-frames))
              (funcall on-control frame)))
          (values-list result))
      (websocket-transport-error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition))
      (websocket-error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition))
      (error (condition)
        (%websocket-network-abort-connection connection condition)
        (error condition)))))

(defun close-websocket-connection
    (connection &key (send-close-p t) payload code reason masking-key
                           masking-key-function (finish-output-p t)
                           timeout deadline
                           (clock-function #'%websocket-monotonic-time))
  "Close CONNECTION, optionally sending a WebSocket Close frame first.

The stream is closed even when sending the Close frame signals an error."
  (unless (member send-close-p '(nil t))
    (%websocket-protocol-error
     "SEND-CLOSE-P must be a generalized boolean."
     send-close-p))
  (unless (websocket-connection-p connection)
    (%websocket-protocol-error
     "A WebSocket connection object is required."
     connection))
  (let ((effective-deadline
          (%websocket-effective-deadline timeout deadline clock-function)))
    (if (not send-close-p)
        (%websocket-network-force-close-connection connection)
        (%websocket-network-with-write-lock (connection)
          (if (websocket-connection-closed-p connection)
              nil
              (let* ((stream (%websocket-network-connection-open-p connection))
                     (mask-p (websocket-connection-local-mask-p connection)))
                (let ((close-code nil)
                      (close-reason nil)
                      (failure nil))
                  (unwind-protect
                       (handler-bind
                           ((error (lambda (condition)
                                     (setf failure condition))))
                         (multiple-value-setq (close-code close-reason)
                           (if payload
                               (parse-websocket-close-payload payload)
                               (values (or code 1000) (or reason ""))))
                         (setf (websocket-connection-state connection) :closing)
                         (websocket-close
                          stream
                          :payload payload
                          :code code
                          :reason reason
                          :mask-p mask-p
                          :masking-key masking-key
                          :masking-key-function
                          (%websocket-network-output-key-function
                           mask-p masking-key masking-key-function)
                          :finish-output-p finish-output-p
                          :deadline effective-deadline
                          :clock-function clock-function))
                    (%websocket-network-mark-closed
                     connection
                     :code close-code
                     :reason close-reason
                     :condition failure)
                    (%websocket-network-close-stream stream))
                  t)))))))

(defun %websocket-tls-package ()
  (or (find-package :cl+ssl)
      (progn
        (ignore-errors (require :cl+ssl))
        (find-package :cl+ssl))))

(defun %websocket-tls-function (name)
  (let* ((package (%websocket-tls-package))
         (symbol (and package (find-symbol name package))))
    (if (and symbol (fboundp symbol))
        (symbol-function symbol)
        (%websocket-network-failure
         "The requested TLS operation is unavailable because cl+ssl is not loaded."
         :tls
         :detail name))))

(defun %websocket-valid-tls-verify-p (verify)
  (member verify '(nil :optional :required) :test #'eq))

(defun %websocket-valid-alpn-protocols-p (protocols)
  (or (null protocols)
      (and (listp protocols)
           (every (lambda (protocol)
                   (and (stringp protocol)
                        (<= 1 (length protocol) 255)
                        (every (lambda (character)
                                (<= 1 (char-code character) 127))
                               protocol)))
                 protocols))))

(defun %websocket-valid-certificate-pair-p (certificate key required-p)
  (if required-p
      (and certificate key)
      (or (and certificate key)
          (and (null certificate) (null key)))))

(defun make-websocket-tls-upgrader
    (&key (verify :required) alpn-protocols certificate key password
          (unwrap-stream-p nil)
          (clock-function #'%websocket-monotonic-time))
  "Return a client TLS-upgrade callback backed by cl+ssl.

The callback receives a binary STREAM and HTTP URI, and accepts TIMEOUT and
DEADLINE keyword arguments. VERIFY may be NIL, :OPTIONAL, or :REQUIRED.
Custom TLS callbacks may return the selected ALPN protocol as a second value."
  (unless (%websocket-valid-tls-verify-p verify)
    (%websocket-protocol-error
     "TLS VERIFY must be NIL, :OPTIONAL, or :REQUIRED."
     verify))
  (unless (%websocket-valid-alpn-protocols-p alpn-protocols)
    (%websocket-protocol-error
     "TLS ALPN protocol names must contain 1 to 255 ASCII characters."
     alpn-protocols))
  (unless (%websocket-valid-certificate-pair-p certificate key nil)
    (%websocket-protocol-error
     "TLS client certificates require both CERTIFICATE and KEY."
     (list :certificate certificate :key key)))
  (unless (functionp clock-function)
    (%websocket-protocol-error
     "TLS CLOCK-FUNCTION must be callable."
     clock-function))
  (let ((make-client-stream (%websocket-tls-function "MAKE-SSL-CLIENT-STREAM")))
    (lambda (stream uri &key timeout deadline &allow-other-keys)
      (unless (streamp stream)
        (%websocket-protocol-error
         "TLS upgrade requires a Lisp stream."
         stream))
      (let* ((http-uri (%websocket-network-uri uri))
             (effective-deadline
               (%websocket-effective-deadline
                timeout deadline clock-function)))
        (%websocket-call-with-deadline
         (lambda ()
           (funcall make-client-stream
                    stream
                    :unwrap-stream-p unwrap-stream-p
                    :hostname (http-uri-host http-uri)
                    :external-format nil
                    :verify verify
                    :alpn-protocols alpn-protocols
                    :certificate certificate
                    :key key
                    :password password))
         effective-deadline clock-function :tls)))))

(defun make-websocket-tls-server-wrapper
    (&key certificate key password (alpn-protocols '("http/1.1"))
          (unwrap-stream-p nil)
          (clock-function #'%websocket-monotonic-time))
  "Return a server callback that upgrades an accepted stream to TLS.

CERTIFICATE and KEY are required because a server cannot complete a TLS
handshake without an identity. The callback returns the selected ALPN
protocol as a second value when cl+ssl reports one."
  (unless (%websocket-valid-certificate-pair-p certificate key t)
    (%websocket-protocol-error
     "TLS server certificates require both CERTIFICATE and KEY."
     (list :certificate certificate :key key)))
  (unless (%websocket-valid-alpn-protocols-p alpn-protocols)
    (%websocket-protocol-error
     "TLS ALPN-PROTOCOLS must be a list of non-empty ASCII protocol names."
     alpn-protocols))
  (when (and alpn-protocols
             (not (member "http/1.1" alpn-protocols :test #'string=)))
    (%websocket-protocol-error
     "TLS server ALPN-PROTOCOLS must include HTTP/1.1."
     alpn-protocols))
  (unless (functionp clock-function)
    (%websocket-protocol-error
     "TLS CLOCK-FUNCTION must be callable."
     clock-function))
  (let ((make-server-stream (%websocket-tls-function "MAKE-SSL-SERVER-STREAM")))
    (lambda (stream &key timeout deadline &allow-other-keys)
      (unless (streamp stream)
        (%websocket-protocol-error
         "TLS upgrade requires a Lisp stream."
         stream))
      (let ((effective-deadline
              (%websocket-effective-deadline
               timeout deadline clock-function)))
        (let ((tls-stream
                (%websocket-call-with-deadline
                 (lambda ()
                   (funcall make-server-stream
                            stream
                            :unwrap-stream-p unwrap-stream-p
                            :external-format nil
                            :alpn-protocols alpn-protocols
                            :certificate certificate
                            :key key
                            :password password))
                 effective-deadline clock-function :tls)))
          (values tls-stream
                  (websocket-tls-selected-alpn-protocol tls-stream)))))))

(defun websocket-tls-selected-alpn-protocol (stream)
  "Return the ALPN protocol selected on STREAM, or NIL when unavailable."
  (unless (streamp stream)
    (%websocket-protocol-error
     "TLS ALPN lookup requires a Lisp stream."
     stream))
  (let ((function (%websocket-tls-function "GET-SELECTED-ALPN-PROTOCOL")))
    (funcall function stream)))

(defun %websocket-network-apply-tls
    (stream uri tls-upgrader deadline clock-function)
  (unless (functionp tls-upgrader)
    (%websocket-protocol-error
     "TLS-UPGRADER must be callable."
     tls-upgrader))
  (multiple-value-bind (upgraded-stream selected-alpn)
      (funcall tls-upgrader stream uri
               :timeout nil
               :deadline deadline
               :clock-function clock-function)
    (unless (streamp upgraded-stream)
      (%websocket-network-failure
       "The TLS upgrader did not return a stream."
       :tls
       :detail upgraded-stream))
    (values upgraded-stream selected-alpn)))

(defun %websocket-network-validate-tls-alpn-value (selected)
  (unless (or (null selected)
              (and (stringp selected)
                   (string= selected "http/1.1")))
    (%websocket-network-failure
     "TLS selected an unsupported application protocol."
     :tls
     :detail selected))
  selected)

(defun %websocket-network-validate-tls-alpn (stream)
  (%websocket-network-validate-tls-alpn-value
   (websocket-tls-selected-alpn-protocol stream)))

(defun %websocket-network-client-sender
    (request stream &key timeout deadline max-header-bytes max-fields max-body-bytes
               collect-body-p clock-function &allow-other-keys)
  (declare (ignore collect-body-p))
  (let ((clock (%websocket-network-clock clock-function))
        (effective-deadline
          (%websocket-effective-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
       (write-http-request request stream)
       (%websocket-network-read-final-http-response
        stream request
        :deadline effective-deadline
        :max-header-bytes max-header-bytes
        :max-fields max-fields
        :max-body-bytes max-body-bytes
        :clock-function clock))
     effective-deadline clock :client-handshake)))

(defun connect-websocket
    (uri &key protocols extensions headers proxy key random-function
         extension-selection-policy
         timeout deadline max-header-bytes
         (max-fields +websocket-default-max-header-fields+)
         max-body-bytes
         tls-upgrader (tls-verify :required)
         (tls-alpn-protocols '("http/1.1"))
         tls-certificate tls-key tls-password
         (local-mask-p t) (peer-mask-required-p t)
         payload-encoder payload-decoder (payload-reserved-bits 0)
         (clock-function #'%websocket-monotonic-time))
  "Open a TCP or TLS WebSocket client connection for URI.

PROXY may be an HTTP CONNECT or SOCKS5 configuration. The returned
WEBSOCKET-CONNECTION owns its stream; use CLOSE-WEBSOCKET-CONNECTION when the
session ends. Client data frames are masked by default and peer frames are
required to be masked by default. PAYLOAD-ENCODER and PAYLOAD-DECODER may be
used for a negotiated extension transformation; PAYLOAD-RESERVED-BITS enables
the corresponding RSV bits on outgoing messages and as the default receive
permission. EXTENSION-SELECTION-POLICY may implement extension parameter
negotiation; selected extension names must still have been offered."
  (let* ((clock (%websocket-network-clock clock-function))
         (input-uri (%websocket-network-uri uri))
         (secure-p (member (string-downcase (%websocket-uri-scheme uri))
                           '("https" "wss") :test #'string=))
         (host (%websocket-network-validate-host
                (http-uri-host input-uri)))
         (port (%websocket-network-validate-port
                (%websocket-network-port input-uri)))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock))
         (request nil)
         (stream nil)
         (raw-stream nil)
         (retained-p nil))
    (unless (or (null protocols) (listp protocols))
      (%websocket-protocol-error
       "WebSocket PROTOCOLS must be a list or NIL."
       protocols))
    (unless (or (null extensions) (stringp extensions))
      (%websocket-protocol-error
       "WebSocket EXTENSIONS must be a string or NIL."
       extensions))
    (when extension-selection-policy
      (unless (functionp extension-selection-policy)
        (%websocket-protocol-error
         "EXTENSION-SELECTION-POLICY must be callable or NIL."
         extension-selection-policy)))
    (unless (or (null proxy) (websocket-proxy-p proxy))
      (%websocket-protocol-error
       "PROXY must be a WEBSOCKET-PROXY or NIL."
       proxy))
    (unless (or (null local-mask-p) (eq local-mask-p t))
      (%websocket-protocol-error
       "LOCAL-MASK-P must be generalized boolean."
       local-mask-p))
    (unless (or (null peer-mask-required-p) (eq peer-mask-required-p t))
      (%websocket-protocol-error
       "PEER-MASK-REQUIRED-P must be generalized boolean."
       peer-mask-required-p))
    (%websocket-validate-payload-transformer
     payload-encoder "PAYLOAD-ENCODER")
    (%websocket-validate-payload-transformer
     payload-decoder "PAYLOAD-DECODER")
    (%websocket-validate-reserved-bits
     payload-reserved-bits "PAYLOAD-RESERVED-BITS")
    (%websocket-network-validate-extension-transformer
     extensions payload-encoder payload-decoder payload-reserved-bits)
    (when tls-upgrader
      (unless (functionp tls-upgrader)
        (%websocket-protocol-error
         "TLS-UPGRADER must be callable or NIL."
         tls-upgrader)))
    (when secure-p
      (unless (%websocket-valid-tls-verify-p tls-verify)
        (%websocket-protocol-error
         "TLS-VERIFY must be NIL, :OPTIONAL, or :REQUIRED."
         tls-verify))
      (unless (%websocket-valid-alpn-protocols-p tls-alpn-protocols)
        (%websocket-protocol-error
         "TLS ALPN protocol names must contain 1 to 255 ASCII characters."
         tls-alpn-protocols))
      (when (and tls-alpn-protocols
                 (not (member "http/1.1" tls-alpn-protocols
                              :test #'string=)))
        (%websocket-protocol-error
         "TLS ALPN protocols must include HTTP/1.1."
         tls-alpn-protocols)))
    (unwind-protect
         (progn
           (multiple-value-bind (opened-stream peer-address peer-port)
             (%websocket-native-connect
                (if proxy (websocket-proxy-host proxy) host)
                (if proxy (websocket-proxy-port proxy) port)
                effective-deadline clock)
             (setf stream opened-stream)
             (setf raw-stream opened-stream)
             (when proxy
               (when (websocket-proxy-tls-upgrader proxy)
                 (multiple-value-bind (proxy-stream selected-alpn)
                     (%websocket-network-apply-tls
                      stream
                      (%websocket-network-proxy-uri proxy)
                      (websocket-proxy-tls-upgrader proxy)
                      effective-deadline clock)
                   (declare (ignore selected-alpn))
                   (setf stream proxy-stream)))
               (ecase (websocket-proxy-type proxy)
                 (:http-connect
                 (%websocket-network-http-connect
                   stream proxy host port effective-deadline clock
                   :max-header-bytes max-header-bytes
                   :max-fields max-fields
                   :max-body-bytes max-body-bytes))
                 (:socks5
                  (%websocket-network-socks5-connect
                   stream proxy host port effective-deadline clock))))
             (when (or secure-p tls-upgrader)
               (multiple-value-bind (upgraded-stream selected-alpn)
                   (%websocket-network-apply-tls
                    stream input-uri
                    (or tls-upgrader
                        (make-websocket-tls-upgrader
                         :verify tls-verify
                         :alpn-protocols tls-alpn-protocols
                         :certificate tls-certificate
                         :key tls-key
                         :password tls-password
                         :clock-function clock))
                    effective-deadline clock)
                 (setf stream upgraded-stream)
                 (when (and tls-upgrader selected-alpn)
                   (%websocket-network-validate-tls-alpn-value
                    selected-alpn))))
             (when (and secure-p (null tls-upgrader))
               (%websocket-network-validate-tls-alpn stream))
             (setf request
                   (make-websocket-upgrade-request
                    uri
                    :key (or key (generate-websocket-key random-function))
                    :protocols protocols
                    :extensions extensions
                    :headers headers))
             (multiple-value-bind (response reusable-p)
                 (websocket-client-handshake
                  stream request #'%websocket-network-client-sender
                  :deadline effective-deadline
                  :max-header-bytes max-header-bytes
                  :max-fields max-fields
                  :max-body-bytes max-body-bytes
                  :extension-selection-policy extension-selection-policy
                  :clock-function clock)
               (declare (ignore reusable-p))
               (let ((selected-extensions
                       (%websocket-single-header-value
                        (http-response-headers response)
                        "Sec-WebSocket-Extensions")))
                 (%websocket-network-validate-extension-transformer
                  selected-extensions payload-encoder payload-decoder
                  payload-reserved-bits)
                 (setf retained-p t)
                 (%make-websocket-connection
                  stream request response
                  (%websocket-single-header-value
                   (http-response-headers response)
                   "Sec-WebSocket-Protocol")
                  selected-extensions
                  peer-address peer-port local-mask-p peer-mask-required-p
                  payload-encoder payload-decoder payload-reserved-bits)))))
      (unless retained-p
        (%websocket-network-close-stream-pair stream raw-stream)))))

(defun open-websocket-client (uri &rest arguments)
  "Compatibility alias for CONNECT-WEBSOCKET."
  (apply #'connect-websocket uri arguments))

(defun %websocket-network-socks5-host (host)
  (if (and (plusp (length host))
           (char= (char host 0) #\[)
           (char= (char host (1- (length host))) #\]))
      (subseq host 1 (1- (length host)))
      host))

(defun %websocket-network-decimal-octet (string start end)
  (when (= start end)
    (return-from %websocket-network-decimal-octet (values nil nil)))
  (let ((value 0))
    (loop for index from start below end
          for code = (char-code (char string index))
          unless (<= (char-code #\0) code (char-code #\9))
            do (return-from %websocket-network-decimal-octet
                 (values nil nil))
          do (setf value (+ (* value 10) (- code (char-code #\0))))
             (when (> value 255)
               (return-from %websocket-network-decimal-octet
                 (values nil nil))))
    (values value t)))

(defun %websocket-network-ipv4-octets (host)
  (let ((octets '())
        (start 0)
        (length (length host)))
    (loop for index from 0 to length
          when (or (= index length)
                   (char= (char host index) #\.))
            do (multiple-value-bind (octet valid-p)
                   (%websocket-network-decimal-octet host start index)
                 (unless valid-p
                   (return-from %websocket-network-ipv4-octets nil))
                 (push octet octets)
                 (setf start (1+ index))))
    (when (= 4 (length octets))
      (coerce (nreverse octets) '(vector (unsigned-byte 8))))))

(defun %websocket-network-hex-group (string)
  (let ((length (length string)))
    (when (or (zerop length) (> length 4))
      (return-from %websocket-network-hex-group nil))
    (let ((value 0))
      (loop for character across string
            for digit = (digit-char-p character 16)
            unless digit
              do (return-from %websocket-network-hex-group nil)
            do (setf value (+ (* value 16) digit)))
      value)))

(defun %websocket-network-split-colon-groups (string)
  (when (zerop (length string))
    (return-from %websocket-network-split-colon-groups '()))
  (let ((groups '())
        (start 0)
        (length (length string)))
    (loop for index from 0 to length
          when (or (= index length)
                   (char= (char string index) #\:))
            do (when (= start index)
                 (return-from %websocket-network-split-colon-groups nil))
               (push (subseq string start index) groups)
               (setf start (1+ index)))
    (nreverse groups)))

(defun %websocket-network-ipv6-octets (host)
  (unless (find #\: host)
    (return-from %websocket-network-ipv6-octets nil))
  (let* ((double-colon (search "::" host))
         (left (if double-colon
                   (subseq host 0 double-colon)
                   host))
         (right (if double-colon
                    (subseq host (+ double-colon 2))
                    "")))
    (when (and double-colon
               (search "::" host :start2 (+ double-colon 2)))
      (return-from %websocket-network-ipv6-octets nil))
    (let ((left-groups (%websocket-network-split-colon-groups left))
          (right-groups (%websocket-network-split-colon-groups right)))
      (when (or (null left-groups) (null right-groups))
        (unless (and (or (zerop (length left))
                         (plusp (length left-groups)))
                     (or (zerop (length right))
                         (plusp (length right-groups))))
          (return-from %websocket-network-ipv6-octets nil)))
      (let ((groups (append left-groups right-groups))
            (expanded-groups '())
            (ipv4-seen-p nil))
        (loop for remaining on groups
              for group = (car remaining)
              for last-p = (endp (cdr remaining))
              do (if (find #\. group)
                     (progn
                       (unless (and last-p (not ipv4-seen-p))
                         (return-from %websocket-network-ipv6-octets nil))
                       (let ((ipv4 (%websocket-network-ipv4-octets group)))
                         (unless ipv4
                           (return-from %websocket-network-ipv6-octets nil))
                         (push (+ (* (aref ipv4 0) 256)
                                  (aref ipv4 1))
                               expanded-groups)
                         (push (+ (* (aref ipv4 2) 256)
                                  (aref ipv4 3))
                               expanded-groups)
                         (setf ipv4-seen-p t)))
                     (let ((value (%websocket-network-hex-group group)))
                       (unless value
                         (return-from %websocket-network-ipv6-octets nil))
                       (push value expanded-groups))))
        (setf expanded-groups (nreverse expanded-groups))
        (when (if double-colon
                  (>= (length expanded-groups) 8)
                  (/= (length expanded-groups) 8))
          (return-from %websocket-network-ipv6-octets nil))
        (let ((groups
                (if double-colon
                    (let ((missing (- 8 (length expanded-groups)))
                          (left-count (length left-groups)))
                      (append (subseq expanded-groups 0 left-count)
                              (make-list missing :initial-element 0)
                              (subseq expanded-groups left-count)))
                    expanded-groups))
              (octets (make-array 16 :element-type '(unsigned-byte 8))))
          (loop for group in groups
                for index from 0 by 2
                do (setf (aref octets index) (ldb (byte 8 8) group)
                         (aref octets (1+ index)) (ldb (byte 8 0) group)))
          octets)))))

(defun %websocket-network-socks5-address (host)
  (let ((host (%websocket-network-socks5-host host)))
    (let ((octets (%websocket-network-ipv4-octets host)))
      (when octets
        (return-from %websocket-network-socks5-address
          (values 1 octets))))
    (let ((octets (%websocket-network-ipv6-octets host)))
      (when octets
        (return-from %websocket-network-socks5-address
          (values 4 octets))))
    (when (find #\: host)
      (%websocket-protocol-error
       "A SOCKS5 IPv6 address is invalid."
       host))
    (let ((octets (%websocket-network-octets host)))
      (unless (<= 1 (length octets) 255)
        (%websocket-protocol-error
         "A SOCKS5 domain name must contain between 1 and 255 octets."
         (length octets)))
      (values 3 octets))))

(defun %websocket-network-socks5-authenticate
    (stream proxy deadline clock-function)
  (let* ((username (websocket-proxy-username proxy))
         (password (websocket-proxy-password proxy))
         (offer-auth-p (or username password))
         (methods (make-array (if offer-auth-p 2 1)
                              :element-type '(unsigned-byte 8))))
    (setf (aref methods 0) 0)
    (when offer-auth-p
      (setf (aref methods 1) 2))
    (%websocket-network-write-octets
     stream
     (let ((message (make-array (+ 2 (length methods))
                                :element-type '(unsigned-byte 8))))
       (setf (aref message 0) 5
             (aref message 1) (length methods))
       (replace message methods :start1 2)
       message)
     deadline clock-function :socks5-greeting-write)
    (let ((reply (%websocket-network-read-octets
                  stream 2 deadline clock-function :socks5-greeting-read)))
      (unless (= (aref reply 0) 5)
        (%websocket-network-failure
         "The SOCKS5 proxy returned an invalid greeting version."
         :socks5-greeting
         :detail (aref reply 0)))
      (case (aref reply 1)
        (0 nil)
        (2
         (unless offer-auth-p
           (%websocket-network-failure
            "The SOCKS5 proxy requires authentication."
            :socks5-authentication))
         (let* ((user-octets (%websocket-network-octets (or username "")))
                (password-octets (%websocket-network-octets (or password ""))))
           (unless (and (<= 1 (length user-octets) 255)
                        (<= 1 (length password-octets) 255))
             (%websocket-protocol-error
              "SOCKS5 credentials must fit in one-octet lengths."
              (list (length user-octets) (length password-octets))))
           (let ((message (make-array (+ 3 (length user-octets)
                                      (length password-octets))
                                      :element-type '(unsigned-byte 8))))
             (setf (aref message 0) 1
                   (aref message 1) (length user-octets))
             (replace message user-octets :start1 2)
             (setf (aref message (+ 2 (length user-octets)))
                   (length password-octets))
             (replace message password-octets
                      :start1 (+ 3 (length user-octets)))
             (%websocket-network-write-octets
              stream message deadline clock-function
              :socks5-authentication-write))
           (let ((auth-reply (%websocket-network-read-octets
                              stream 2 deadline clock-function
                              :socks5-authentication-read)))
             (unless (and (= (aref auth-reply 0) 1)
                          (zerop (aref auth-reply 1)))
               (%websocket-network-failure
                "SOCKS5 username/password authentication failed."
                :socks5-authentication
                :detail (aref auth-reply 1))))))
        (t
         (%websocket-network-failure
          "The SOCKS5 proxy selected an unsupported authentication method."
          :socks5-authentication
          :detail (aref reply 1)))))))

(defun %websocket-network-socks5-read-address
    (stream address-type deadline clock-function)
  (case address-type
    (1 (%websocket-network-read-octets
        stream 4 deadline clock-function :socks5-reply-address))
    (3 (let ((length (aref (%websocket-network-read-octets
                            stream 1 deadline clock-function
                            :socks5-reply-address)
                           0)))
         (unless (plusp length)
           (%websocket-network-failure
            "The SOCKS5 proxy returned an empty domain address."
            :socks5-reply-address
            :detail length))
         (%websocket-network-read-octets
          stream length deadline clock-function :socks5-reply-address)))
    (4 (%websocket-network-read-octets
        stream 16 deadline clock-function :socks5-reply-address))
    (t (%websocket-network-failure
        "The SOCKS5 proxy returned an unsupported address type."
        :socks5-reply-address
        :detail address-type))))

(defun %websocket-network-socks5-connect
    (stream proxy target-host target-port deadline clock-function)
  (%websocket-network-socks5-authenticate stream proxy deadline clock-function)
  (multiple-value-bind (address-type address-octets)
      (%websocket-network-socks5-address target-host)
    (let* ((length (length address-octets))
           (address-start (if (= address-type 3) 5 4))
           (port-start (+ address-start length))
           (message (make-array (+ port-start 2)
                                :element-type '(unsigned-byte 8))))
      (setf (aref message 0) 5
            (aref message 1) 1
            (aref message 2) 0
            (aref message 3) address-type)
      (when (= address-type 3)
        (setf (aref message 4) length))
      (replace message address-octets :start1 address-start)
      (setf (aref message port-start) (ldb (byte 8 8) target-port)
            (aref message (1+ port-start)) (ldb (byte 8 0) target-port))
      (%websocket-network-write-octets
       stream message deadline clock-function :socks5-connect-write))
    (let ((reply (%websocket-network-read-octets
                  stream 4 deadline clock-function :socks5-connect-read)))
      (unless (= (aref reply 0) 5)
        (%websocket-network-failure
         "The SOCKS5 proxy returned an invalid connection version."
         :socks5-connect
         :detail (aref reply 0)))
      (unless (zerop (aref reply 2))
        (%websocket-network-failure
         "The SOCKS5 proxy returned an invalid reserved byte."
         :socks5-connect
         :detail (aref reply 2)))
      (let ((status (aref reply 1)))
        (unless (zerop status)
          (%websocket-network-failure
           "The SOCKS5 proxy rejected the connection request."
           :socks5-connect
           :detail status))
        (%websocket-network-socks5-read-address
         stream (aref reply 3) deadline clock-function)
        (%websocket-network-read-octets
         stream 2 deadline clock-function :socks5-reply-port))))
  stream)

(defun %websocket-network-listener-open-p (listener)
  (unless (websocket-listener-p listener)
    (%websocket-protocol-error
     "A WebSocket listener is required."
     listener))
  (when (websocket-listener-closed-p listener)
    (%websocket-network-failure
     "The WebSocket listener is closed."
     :listener))
  listener)

(defun %websocket-network-validate-protocols (protocols)
  (unless (or (null protocols) (listp protocols))
    (%websocket-protocol-error
     "WebSocket PROTOCOLS must be a list or NIL."
     protocols))
  (dolist (protocol protocols)
    (unless (%websocket-token-string-p protocol)
      (%websocket-protocol-error
       "WebSocket protocol names must be non-empty tokens."
       protocol)))
  (copy-list protocols))

(defun %websocket-network-validate-extensions (extensions)
  (unless (or (null extensions) (stringp extensions))
    (%websocket-protocol-error
     "WebSocket EXTENSIONS must be a string or NIL."
     extensions))
  extensions)

(defun %websocket-network-validate-extension-transformer
    (extensions payload-encoder payload-decoder payload-reserved-bits)
  (when (and extensions
             (some (lambda (item)
                     (string-equal
                      (first item)
                      "permessage-deflate"))
                   (%websocket-extension-items extensions)))
    (unless (and (functionp payload-encoder)
                 (functionp payload-decoder)
                 (not (zerop (logand payload-reserved-bits #x40))))
      (%websocket-protocol-error
       "The permessage-deflate extension requires PAYLOAD-ENCODER, PAYLOAD-DECODER, and RSV1 (#x40)."
       extensions)))
  extensions)

(defun %websocket-network-permessage-deflate-selected-p (extensions)
  (and extensions
       (some (lambda (item)
               (string-equal (first item) "permessage-deflate"))
             (%websocket-extension-items extensions))))

(defun %websocket-network-permessage-deflate-frame-validator
    (extensions payload-decoder)
  (when (%websocket-network-permessage-deflate-selected-p extensions)
    (let ((message-open-p nil))
      (lambda (frame)
        (let* ((opcode (websocket-frame-opcode frame))
               (rsv1-p (not (zerop
                             (logand
                              (websocket-frame-reserved-bits frame)
                              #x40)))))
          (when (and rsv1-p (not (functionp payload-decoder)))
            (%websocket-protocol-error
             "A permessage-deflate frame requires a payload decoder."
             frame))
          (when (and rsv1-p
                     (or (%websocket-control-opcode-p opcode)
                         (= opcode 0)
                         message-open-p))
            (%websocket-protocol-error
             "RSV1 is only allowed on the first data frame of a permessage-deflate message."
             frame))
          (case opcode
            ((1 2)
             (setf message-open-p
                   (not (websocket-frame-fin-p frame))))
            (0
             (when (websocket-frame-fin-p frame)
               (setf message-open-p nil)))))))))

(defun %websocket-network-validate-generalized-boolean (value name)
  (unless (or (null value) (eq value t))
    (%websocket-protocol-error
     (format nil "~A must be generalized boolean." name)
     value))
  value)

(defun %websocket-network-close-stream-pair (stream raw-stream)
  (%websocket-network-close-stream stream)
  (unless (eq stream raw-stream)
    (%websocket-network-close-stream raw-stream))
  nil)

(defun %websocket-network-request-error-response (condition)
  (cond
    ((typep condition 'websocket-timeout)
     (values 408 "Request Timeout"))
    ((typep condition 'websocket-size-limit-exceeded)
     (case (websocket-error-operation condition)
       (:body-limit (values 413 "Payload Too Large"))
       (:header-limit (values 431 "Request Header Fields Too Large"))
       (otherwise (values 400 "Bad Request"))))
    (t
     (values 400 "Bad Request"))))

(defun %websocket-network-reject-request-error
    (stream condition deadline clock-function)
  (multiple-value-bind (status reason)
      (%websocket-network-request-error-response condition)
    (%websocket-network-reject-upgrade
     stream status reason
     :deadline deadline
     :clock-function clock-function)))

(defun %websocket-network-reject-upgrade
    (stream status reason &key headers body deadline clock-function)
  (unwind-protect
       (handler-case
           (let ((response
                   (make-http-response
                    :status status
                    :reason reason
                    :protocol-version "HTTP/1.1"
                    :headers
                    (append
                     (list (make-http-header "Connection" "close")
                           (make-http-header "Content-Type"
                                              "text/plain; charset=utf-8"))
                     headers)
                    :body (or body (%websocket-network-octets reason)))))
             (%websocket-call-with-deadline
              (lambda ()
                (write-http-response response stream))
              deadline clock-function :upgrade-rejection))
         (error () nil))
    (%websocket-network-close-stream stream))
  nil)

(defun %websocket-network-default-protocol
    (request protocols)
  (let ((offered
          (%websocket-header-token-values
           (http-request-headers request)
           "Sec-WebSocket-Protocol")))
    (find-if (lambda (protocol)
               (member protocol offered :test #'string=))
             protocols)))

(defun %websocket-network-selection
    (request protocols extensions headers acceptor)
  (let* ((offered
           (%websocket-header-token-values
            (http-request-headers request)
            "Sec-WebSocket-Protocol"))
         (default-protocol
           (%websocket-network-default-protocol request protocols))
         (decision (if acceptor (funcall acceptor request) t))
         (validate-protocol
           (lambda (protocol)
             (unless (or (null protocol)
                         (%websocket-token-string-p protocol))
               (%websocket-protocol-error
                "The selected WebSocket protocol must be a token or NIL."
                protocol))
             (when (and protocol
                        (not (member protocol offered :test #'string=)))
               (%websocket-protocol-error
                "The selected WebSocket protocol was not offered by the client."
                protocol))
             (when (and protocol protocols
                        (not (member protocol protocols :test #'string=)))
               (%websocket-protocol-error
                "The selected WebSocket protocol is not enabled by the listener."
                protocol))
             protocol)))
    (cond
      ((null decision) nil)
      ((eq decision t)
       (list :protocol (funcall validate-protocol default-protocol)
             :extensions extensions
             :headers (copy-list headers)))
      ((stringp decision)
       (list :protocol (funcall validate-protocol decision)
             :extensions extensions
             :headers (copy-list headers)))
      ((and (consp decision) (keywordp (car decision)))
       (let ((protocol
               (if (member :protocol decision)
                   (getf decision :protocol)
                   default-protocol))
             (selected-extensions
               (if (member :extensions decision)
                   (getf decision :extensions)
                   extensions))
             (selected-headers
               (if (member :headers decision)
                   (getf decision :headers)
                   headers)))
         (setf protocol (funcall validate-protocol protocol))
         (%websocket-network-validate-extensions selected-extensions)
         (list :protocol protocol
               :extensions selected-extensions
               :headers (%websocket-network-validate-headers
                         selected-headers))))
      (t
       (%websocket-protocol-error
        "A WebSocket ACCEPTOR must return NIL, T, a protocol string, or a selection plist."
        decision)))))

(defun open-websocket-listener
    (&key host (port 0) (backlog 128) (reuse-address t) ipv6 tls-wrapper
          timeout deadline (clock-function #'%websocket-monotonic-time))
  "Open a TCP WebSocket listener.

HOST may be NIL for the local wildcard address.  TLS-WRAPPER, when supplied,
receives an accepted binary stream and the DEADLINE/CLOCK-FUNCTION keywords,
and must return the stream used for the HTTP handshake.  The returned listener
owns its listening socket; CLOSE-WEBSOCKET-LISTENER releases it."
  (when host
    (%websocket-network-validate-host host))
  (%websocket-network-validate-port port)
  (unless (and (integerp backlog) (plusp backlog))
    (%websocket-protocol-error
     "BACKLOG must be a positive integer."
     backlog))
  (%websocket-network-validate-generalized-boolean
   reuse-address "REUSE-ADDRESS")
  (%websocket-network-validate-generalized-boolean ipv6 "IPV6")
  (when tls-wrapper
    (unless (functionp tls-wrapper)
      (%websocket-protocol-error
       "TLS-WRAPPER must be callable or NIL."
       tls-wrapper)))
  (let* ((clock (%websocket-network-clock clock-function))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock))
         (socket nil)
         (retained-p nil))
    (unwind-protect
         (multiple-value-bind (opened-socket address bound-port address-family)
             (%websocket-native-open-listener
              host port backlog reuse-address ipv6 effective-deadline clock)
           (setf socket opened-socket)
           (let ((listener
                   (%make-websocket-listener
                    socket address bound-port address-family tls-wrapper)))
             (setf retained-p t)
             listener))
      (unless retained-p
        (when socket
          (%websocket-with-cleanup
            (%websocket-native-close-listener socket)))))))

(defun close-websocket-listener (listener &key (close-connections-p t))
  "Close LISTENER and release its listening socket.

Closing an already closed listener is idempotent and returns NIL; the first
successful close returns T.  When CLOSE-CONNECTIONS-P is true, connections
accepted by LISTENER are closed without sending another Close frame."
  (unless (websocket-listener-p listener)
    (%websocket-protocol-error
     "A WebSocket listener is required."
     listener))
  (%websocket-network-validate-generalized-boolean
   close-connections-p "CLOSE-CONNECTIONS-P")
  (let ((close-p nil)
        (socket nil)
        (connections nil)
        (pending-streams nil))
    (%websocket-network-with-listener-lock (listener)
      (unless (websocket-listener-closed-p listener)
        (setf (websocket-listener-closed-p listener) t
              close-p t
              socket (websocket-listener-socket listener)
              pending-streams
              (copy-list (websocket-listener-pending-streams listener))
              (websocket-listener-pending-streams listener) nil)
        (when close-connections-p
          (setf connections
                (copy-list (websocket-listener-connections listener))))))
    (when close-p
      (%websocket-with-cleanup
        (%websocket-native-close-listener socket))
      (dolist (stream pending-streams)
        (%websocket-network-close-stream stream))
      (dolist (connection connections)
        (%websocket-with-cleanup
          (close-websocket-connection connection :send-close-p nil)))
      t)))

(defun accept-websocket-connection
    (listener &key acceptor protocols extensions headers origin-policy
                    extension-selection-policy
                    tls-wrapper (timeout +websocket-default-handshake-timeout+)
                    deadline
                    (max-header-bytes +websocket-default-max-header-bytes+)
                    (max-fields +websocket-default-max-header-fields+)
                    (max-body-bytes +websocket-default-max-body-bytes+)
                    (local-mask-p nil)
                    (peer-mask-required-p t)
                    payload-encoder payload-decoder
                    (payload-reserved-bits 0)
                    on-error
                    (clock-function #'%websocket-monotonic-time))
  "Accept and complete one HTTP/1.1 WebSocket upgrade.

ACCEPTOR is called with the validated request.  It may return NIL to reject
the request, T to use the listener defaults, a selected protocol string, or a
plist containing :PROTOCOL, :EXTENSIONS, and :HEADERS.  PROTOCOLS are server
preferences and an offered protocol is selected in their order.  A NIL return
for a malformed request or a rejected policy closes that client and returns
NIL.  PAYLOAD-ENCODER and PAYLOAD-DECODER configure a negotiated extension
transformation, and PAYLOAD-RESERVED-BITS enables the corresponding RSV bits
on outgoing messages.  TIMEOUT, MAX-HEADER-BYTES, MAX-FIELDS, and
MAX-BODY-BYTES have finite defaults; an explicit NIL disables the corresponding
HTTP/1.1 boundary.  ON-ERROR, when supplied, receives a handshake or transport
condition before this function returns NIL; without it, unexpected conditions
are signaled.  EXTENSION-SELECTION-POLICY may implement extension parameter
negotiation; selected extension names must still have been offered."
  (%websocket-network-listener-open-p listener)
  (let* ((server-protocols
           (%websocket-network-validate-protocols protocols))
         (server-extensions
           (%websocket-network-validate-extensions extensions))
         (server-headers (%websocket-network-validate-headers headers))
         (clock (%websocket-network-clock clock-function))
         (effective-deadline
           (%websocket-effective-deadline timeout deadline clock)))
    (when acceptor
      (unless (functionp acceptor)
        (%websocket-protocol-error
         "ACCEPTOR must be callable or NIL."
         acceptor)))
    (when origin-policy
      (unless (functionp origin-policy)
        (%websocket-protocol-error
         "ORIGIN-POLICY must be callable or NIL."
         origin-policy)))
    (when extension-selection-policy
      (unless (functionp extension-selection-policy)
        (%websocket-protocol-error
         "EXTENSION-SELECTION-POLICY must be callable or NIL."
         extension-selection-policy)))
    (when tls-wrapper
      (unless (functionp tls-wrapper)
        (%websocket-protocol-error
         "TLS-WRAPPER must be callable or NIL."
         tls-wrapper)))
    (when on-error
      (unless (functionp on-error)
        (%websocket-protocol-error
         "ON-ERROR must be callable or NIL."
         on-error)))
    (%websocket-network-validate-generalized-boolean
     local-mask-p "LOCAL-MASK-P")
    (%websocket-network-validate-generalized-boolean
     peer-mask-required-p "PEER-MASK-REQUIRED-P")
    (%websocket-validate-payload-transformer
     payload-encoder "PAYLOAD-ENCODER")
    (%websocket-validate-payload-transformer
     payload-decoder "PAYLOAD-DECODER")
    (%websocket-validate-reserved-bits
     payload-reserved-bits "PAYLOAD-RESERVED-BITS")
    (multiple-value-bind (raw-stream peer-address peer-port)
        (%websocket-native-accept
         (websocket-listener-socket listener)
         effective-deadline clock)
      (unless (%websocket-network-register-pending-stream
               listener raw-stream)
        (%websocket-network-close-stream raw-stream)
        (return-from accept-websocket-connection nil))
      (let ((stream raw-stream)
            (request nil)
            (response nil)
            (retained-p nil)
            (wrapper (or tls-wrapper
                         (websocket-listener-tls-wrapper listener))))
        (unwind-protect
             (handler-case
                 (progn
                   (when wrapper
                     (multiple-value-bind (upgraded-stream selected-alpn)
                         (funcall wrapper
                                  stream
                                  :timeout nil
                                  :deadline effective-deadline
                                  :clock-function clock)
                       (setf stream upgraded-stream)
                       (when selected-alpn
                         (%websocket-network-validate-tls-alpn-value
                          selected-alpn)))
                     (unless (streamp stream)
                       (%websocket-network-failure
                        "The TLS wrapper did not return a stream."
                        :tls
                         :detail stream))
                     (unless (%websocket-network-replace-pending-stream
                              listener raw-stream stream)
                                (return-from accept-websocket-connection nil)))
                   (setf request
                         (handler-case
                             (read-http-request
                              stream
                              :deadline effective-deadline
                              :max-header-bytes max-header-bytes
                              :max-fields max-fields
                              :max-body-bytes max-body-bytes
                              :clock-function clock
                              :on-headers
                              (lambda (header-request mode length)
                                (when (and
                                       (%websocket-http-expect-continue-p
                                        (%websocket-http-header-pairs
                                         (http-request-headers
                                          header-request)))
                                       (or (eq mode :chunked)
                                           (and (eq mode :length)
                                                (plusp length))))
                                  (write-http-response
                                   (make-http-response
                                    :status 100
                                    :reason "Continue")
                                   stream
                                   :deadline effective-deadline
                                   :clock-function clock))))
                           (websocket-error (condition)
                             (%websocket-network-reject-request-error
                              stream condition effective-deadline clock)
                             (when on-error
                               (funcall on-error condition))
                             (return-from accept-websocket-connection nil))))
                   (unless (websocket-upgrade-request-p request)
                     (%websocket-network-reject-upgrade
                      stream 400 "Bad Request"
                      :deadline effective-deadline
                      :clock-function clock)
                     (return-from accept-websocket-connection nil))
                   (unless (websocket-upgrade-request-p
                            request :origin-policy origin-policy)
                     (%websocket-network-reject-upgrade
                      stream 403 "Forbidden"
                      :deadline effective-deadline
                      :clock-function clock)
                     (return-from accept-websocket-connection nil))
                   (let ((selection
                           (%websocket-network-selection
                            request server-protocols server-extensions
                            server-headers acceptor)))
                     (unless selection
                       (%websocket-network-reject-upgrade
                        stream 403 "Forbidden"
                        :deadline effective-deadline
                        :clock-function clock)
                       (return-from accept-websocket-connection nil))
                     (let ((selected-protocol (getf selection :protocol)))
                       (when (and server-protocols (null selected-protocol))
                         (%websocket-network-reject-upgrade
                          stream 426 "Upgrade Required"
                          :headers (list (make-http-header
                                          "Upgrade" "websocket"))
                          :deadline effective-deadline
                          :clock-function clock)
                         (return-from accept-websocket-connection nil)))
                     (setf response
                           (handler-case
                               (progn
                                 (%websocket-network-validate-extension-transformer
                                  (getf selection :extensions)
                                  payload-encoder payload-decoder
                                  payload-reserved-bits)
                                 (websocket-upgrade-response
                                  request
                                  :protocol (getf selection :protocol)
                                  :extensions (getf selection :extensions)
                                  :headers (getf selection :headers)
                                  :origin-policy origin-policy
                                  :extension-selection-policy
                                  extension-selection-policy))
                             (websocket-error (condition)
                               (%websocket-network-reject-upgrade
                                stream 400 "Bad Request"
                                :deadline effective-deadline
                                :clock-function clock)
                                (when on-error
                                  (funcall on-error condition))
                                (return-from accept-websocket-connection nil))))
                      (%websocket-call-with-deadline
                      (lambda ()
                        (write-http-response response stream))
                      effective-deadline clock :server-handshake)
                      (let ((connection
                              (%make-websocket-connection
                              stream request response
                              (getf selection :protocol)
                              (getf selection :extensions)
                               peer-address peer-port
                               local-mask-p peer-mask-required-p
                               payload-encoder payload-decoder
                               payload-reserved-bits)))
                        (%websocket-network-unregister-pending-stream
                         listener raw-stream)
                        (unless (eq stream raw-stream)
                          (%websocket-network-unregister-pending-stream
                           listener stream))
                        (unless (%websocket-network-register-connection
                                 listener connection)
                         (%websocket-network-close-stream-pair
                          stream raw-stream)
                         (return-from accept-websocket-connection nil))
                       (setf retained-p t)
                        connection)))
               (websocket-error (condition)
                 (if on-error
                     (progn
                       (funcall on-error condition)
                       nil)
                     (error condition)))
               (error (condition)
                 (if on-error
                     (progn
                       (funcall on-error condition)
                       nil)
                     (error condition))))
          (unless retained-p
            (%websocket-network-close-stream-pair stream raw-stream))
          (%websocket-network-unregister-pending-stream
           listener raw-stream)
          (unless (eq stream raw-stream)
             (%websocket-network-unregister-pending-stream listener stream)))))))

(defun serve-websocket-listener
    (listener handler &key acceptor protocols extensions headers origin-policy
                            extension-selection-policy
                            tls-wrapper
                            (timeout +websocket-default-handshake-timeout+)
                            deadline session-timeout
                            session-deadline
                            (max-header-bytes +websocket-default-max-header-bytes+)
                            (max-fields +websocket-default-max-header-fields+)
                            (max-body-bytes +websocket-default-max-body-bytes+)
                            (max-message-bytes
                             +websocket-default-max-payload-bytes+)
                            (max-payload-bytes +websocket-default-max-payload-bytes+)
                            (max-fragments +websocket-default-max-fragments+)
                            (max-control-frames
                             +websocket-default-max-control-frames+)
                            (allowed-reserved-bits +websocket-unspecified+)
                            payload-encoder payload-decoder
                            (payload-reserved-bits 0)
                            max-frames max-messages
                            idle-timeout heartbeat-interval heartbeat-timeout
                            on-control on-error (close-on-error-p t)
                            (local-mask-p nil) (peer-mask-required-p t)
                            (worker-count 1) max-connections
                            max-accepted-connections
                            (clock-function #'%websocket-monotonic-time))
  "Serve upgraded connections from LISTENER.

HANDLER is called as (CONNECTION PAYLOAD OPCODE) for each complete data
message.  WORKER-COUNT controls the number of concurrent client sessions on
SBCL; its default of one preserves sequential operation.  MAX-CONNECTIONS,
when non-NIL, limits the number of active client sessions.  The effective
limit is also bounded by WORKER-COUNT.  MAX-ACCEPTED-CONNECTIONS, when
non-NIL, stops accepting after that many successful upgrades and returns
:MAX-ACCEPTED-CONNECTIONS.  The other return keywords are :CLOSED and
:TIMEOUT.

  TIMEOUT and DEADLINE bound accepting and upgrading a connection.  The
  SESSION-TIMEOUT and SESSION-DEADLINE options independently bound each
  connection's receive/control operations.  IDLE-TIMEOUT, HEARTBEAT-INTERVAL,
  and HEARTBEAT-TIMEOUT are forwarded to the per-connection session service.
  TIMEOUT, MAX-HEADER-BYTES, MAX-FIELDS, and MAX-BODY-BYTES have finite
  defaults; an explicit NIL disables the corresponding HTTP/1.1 boundary.
  MAX-MESSAGE-BYTES, MAX-PAYLOAD-BYTES, MAX-FRAGMENTS, and MAX-CONTROL-FRAMES
  have finite defaults and must be positive integers when overridden.
  PAYLOAD-ENCODER, PAYLOAD-DECODER, and PAYLOAD-RESERVED-BITS configure the
  negotiated WebSocket extension transformation for each connection.  An
  explicit ALLOWED-RESERVED-BITS overrides the connection default.
  EXTENSION-SELECTION-POLICY may implement extension parameter negotiation;
  selected extension names must still have been offered.
  Per-client protocol and handler failures close that client and do not stop
  the listener; ON-ERROR is forwarded to the existing session service.  Use
  CLOSE-WEBSOCKET-LISTENER from another execution context to stop a blocking
  accept.  Closing the listener closes accepted streams, but does not
  asynchronously interrupt user HANDLER code; a blocking handler must return
  before this function can join its worker."
  (%websocket-network-listener-open-p listener)
  (unless (functionp handler)
    (%websocket-protocol-error
     "A WebSocket listener handler must be callable."
     handler))
  (unless (and (integerp worker-count) (plusp worker-count))
    (%websocket-protocol-error
     "WORKER-COUNT must be a positive integer."
     worker-count))
  (when (and max-connections
             (or (not (integerp max-connections))
                 (not (plusp max-connections))))
    (%websocket-protocol-error
     "MAX-CONNECTIONS must be NIL or a positive integer."
     max-connections))
  (when (and max-accepted-connections
             (or (not (integerp max-accepted-connections))
                 (not (plusp max-accepted-connections))))
    (%websocket-protocol-error
     "MAX-ACCEPTED-CONNECTIONS must be NIL or a positive integer."
     max-accepted-connections))
  (when extension-selection-policy
    (unless (functionp extension-selection-policy)
      (%websocket-protocol-error
       "EXTENSION-SELECTION-POLICY must be callable or NIL."
       extension-selection-policy)))
  (%websocket-validate-payload-transformer
   payload-encoder "PAYLOAD-ENCODER")
  (%websocket-validate-payload-transformer
   payload-decoder "PAYLOAD-DECODER")
  (%websocket-validate-reserved-bits
   payload-reserved-bits "PAYLOAD-RESERVED-BITS")
  (unless (eq allowed-reserved-bits +websocket-unspecified+)
    (%websocket-validate-reserved-bits
     allowed-reserved-bits "ALLOWED-RESERVED-BITS"))
  #+sbcl nil
  #-sbcl
  (when (> worker-count 1)
    (%websocket-network-failure
     "Concurrent listener workers require SBCL native threads."
     :listener-workers
     :detail worker-count))
  (let ((connection-count 0)
        (threads nil)
        #+sbcl
        (worker-semaphore
          (and (> worker-count 1)
               (sb-thread:make-semaphore
                :count (min worker-count
                             (or max-connections worker-count))))))
    (labels ((serve-connection (connection)
               (unwind-protect
                    (handler-case
                        (serve-websocket-session
                         (websocket-connection-stream connection)
                         (lambda (stream payload opcode)
                           (declare (ignore stream))
                           (funcall handler connection payload opcode))
                         :max-message-bytes max-message-bytes
                         :max-payload-bytes max-payload-bytes
                         :max-fragments max-fragments
                         :max-control-frames max-control-frames
                         :allowed-reserved-bits
                         (if (eq allowed-reserved-bits
                                 +websocket-unspecified+)
                             (websocket-connection-payload-reserved-bits
                              connection)
                             allowed-reserved-bits)
                         :payload-decoder
                         (websocket-connection-payload-decoder connection)
                         :frame-validator
                         (%websocket-network-permessage-deflate-frame-validator
                          (websocket-connection-selected-extensions connection)
                          (websocket-connection-payload-decoder connection))
                         :max-frames max-frames
                         :max-messages max-messages
                         :require-mask-p peer-mask-required-p
                         :allow-unmasked-p (not peer-mask-required-p)
                         :require-unmasked-p nil
                         :on-control on-control
                         :on-error on-error
                         :close-on-error-p close-on-error-p
                         :close-stream nil
                         :write-guard
                         (lambda (thunk)
                           (%websocket-network-with-write-lock (connection)
                             (funcall thunk)))
                         :timeout session-timeout
                         :deadline session-deadline
                         :idle-timeout idle-timeout
                         :heartbeat-interval heartbeat-interval
                         :heartbeat-timeout heartbeat-timeout
                         :clock-function clock-function)
                      (error () nil))
                 (%websocket-with-cleanup
                   (close-websocket-connection
                    connection :send-close-p nil))))
             #+sbcl
             (acquire-worker-slot ()
               (if (null worker-semaphore)
                   (not (websocket-listener-closed-p listener))
                   (loop
                     (when (websocket-listener-closed-p listener)
                       (return :closed))
                     (when (sb-thread:wait-on-semaphore
                            worker-semaphore :timeout 0.1)
                       (return t)))))
             #+sbcl
             (reap-workers ()
               (setf threads
                     (delete-if-not #'sb-thread:thread-alive-p threads)))
             #+sbcl
             (join-workers ()
               (dolist (thread threads)
                 (sb-thread:join-thread thread)))
             #-sbcl
             (join-workers () nil))
      (unwind-protect
           (loop
             #+sbcl
             (reap-workers)
             (when (websocket-listener-closed-p listener)
               (return (values connection-count :closed)))
             (when (and max-accepted-connections
                        (>= connection-count max-accepted-connections))
               (return (values connection-count :max-accepted-connections)))
             #+sbcl
             (let ((slot-result (acquire-worker-slot)))
               (when (eq slot-result :closed)
                 (return (values connection-count :closed)))
               (let ((connection nil))
                 (unwind-protect
                      (handler-case
                          (setf connection
                                (accept-websocket-connection
                                 listener
                                 :acceptor acceptor
                                 :protocols protocols
                                 :extensions extensions
                                 :headers headers
                                 :origin-policy origin-policy
                                 :extension-selection-policy
                                 extension-selection-policy
                                 :tls-wrapper tls-wrapper
                                 :timeout timeout
                                 :deadline deadline
                                 :max-header-bytes max-header-bytes
                                 :max-fields max-fields
                                 :max-body-bytes max-body-bytes
                                 :local-mask-p local-mask-p
                                 :peer-mask-required-p peer-mask-required-p
                                 :payload-encoder payload-encoder
                                 :payload-decoder payload-decoder
                                 :payload-reserved-bits payload-reserved-bits
                                 :on-error on-error
                                 :clock-function clock-function))
                        (websocket-timeout ()
                          (return-from serve-websocket-listener
                            (values connection-count :timeout)))
                        (websocket-transport-error (condition)
                          (if (websocket-listener-closed-p listener)
                              (return-from serve-websocket-listener
                                (values connection-count :closed))
                              (error condition)))
                        (error (condition)
                          (error condition)))
                   (unless connection
                     (when worker-semaphore
                       (sb-thread:signal-semaphore worker-semaphore))))
                 (when connection
                   (incf connection-count)
                   (if worker-semaphore
                       (handler-case
                           (push
                            (sb-thread:make-thread
                             (lambda ()
                               (unwind-protect
                                    (serve-connection connection)
                                 (sb-thread:signal-semaphore
                                  worker-semaphore)))
                             :name
                             (format nil "websocket-worker-~D"
                                     connection-count))
                            threads)
                         (error (condition)
                           (sb-thread:signal-semaphore worker-semaphore)
                           (%websocket-with-cleanup
                             (close-websocket-connection
                              connection :send-close-p nil))
                           (error condition)))
                       (serve-connection connection))))
                 )
             #-sbcl
             (let ((connection
                     (handler-case
                         (accept-websocket-connection
                          listener
                          :acceptor acceptor
                          :protocols protocols
                          :extensions extensions
                          :headers headers
                          :origin-policy origin-policy
                          :extension-selection-policy
                          extension-selection-policy
                          :tls-wrapper tls-wrapper
                          :timeout timeout
                          :deadline deadline
                          :max-header-bytes max-header-bytes
                          :max-fields max-fields
                          :max-body-bytes max-body-bytes
                          :local-mask-p local-mask-p
                          :peer-mask-required-p peer-mask-required-p
                          :payload-encoder payload-encoder
                          :payload-decoder payload-decoder
                          :payload-reserved-bits payload-reserved-bits
                          :on-error on-error
                          :clock-function clock-function)
                       (websocket-timeout ()
                         (return (values connection-count :timeout)))
                       (websocket-transport-error (condition)
                         (if (websocket-listener-closed-p listener)
                             (return (values connection-count :closed))
                             (error condition)))))
               (when connection
                 (incf connection-count)
                 (serve-connection connection))))
        (join-workers))))))
