(in-package #:websocket-kit)

(defun %websocket-token-string-p (value)
  (and (stringp value)
       (plusp (length value))
       (loop for character across value
             for code = (char-code character)
             always (and (<= #x21 code #x7e)
                         (not (find character
                                    '(#\( #\) #\< #\> #\@ #\, #\;
                                      #\: #\\ #\" #\/ #\[ #\] #\?
                                      #\= #\{ #\} #\Space #\Tab)
                                    :test #'char=))))))

(defun %websocket-quoted-pair-character-p (character)
  (let ((code (char-code character)))
    (or (= code 9)
        (<= 32 code 126)
        (<= 128 code 255))))

(defun %websocket-quoted-string-p (value)
  (and (stringp value)
       (>= (length value) 2)
       (char= (char value 0) #\")
       (char= (char value (1- (length value))) #\")
       (loop with index = 1
             with end = (1- (length value))
             while (< index end)
             for character = (char value index)
             do (if (char= character #\\)
                    (progn
                      (incf index)
                      (unless (and (< index end)
                                   (%websocket-quoted-pair-character-p
                                    (char value index)))
                        (return nil)))
                    (unless (let ((code (char-code character)))
                              (or (= code 9)
                                  (= code 32)
                                  (= code 33)
                                  (<= 35 code 91)
                                  (<= 93 code 126)
                                  (<= 128 code 255)))
                      (return nil)))
                (incf index)
             finally (return t))))

(defun %websocket-separated-items (value separator)
  (unless (stringp value)
    (%websocket-protocol-error
     "A WebSocket header value must be a string."
     value))
  (let ((items '())
        (start 0)
        (quoted-p nil)
        (escaped-p nil))
    (loop for index from 0 below (length value)
          for character = (char value index)
          do (cond
               (escaped-p
                (setf escaped-p nil))
               ((and quoted-p (char= character #\\))
                (setf escaped-p t))
               ((char= character #\")
                (setf quoted-p (not quoted-p)))
               ((and (not quoted-p) (char= character separator))
                (let ((item (string-trim '(#\Space #\Tab)
                                          (subseq value start index))))
                  (unless (plusp (length item))
                    (%websocket-protocol-error
                     "A WebSocket comma-separated header contains an empty item."
                     value))
                  (push item items))
                (setf start (1+ index)))))
    (when (or quoted-p escaped-p)
      (%websocket-protocol-error
       "A WebSocket header contains an unterminated quoted string."
       value))
    (let ((item (string-trim '(#\Space #\Tab)
                             (subseq value start))))
      (unless (plusp (length item))
        (%websocket-protocol-error
         "A WebSocket comma-separated header contains an empty item."
         value))
      (push item items))
    (nreverse items)))

(defun %websocket-header-tokens (value)
  (mapcar (lambda (token)
            (unless (%websocket-token-string-p token)
              (%websocket-protocol-error
               "A WebSocket token header contains an invalid token."
               token))
            token)
          (%websocket-separated-items value #\,)))

(defun %websocket-header-has-token-p (headers name token)
  (some (lambda (value)
          (some (lambda (candidate)
                  (string-equal candidate token))
                (%websocket-header-tokens value)))
        (http-header-values headers name)))

(defun %websocket-header-token-values (headers name)
  (mapcan #'%websocket-header-tokens
          (http-header-values headers name)))

(defun %websocket-single-header-value (headers name)
  (let ((values (http-header-values headers name)))
    (when (and (consp values) (null (cdr values)))
      (string-trim '(#\Space #\Tab) (first values)))))

(defun %websocket-header-values-string (headers name)
  (format nil "~{~A~^, ~}" (http-header-values headers name)))

(defparameter +websocket-extension-parameter-absent+
  (gensym "EXTENSION-PARAMETER-ABSENT-"))

(defun %websocket-extension-item (item)
  (let ((parts (%websocket-separated-items item #\;)))
    (let ((name (first parts)))
      (unless (%websocket-token-string-p name)
        (%websocket-protocol-error
         "A WebSocket extension name must be a token."
         name))
      (list name
            (mapcar
             (lambda (parameter)
               (let ((equals (position #\= parameter)))
                 (if equals
                     (let ((parameter-name
                             (string-trim '(#\Space #\Tab)
                                           (subseq parameter 0 equals)))
                           (parameter-value
                             (string-trim '(#\Space #\Tab)
                                          (subseq parameter (1+ equals)))))
                       (unless (%websocket-token-string-p parameter-name)
                         (%websocket-protocol-error
                          "A WebSocket extension parameter name must be a token."
                          parameter-name))
                       (unless (or (%websocket-token-string-p parameter-value)
                                   (%websocket-quoted-string-p parameter-value))
                         (%websocket-protocol-error
                          "A WebSocket extension parameter value is invalid."
                          parameter-value))
                       (list parameter-name parameter-value))
                     (progn
                       (unless (%websocket-token-string-p parameter)
                         (%websocket-protocol-error
                          "A WebSocket extension parameter name must be a token."
                          parameter))
                       (list parameter
                             +websocket-extension-parameter-absent+)))))
             (rest parts))))))

(defun %websocket-extension-item-name (item)
  (first item))

(defun %websocket-extension-items (headers-or-value)
  (mapcan (lambda (value)
            (mapcar #'%websocket-extension-item
                    (%websocket-separated-items value #\,)))
          (if (stringp headers-or-value)
              (list headers-or-value)
              (http-header-values headers-or-value
                                  "Sec-WebSocket-Extensions"))))

(defun %websocket-extension-names (headers-or-value)
  (mapcar #'%websocket-extension-item-name
          (%websocket-extension-items headers-or-value)))

(defun %websocket-extension-parameter-equal-p (left right)
  (and (string-equal (first left) (first right))
       (or (and (eq (second left) +websocket-extension-parameter-absent+)
                (eq (second right) +websocket-extension-parameter-absent+))
           (and (not (eq (second left) +websocket-extension-parameter-absent+))
                (not (eq (second right) +websocket-extension-parameter-absent+))
                (string= (second left) (second right))))))

(defun %websocket-extension-item-equal-p (left right)
  (and (string-equal (first left) (first right))
       (= (length (second left)) (length (second right)))
       (every #'%websocket-extension-parameter-equal-p
              (second left)
              (second right))))

(defun %websocket-extension-selection-p (selected offered)
  (every (lambda (selected-item)
           (some (lambda (offered-item)
                   (%websocket-extension-item-equal-p
                    selected-item offered-item))
                 offered))
         selected))

(defun %websocket-extension-name-selection-p (selected offered)
  (every (lambda (selected-item)
           (some (lambda (offered-item)
                   (string-equal (first selected-item)
                                 (first offered-item)))
                 offered))
         selected))

(defun %websocket-extension-selection-allowed-p
    (selected offered selected-value offered-value policy)
  (and (%websocket-extension-name-selection-p selected offered)
       (if policy
           (funcall policy selected-value offered-value)
           (%websocket-extension-selection-p selected offered))))

(defun %websocket-host-plain-character-p (character)
  (let ((code (char-code character)))
    (or (and (<= #x30 code) (<= code #x39))
        (and (<= #x41 code) (<= code #x5a))
        (and (<= #x61 code) (<= code #x7a))
        (find character "-.~_!$&'()*+;=" :test #'char=))))

(defun %websocket-hex-digit-p (character)
  (not (null (digit-char-p character 16))))

(defun %websocket-host-reg-name-p (value)
  (and (plusp (length value))
       (loop with index = 0
             while (< index (length value))
             do (let ((character (char value index)))
                  (cond ((%websocket-host-plain-character-p character)
                         (incf index))
                        ((char= character #\%)
                         (unless (and (< (+ index 2) (length value))
                                      (%websocket-hex-digit-p
                                       (char value (1+ index)))
                                      (%websocket-hex-digit-p
                                       (char value (+ index 2))))
                           (return-from %websocket-host-reg-name-p nil))
                         (incf index 3))
                        (t
                         (return-from %websocket-host-reg-name-p nil))))
             finally (return t))))

(defun %websocket-decimal-port-p (value)
  (and (plusp (length value))
       (<= (length value) 5)
       (every (lambda (character)
                (not (null (digit-char-p character))))
              value)
       (<= (parse-integer value) 65535)))

(defun %websocket-ipv4-decimal-octet-p (value)
  (and (plusp (length value))
       (<= (length value) 3)
       (or (= (length value) 1)
           (char/= (char value 0) #\0))
       (every (lambda (character)
                (not (null (digit-char-p character))))
              value)
       (<= (parse-integer value) 255)))

(defun %websocket-ipv4-address-p (value)
  (and (plusp (length value))
       (loop with start = 0
             with count = 0
             for index from 0 to (length value)
             when (or (= index (length value))
                      (char= (char value index) #\.))
               do (unless (%websocket-ipv4-decimal-octet-p
                           (subseq value start index))
                    (return nil))
                  (incf count)
                  (setf start (1+ index))
             finally (return (= count 4)))))

(defun %websocket-ipv6-side-group-count (value)
  (if (zerop (length value))
      0
      (loop with start = 0
            with count = 0
            for index from 0 to (length value)
            when (or (= index (length value))
                     (char= (char value index) #\:))
              do (let ((group (subseq value start index)))
                   (when (zerop (length group))
                     (return nil))
                   (if (find #\. group)
                       (unless (and (= index (length value))
                                    (%websocket-ipv4-address-p group))
                         (return nil))
                       (unless (and (<= 1 (length group) 4)
                                    (every #'%websocket-hex-digit-p group))
                         (return nil)))
                   (incf count (if (find #\. group) 2 1))
                   (setf start (1+ index)))
            finally (return count))))

(defun %websocket-ipv6-address-p (value)
  (and (plusp (length value))
       (find #\: value)
       (let ((compression (search "::" value)))
         (if compression
             (and (null (search "::" value
                                :start2 (+ compression 2)))
                  (let ((left (%websocket-ipv6-side-group-count
                               (subseq value 0 compression)))
                        (right (%websocket-ipv6-side-group-count
                                (subseq value (+ compression 2)))))
                    (and (numberp left)
                         (numberp right)
                         (< (+ left right) 8))))
             (let ((groups (%websocket-ipv6-side-group-count value)))
               (and (numberp groups)
                    (= groups 8)))))))

(defun %websocket-ip-literal-p (value)
  (and (plusp (length value))
       (or (let ((dot (position #\. value)))
             (and dot
                  (> dot 1)
                  (member (char value 0) '(#\v #\V))
                  (loop for index from 1 below dot
                        always (%websocket-hex-digit-p (char value index)))
                  (< (1+ dot) (length value))
                  (loop for index from (1+ dot) below (length value)
                        always (or (%websocket-host-plain-character-p
                                    (char value index))
                                   (char= (char value index) #\:)))))
           (%websocket-ipv6-address-p value))))

(defun %websocket-host-value-p (value)
  (and (stringp value)
       (let* ((trimmed (string-trim '(#\Space #\Tab) value))
              (length (length trimmed)))
         (and (plusp length)
              (not (find-if (lambda (character)
                              (or (char= character #\,)
                                  (char= character #\Space)
                                  (char= character #\Tab)
                                  (char= character #\Return)
                                  (char= character #\Newline)))
                            trimmed))
              (if (char= (char trimmed 0) #\[)
                  (let ((closing (position #\] trimmed)))
                    (and closing
                         (> closing 1)
                         (%websocket-ip-literal-p
                          (subseq trimmed 1 closing))
                         (or (= closing (1- length))
                             (and (char= (char trimmed (1+ closing)) #\:)
                                  (%websocket-decimal-port-p
                                   (subseq trimmed (+ closing 2)))))))
                  (let ((colon (position #\: trimmed)))
                    (if colon
                        (and (%websocket-host-reg-name-p
                              (subseq trimmed 0 colon))
                             (%websocket-decimal-port-p
                              (subseq trimmed (1+ colon))))
                        (%websocket-host-reg-name-p trimmed))))))))

(defun %websocket-request-host-p (request)
  (let ((values (http-header-values (http-request-headers request) "Host")))
    (and (consp values)
         (null (cdr values))
         (%websocket-host-value-p (first values)))))

(defun %websocket-origin-allowed-p (request origin-policy)
  (or (null origin-policy)
      (and (functionp origin-policy)
           (funcall origin-policy
                    (%websocket-single-header-value
                     (http-request-headers request) "Origin")
                    request))))

(defun make-websocket-origin-policy (allowed-origins &key (require-origin-p t))
  "Return an exact-match Origin allowlist predicate.

ALLOWED-ORIGINS is a string or a proper list of strings.  The returned
predicate accepts an Origin only when it is present in that allowlist.
REQUIRE-ORIGIN-P defaults to true and rejects requests without an Origin;
when false, a missing Origin is accepted while present Origins still need an
exact allowlist match."
  (unless (member require-origin-p '(nil t) :test #'eq)
    (%websocket-protocol-error
     "REQUIRE-ORIGIN-P must be either T or NIL."
     require-origin-p))
  (labels ((copy-origin-list (origins)
             (if (consp origins)
                 (cons (progn
                         (unless (stringp (car origins))
                           (%websocket-protocol-error
                            "Allowed WebSocket Origins must be strings."
                            (car origins)))
                         (copy-seq (car origins)))
                       (copy-origin-list (cdr origins)))
                 (unless (null origins)
                   (%websocket-protocol-error
                    "Allowed WebSocket Origins must be a string or proper list of strings."
                    origins)))))
    (let ((origins (cond ((stringp allowed-origins)
                          (list (copy-seq allowed-origins)))
                         ((null allowed-origins) nil)
                         (t (copy-origin-list allowed-origins)))))
      (lambda (origin request)
        (declare (ignore request))
        (and (or origin (not require-origin-p))
             (or (null origin)
                 (not (null (member origin origins :test #'string=)))))))))

(defun websocket-upgrade-request-p (request &key origin-policy)
  "Return true when REQUEST satisfies the RFC 6455 HTTP/1.1 handshake.

ORIGIN-POLICY, when supplied, is called with the Origin value (or NIL) and
REQUEST.  A false result rejects the upgrade."
  (handler-case
      (and (http-request-p request)
           (string-equal (http-request-method request) "GET")
           (string-equal (http-request-protocol-version request) "HTTP/1.1")
           (%websocket-request-host-p request)
           (zerop (length (http-request-body request)))
           (null (http-request-trailers request))
           (%websocket-header-has-token-p (http-request-headers request)
                                          "Upgrade" "websocket")
           (%websocket-header-has-token-p (http-request-headers request)
                                          "Connection" "upgrade")
           (let ((version (%websocket-single-header-value
                           (http-request-headers request)
                           "Sec-WebSocket-Version"))
                 (key (%websocket-single-header-value
                       (http-request-headers request)
                       "Sec-WebSocket-Key")))
             (and version
                  (string= version "13")
                  key
                  (progn (websocket-accept-key key) t)))
           (every #'%websocket-token-string-p
                  (%websocket-header-token-values
                   (http-request-headers request)
                   "Sec-WebSocket-Protocol"))
           (progn
             (%websocket-extension-names (http-request-headers request))
             t)
           (%websocket-origin-allowed-p request origin-policy))
    (websocket-error () nil)))

(defun %websocket-extra-header-name (header)
  (cond ((http-header-p header)
         (http-header-name header))
        ((and (consp header) (stringp (car header)))
         (car header))
        (t nil)))

(defun %websocket-reserved-header-p (name)
  (member (string-downcase name)
          '("upgrade" "connection" "sec-websocket-accept"
            "sec-websocket-protocol" "sec-websocket-extensions")
          :test #'string=))

(defun websocket-upgrade-response
    (request &key protocol extensions headers origin-policy
                    extension-selection-policy)
  "Create a validated HTTP 101 response for REQUEST.

PROTOCOL, when supplied, must have been offered by the client.  EXTENSIONS is
the already-negotiated extension value.  By default every selected extension
name and parameter must exactly match an offered item.  When supplied,
EXTENSION-SELECTION-POLICY is called as (SELECTED OFFERED) with serialized
header values and may implement parameter negotiation; selected extension
names must still have been offered."
  (unless (websocket-upgrade-request-p request
                                       :origin-policy origin-policy)
    (%websocket-protocol-error
     "An HTTP request does not satisfy the WebSocket upgrade handshake."))
  (when extension-selection-policy
    (unless (functionp extension-selection-policy)
      (%websocket-protocol-error
       "EXTENSION-SELECTION-POLICY must be callable or NIL."
       extension-selection-policy)))
  (when (and protocol
             (not (and (%websocket-token-string-p protocol) (%websocket-header-has-token-p
                       (http-request-headers request)
                       "Sec-WebSocket-Protocol"
                       protocol))))
    (%websocket-protocol-error
     "The selected WebSocket subprotocol was not offered by the client."
     protocol))
  (when extensions
    (unless (stringp extensions)
      (%websocket-protocol-error
       "WebSocket extensions must be a string or NIL."
       extensions))
    (unless (%websocket-extension-selection-allowed-p
             (%websocket-extension-items extensions)
             (%websocket-extension-items (http-request-headers request))
             extensions
             (%websocket-header-values-string
              (http-request-headers request)
              "Sec-WebSocket-Extensions")
             extension-selection-policy)
      (%websocket-protocol-error
       "The selected WebSocket extension was not offered by the client."
       extensions)))
  (unless (listp headers)
    (%websocket-protocol-error
     "Additional WebSocket handshake headers must be a list."
     headers))
  (dolist (header headers)
    (let ((name (%websocket-extra-header-name header)))
      (unless name
        (%websocket-protocol-error
         "Additional WebSocket handshake headers must be HTTP header values."
         header))
      (when (%websocket-reserved-header-p name)
        (%websocket-protocol-error
         "Custom WebSocket handshake headers cannot replace reserved headers."
         name))))
  (let ((response-headers
          (list (make-http-header "Upgrade" "websocket")
                (make-http-header "Connection" "Upgrade")
                (make-http-header
                 "Sec-WebSocket-Accept"
                 (websocket-accept-key
                  (%websocket-single-header-value
                   (http-request-headers request)
                   "Sec-WebSocket-Key"))))))
    (when protocol
      (setf response-headers
            (append response-headers
                    (list (make-http-header "Sec-WebSocket-Protocol"
                                             protocol)))))
    (when extensions
      (setf response-headers
            (append response-headers
                    (list (make-http-header "Sec-WebSocket-Extensions"
                                             extensions)))))
    (make-http-response :status 101
                        :reason "Switching Protocols"
                        :protocol-version "HTTP/1.1"
                        :headers (append response-headers headers))))

(defun %websocket-client-reserved-header-p (name)
  (member (string-downcase name)
          '("host" "upgrade" "connection" "sec-websocket-version"
            "sec-websocket-key" "sec-websocket-protocol"
            "sec-websocket-extensions")
          :test #'string=))

(defun %websocket-http-uri (uri)
  (if (stringp uri)
      (cond ((and (>= (length uri) 5)
                  (string-equal (subseq uri 0 5) "ws://"))
             (concatenate 'string "http" (subseq uri 2)))
            ((and (>= (length uri) 6)
                  (string-equal (subseq uri 0 6) "wss://"))
             (concatenate 'string "https" (subseq uri 3)))
            (t uri))
      uri))

(defun make-websocket-upgrade-request
    (uri &key key protocols extensions headers)
  "Create an HTTP/1.1 WebSocket client upgrade request for URI.

KEY is the already-generated Base64 value for Sec-WebSocket-Key.  This API
requires the caller to supply it so that key generation can use the
application's cryptographically secure random source.  PROTOCOLS is a list of
offered subprotocol tokens.  EXTENSIONS is an optional already-serialized
Sec-WebSocket-Extensions value; extension negotiation is intentionally left to
the caller.

The reserved handshake headers are generated by this function and cannot be
overridden through HEADERS.  WS and WSS URI strings are converted to their
HTTP and HTTPS equivalents for the underlying HTTP request model."
  (unless (stringp key)
    (%websocket-protocol-error
     "Sec-WebSocket-Key must be a Base64 string."
     key))
  (let ((key (string-trim '(#\Space #\Tab) key)))
    (websocket-accept-key key)
    (unless (or (null protocols) (listp protocols))
      (%websocket-protocol-error
       "WebSocket subprotocols must be supplied as a list."
       protocols))
    (dolist (protocol protocols)
      (unless (%websocket-token-string-p protocol)
        (%websocket-protocol-error
         "A WebSocket subprotocol must be a token."
         protocol)))
    (when (and extensions (not (stringp extensions)))
      (%websocket-protocol-error
       "WebSocket extensions must be a string or NIL."
       extensions))
    (when extensions
      (%websocket-extension-names extensions))
    (unless (listp headers)
      (%websocket-protocol-error
       "Additional WebSocket handshake headers must be a list."
       headers))
    (dolist (header headers)
      (let ((name (%websocket-extra-header-name header)))
        (unless name
          (%websocket-protocol-error
           "Additional WebSocket handshake headers must be HTTP header values."
           header))
        (when (%websocket-client-reserved-header-p name)
          (%websocket-protocol-error
           "Custom WebSocket handshake headers cannot replace reserved headers."
           name))))
    (let* ((http-uri (%websocket-http-uri uri))
           (authority
            (http-request-authority
             (make-http-request :method "GET" :uri http-uri))))
      (unless (%websocket-host-value-p authority)
        (%websocket-protocol-error
         "The WebSocket request URI must provide a valid Host authority."
         authority))
      (make-http-request
       :method "GET"
       :uri http-uri
       :headers
       (append
        (list (make-http-header "Host" authority)
              (make-http-header "Upgrade" "websocket")
              (make-http-header "Connection" "Upgrade")
              (make-http-header "Sec-WebSocket-Version" "13")
              (make-http-header "Sec-WebSocket-Key" key))
        (when protocols
          (list (make-http-header "Sec-WebSocket-Protocol"
                                  (format nil "~{~A~^, ~}" protocols))))
        (when extensions
          (list (make-http-header "Sec-WebSocket-Extensions" extensions)))
        headers)))))

(defun websocket-client-handshake
    (stream request send-request-function
     &key timeout deadline max-header-bytes max-body-bytes max-fields
          extension-selection-policy
          (clock-function #'%websocket-monotonic-time))
  "Send REQUEST on STREAM and validate its RFC 6455 HTTP/1.1 response.

SEND-REQUEST-FUNCTION performs the HTTP/1.1 exchange. It is called as

  (funcall send-request-function request stream
           :timeout ... :deadline ... :max-header-bytes ...
           :max-body-bytes ... :max-fields ... :collect-body-p nil
           :clock-function ...)

and must return the response value and, as a second value, whether the
connection is reusable. It is a parameter rather than a dependency so that
this kit needs no HTTP/1.1 implementation of its own; a caller pairs it with
whichever one it already has.

The HTTP response is returned as the primary value and the reusability result
as the second value.  STREAM stays open, including after a successful 101
response, so the caller can immediately use READ-WEBSOCKET-FRAME or
READ-WEBSOCKET-MESSAGE on it.  The caller owns the stream and must close it
when the handshake or subsequent WebSocket session ends.  By default every
selected extension name and parameter must exactly match an offered item.
When supplied, EXTENSION-SELECTION-POLICY is called as (SELECTED OFFERED)
with serialized header values and may implement parameter negotiation;
selected extension names must still have been offered."
  (unless (streamp stream)
    (%websocket-protocol-error
     "The WebSocket client handshake requires an open stream."
     stream))
  (unless (functionp send-request-function)
    (%websocket-protocol-error
     "The WebSocket client handshake requires a request-sending function."
     send-request-function))
  (unless (websocket-upgrade-request-p request)
    (%websocket-protocol-error
     "An HTTP request does not satisfy the WebSocket upgrade handshake."
     request))
  (when extension-selection-policy
    (unless (functionp extension-selection-policy)
      (%websocket-protocol-error
       "EXTENSION-SELECTION-POLICY must be callable or NIL."
       extension-selection-policy)))
  (multiple-value-bind (response reusable-p)
      (funcall send-request-function
       request stream
       :timeout timeout
       :deadline deadline
       :max-header-bytes max-header-bytes
       :max-body-bytes max-body-bytes
       :max-fields max-fields
       :collect-body-p nil
       :clock-function clock-function)
    (unless (and (http-response-p response)
                 (= 101 (http-response-status response))
                 (string= "HTTP/1.1"
                          (http-response-protocol-version response))
                 (zerop (length (http-response-body response)))
                 (null (http-response-trailers response))
                 (null (http-header-values
                        (http-response-headers response)
                        "Content-Length"))
                 (null (http-header-values
                        (http-response-headers response)
                        "Transfer-Encoding"))
                 (%websocket-header-has-token-p
                  (http-response-headers response) "Upgrade" "websocket")
                 (%websocket-header-has-token-p
                  (http-response-headers response) "Connection" "upgrade"))
      (%websocket-protocol-error
       "The server response is not a valid WebSocket 101 upgrade response."
       response))
    (let* ((request-headers (http-request-headers request))
           (response-headers (http-response-headers response))
           (key (%websocket-single-header-value
                 request-headers "Sec-WebSocket-Key"))
           (accept (%websocket-single-header-value
                   response-headers "Sec-WebSocket-Accept")))
      (unless (and accept key
                   (string= accept (websocket-accept-key key)))
        (%websocket-protocol-error
         "The server returned an invalid Sec-WebSocket-Accept value."
         accept))
      (let ((selected-protocol-values
              (http-header-values response-headers "Sec-WebSocket-Protocol"))
            (requested-protocol-values
              (http-header-values request-headers "Sec-WebSocket-Protocol")))
        (when selected-protocol-values
          (let ((selected-protocol
                  (%websocket-single-header-value
                   response-headers "Sec-WebSocket-Protocol")))
            (unless (and (consp selected-protocol-values)
                         (null (cdr selected-protocol-values))
                         (%websocket-token-string-p selected-protocol)
                         requested-protocol-values
                         (%websocket-header-has-token-p
                          request-headers
                          "Sec-WebSocket-Protocol"
                          selected-protocol))
              (%websocket-protocol-error
               "The server selected an invalid WebSocket subprotocol."
               selected-protocol))))
        (let ((response-extension-values
                (http-header-values response-headers
                                    "Sec-WebSocket-Extensions"))
              (request-extension-values
                (http-header-values request-headers
                                    "Sec-WebSocket-Extensions"))
              (selected-extension-value
                (%websocket-header-values-string
                 response-headers "Sec-WebSocket-Extensions"))
              (requested-extension-value
                (%websocket-header-values-string
                 request-headers "Sec-WebSocket-Extensions")))
          (when response-extension-values
            (unless (and request-extension-values
                         (%websocket-extension-selection-allowed-p
                          (%websocket-extension-items response-headers)
                          (%websocket-extension-items request-headers)
                          selected-extension-value
                          requested-extension-value
                          extension-selection-policy))
              (%websocket-protocol-error
               "The server selected a WebSocket extension that was not offered."))))))
    (values response reusable-p)))
