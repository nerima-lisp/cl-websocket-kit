(in-package #:websocket-kit)

(defun %websocket-header-tokens (value)
  (unless (stringp value)
    (%websocket-protocol-error "A WebSocket header value must be a string." value))
  (let ((tokens '())
        (start 0)
        (length (length value)))
    (loop
      (let* ((comma (position #\, value :start start))
             (end (or comma length))
             (token (string-trim '(#\Space #\Tab)
                                 (subseq value start end))))
        (when (plusp (length token))
          (push token tokens))
        (if comma
            (setf start (1+ comma))
            (return (nreverse tokens)))))))

(defun %websocket-header-has-token-p (headers name token)
  (some (lambda (value)
          (some (lambda (candidate)
                  (string-equal candidate token))
                (%websocket-header-tokens value)))
        (http-header-values headers name)))

(defun %websocket-single-header-value (headers name)
  (let ((values (http-header-values headers name)))
    (when (and (consp values) (null (cdr values)))
      (string-trim '(#\Space #\Tab) (first values)))))

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

(defun websocket-upgrade-request-p (request)
  "Return true when REQUEST satisfies the RFC 6455 HTTP/1.1 handshake."
  (and (http-request-p request)
       (string-equal (http-request-method request) "GET")
       (string= (http-request-protocol-version request) "HTTP/1.1")
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
              (handler-case
                  (progn (websocket-accept-key key) t)
                (websocket-error () nil))))))

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
    (request &key protocol extensions headers)
  "Create a validated HTTP 101 response for REQUEST.

PROTOCOL, when supplied, must have been offered by the client.  EXTENSIONS is
the already-negotiated extension value; this API does not silently negotiate
an extension it does not understand."
  (unless (websocket-upgrade-request-p request)
    (%websocket-protocol-error
     "An HTTP request does not satisfy the WebSocket upgrade handshake."))
  (when (and protocol
             (not (and (%websocket-token-string-p protocol) (%websocket-header-has-token-p
                       (http-request-headers request)
                       "Sec-WebSocket-Protocol"
                       protocol))))
    (%websocket-protocol-error
     "The selected WebSocket subprotocol was not offered by the client."
     protocol))
  (when (and extensions (not (stringp extensions)))
    (%websocket-protocol-error
     "WebSocket extensions must be a string or NIL."
     extensions))
  (dolist (header headers)
    (let ((name (%websocket-extra-header-name header)))
      (when (and name (%websocket-reserved-header-p name))
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
          '("upgrade" "connection" "sec-websocket-version"
            "sec-websocket-key" "sec-websocket-protocol"
            "sec-websocket-extensions")
          :test #'string=))

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
overridden through HEADERS."
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
    (unless (listp headers)
      (%websocket-protocol-error
       "Additional WebSocket handshake headers must be a list."
       headers))
    (dolist (header headers)
      (let ((name (%websocket-extra-header-name header)))
        (when (and name (%websocket-client-reserved-header-p name))
          (%websocket-protocol-error
           "Custom WebSocket handshake headers cannot replace reserved headers."
           name))))
    (make-http-request
     :method "GET"
     :uri uri
     :headers
     (append
      (list (make-http-header "Upgrade" "websocket")
            (make-http-header "Connection" "Upgrade")
            (make-http-header "Sec-WebSocket-Version" "13")
            (make-http-header "Sec-WebSocket-Key" key))
      (when protocols
        (list (make-http-header "Sec-WebSocket-Protocol"
                                (format nil "~{~A~^, ~}" protocols))))
      (when extensions
        (list (make-http-header "Sec-WebSocket-Extensions" extensions)))
      headers))))

(defun websocket-client-handshake
    (stream request send-request-function
     &key timeout deadline max-header-bytes max-body-bytes
          (clock-function #'%websocket-monotonic-time))
  "Send REQUEST on STREAM and validate its RFC 6455 HTTP/1.1 response.

SEND-REQUEST-FUNCTION performs the HTTP/1.1 exchange. It is called as

  (funcall send-request-function request stream
           :timeout ... :deadline ... :max-header-bytes ...
           :max-body-bytes ... :collect-body-p nil :clock-function ...)

and must return the response value and, as a second value, whether the
connection is reusable. It is a parameter rather than a dependency so that
this kit needs no HTTP/1.1 implementation of its own; a caller pairs it with
whichever one it already has.

The HTTP response is returned as the primary value and the reusability result
as the second value.  STREAM stays open, including after a successful 101
response, so the caller can immediately use READ-WEBSOCKET-FRAME or
READ-WEBSOCKET-MESSAGE on it.  The caller owns the stream and must close it
when the handshake or subsequent WebSocket session ends."
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
  (multiple-value-bind (response reusable-p)
      (funcall send-request-function
       request stream
       :timeout timeout
       :deadline deadline
       :max-header-bytes max-header-bytes
       :max-body-bytes max-body-bytes
       :collect-body-p nil
       :clock-function clock-function)
    (unless (and (http-response-p response)
                 (= 101 (http-response-status response))
                 (string= "HTTP/1.1"
                          (http-response-protocol-version response))
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
        (when (and (http-header-values response-headers
                                       "Sec-WebSocket-Extensions")
                   (null (http-header-values request-headers
                                              "Sec-WebSocket-Extensions")))
          (%websocket-protocol-error
           "The server selected a WebSocket extension that was not offered."))))
    (values response reusable-p)))
