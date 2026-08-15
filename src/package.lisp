(defpackage #:websocket-kit
  (:use #:cl)
  ;; The handshake speaks HTTP/1.1, so it works in the message vocabulary
  ;; rather than defining a second one. Only the value types are imported;
  ;; performing the exchange is left to a function the caller supplies.
  (:import-from #:http-message-kit
                #:http-request
                #:http-request-p
                #:http-request-protocol-version
                #:http-request-method
                #:http-request-headers
                #:make-http-request
                #:http-response
                #:http-response-p
                #:http-response-protocol-version
                #:http-response-status
                #:http-response-headers
                #:make-http-response
                #:http-header
                #:http-header-p
                #:http-header-name
                #:http-header-values
                #:make-http-header)
  (:export
   ;; Conditions
   #:websocket-error
   #:websocket-error-message
   #:websocket-error-operation
   #:websocket-error-detail
   #:websocket-size-limit-exceeded
   #:websocket-size-limit-exceeded-limit
   #:websocket-size-limit-exceeded-observed
   #:websocket-size-limit-exceeded-kind
   ;; Frames
   #:websocket-frame
   #:websocket-frame-p
   #:websocket-frame-fin-p
   #:websocket-frame-opcode
   #:websocket-frame-mask-p
   #:websocket-frame-masking-key
   #:websocket-frame-payload
   #:make-websocket-frame
   #:serialize-websocket-frame
   #:parse-websocket-frame
   #:read-websocket-frame
   #:write-websocket-frame
   ;; Messages and sessions
   #:read-websocket-message
   #:write-websocket-message
   #:websocket-ping
   #:websocket-pong
   #:websocket-close
   #:serve-websocket-session
   ;; Handshake
   #:websocket-accept-key
   #:websocket-upgrade-request-p
   #:websocket-upgrade-response
   #:make-websocket-upgrade-request
   #:websocket-client-handshake
   ;; Close payloads
   #:websocket-valid-close-code-p
   #:make-websocket-close-payload
   #:parse-websocket-close-payload))
