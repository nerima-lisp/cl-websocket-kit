(in-package #:websocket-kit)

;; The slot shape (message, operation, detail) mirrors the protocol-error
;; conditions used by the HTTP libraries that consume this kit, so a caller
;; can translate one into the other without losing the diagnostic payload.
(define-condition websocket-error (error)
  ((message :initarg :message :reader websocket-error-message)
   (operation :initarg :operation :initform nil :reader websocket-error-operation)
   (detail :initarg :detail :initform nil :reader websocket-error-detail))
  (:report (lambda (condition stream)
             (format stream "~A" (websocket-error-message condition)))))

;; A frame or message exceeded a caller-supplied budget. This is a subtype of
;; websocket-error rather than a sibling because a session that maps
;; conditions to close codes wants the more specific one first: a budget
;; breach closes with 1009 (message too big), any other protocol fault with
;; 1002.
(define-condition websocket-size-limit-exceeded (websocket-error)
  ((limit :initarg :limit :reader websocket-size-limit-exceeded-limit)
   (observed :initarg :observed :reader websocket-size-limit-exceeded-observed)
   (kind :initarg :kind :initform :websocket
         :reader websocket-size-limit-exceeded-kind)))

(define-condition websocket-invalid-data (websocket-error)
  ()
  (:default-initargs
   :message "The WebSocket peer sent invalid data."
   :operation :websocket))

(define-condition websocket-protocol-error (websocket-error)
  ()
  (:default-initargs
   :operation :websocket))

(define-condition websocket-http-error (websocket-error)
  ()
  (:default-initargs
   :operation :http))

(define-condition websocket-timeout (websocket-error)
  ((kind :initarg :kind :initform :timeout :reader websocket-timeout-kind))
  (:default-initargs
   :message "The WebSocket operation exceeded its deadline."
   :operation :timeout))

(define-condition websocket-transport-error (websocket-error)
  ((cause :initarg :cause :initform nil :reader websocket-transport-error-cause))
  (:default-initargs
   :message "The WebSocket transport failed."
   :operation :transport))

(define-condition websocket-flow-control-error (websocket-error)
  ((window :initarg :window :reader websocket-flow-control-error-window)
   (required :initarg :required :reader websocket-flow-control-error-required)
   (kind :initarg :kind :initform :stream
         :reader websocket-flow-control-error-kind))
  (:default-initargs
   :message "The WebSocket flow-control window is insufficient."
   :operation :flow-control))
