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
