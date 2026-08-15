(in-package #:websocket-kit/test)

(defun run-tests ()
  (unless (run-all :reporter :spec :pass-with-no-tests nil)
    (error "cl-websocket-kit tests failed."))
  t)
