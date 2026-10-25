(defpackage #:websocket-kit/test
  (:use #:cl #:websocket-kit #:http-message-kit)
  (:shadowing-import-from #:websocket-kit
                          #:http-pseudo-header-p
                          #:make-http-pseudo-header)
  (:shadowing-import-from #:cl-weave
                          #:describe)
  (:import-from #:cl-weave
                #:expect
                #:it
                #:run-all
                #:signals)
  (:export #:run-tests))

(in-package #:websocket-kit/test)

(defun octets (&rest values)
  (make-array (length values)
              :element-type '(unsigned-byte 8)
              :initial-contents values))

;; The Sec-WebSocket-Key from the RFC 6455 section 1.3 worked example. Real
;; clients must generate this from a cryptographically secure source; the kit
;; deliberately refuses to invent one.
(defparameter +sample-key+ "dGhlIHNhbXBsZSBub25jZQ==")

(defun upgrade-request (&optional (uri "http://example.test/socket"))
  (make-websocket-upgrade-request uri :key +sample-key+))

(defun with-binary-input (octets function)
  (let ((path (merge-pathnames
               (make-pathname :name (format nil "cl-websocket-kit-~A" (gensym))
                              :type "bin")
               (uiop:temporary-directory))))
    (unwind-protect
        (progn
          (with-open-file (stream path
                                  :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create
                                  :element-type '(unsigned-byte 8))
            (write-sequence octets stream))
          (with-open-file (stream path
                                  :direction :input
                                  :element-type '(unsigned-byte 8))
            (funcall function stream)))
      (when (probe-file path)
        (delete-file path)))))

(defun with-binary-two-way (input-octets function)
  (let ((input-path (merge-pathnames
                     (make-pathname
                      :name (format nil "cl-websocket-kit-input-~A" (gensym))
                      :type "bin")
                     (uiop:temporary-directory)))
        (output-path (merge-pathnames
                      (make-pathname
                       :name (format nil "cl-websocket-kit-output-~A" (gensym))
                       :type "bin")
                      (uiop:temporary-directory))))
    (unwind-protect
        (progn
          (with-open-file (stream input-path
                                  :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create
                                  :element-type '(unsigned-byte 8))
            (write-sequence input-octets stream))
          (let ((values
                  (with-open-file (input input-path
                                         :direction :input
                                         :element-type '(unsigned-byte 8))
                    (with-open-file (output output-path
                                            :direction :output
                                            :if-exists :supersede
                                            :if-does-not-exist :create
                                            :element-type '(unsigned-byte 8))
                      (multiple-value-list
                       (funcall function (make-two-way-stream input output)))))))
            (values
             values
             (with-open-file (output output-path
                                     :direction :input
                                     :element-type '(unsigned-byte 8))
               (let ((result (make-array (file-length output)
                                         :element-type '(unsigned-byte 8))))
                 (read-sequence result output)
                 result)))))
      (when (probe-file input-path)
        (delete-file input-path))
      (when (probe-file output-path)
        (delete-file output-path)))))
