(in-package #:websocket-kit)

(defparameter +websocket-default-max-header-bytes+ (* 64 1024))
(defparameter +websocket-default-max-header-fields+ 100)
(defparameter +websocket-default-max-body-bytes+ (* 16 1024 1024))

(defun %websocket-http-fail (message &key detail (operation :http))
  (error 'websocket-http-error
         :message message
         :operation operation
         :detail detail))

(defun %websocket-http-size-fail (message limit observed operation)
  (error 'websocket-size-limit-exceeded
         :message message
         :operation operation
         :detail (list :limit limit :observed observed)
         :limit limit
         :observed observed
         :kind :http))

(defun %websocket-http-octets-p (value)
  (and (arrayp value)
       (= (array-rank value) 1)
       (not (stringp value))
       (loop for octet across value
             always (and (integerp octet) (<= 0 octet 255)))))

(defun %websocket-http-copy-octets (value)
  (unless (%websocket-http-octets-p value)
    (%websocket-http-fail
     "HTTP data must be a one-dimensional octet vector."
     :detail (type-of value)
     :operation :body))
  (let ((copy (make-array (length value) :element-type '(unsigned-byte 8))))
    (replace copy value)
    copy))

(defun %websocket-http-string-octets (value)
  (unless (stringp value)
    (%websocket-http-fail
     "HTTP wire text must be a string."
     :detail (type-of value)
     :operation :text))
  (let ((result (make-array (length value) :element-type '(unsigned-byte 8))))
    (loop for index below (length value)
          for code = (char-code (char value index))
          do (when (> code #xff)
               (%websocket-http-fail
                "HTTP wire text contains a character outside the octet range."
                :detail code
                :operation :text))
             (setf (aref result index) code))
    result))

(defun %websocket-http-builder ()
  (make-array 256
              :element-type '(unsigned-byte 8)
              :adjustable t
              :fill-pointer 0))

(defun %websocket-http-builder-append-octets (builder octets)
  (loop for octet across octets
        do (vector-push-extend octet builder))
  builder)

(defun %websocket-http-builder-append-string (builder string)
  (%websocket-http-builder-append-octets
   builder
   (%websocket-http-string-octets string)))

(defun %websocket-http-builder-result (builder)
  (let ((result (make-array (length builder)
                            :element-type '(unsigned-byte 8))))
    (replace result builder)
    result))

(defun %websocket-http-token-p (value)
  (and (stringp value)
       (plusp (length value))
       (loop for character across value
             for code = (char-code character)
             always
             (or (and (<= (char-code #\0) code)
                      (<= code (char-code #\9)))
                 (and (<= (char-code #\A) code)
                      (<= code (char-code #\Z)))
                 (and (<= (char-code #\a) code)
                      (<= code (char-code #\z)))
                 (find character
                       (concatenate 'string "!#$%&'*+-.^_"
                                    (string (code-char #x60))
                                    "|~")
                       :test #'char=)))))

(defun %websocket-http-header-value-p (value)
  (and (stringp value)
       (every (lambda (character)
                (let ((code (char-code character)))
                  (or (= code #x09)
                      (<= #x20 code #x7e)
                      (<= #x80 code #xff))))
              value)))

(defun %websocket-http-request-target-p (value)
  (and (stringp value)
       (plusp (length value))
       (every (lambda (character)
                (let ((code (char-code character)))
                  (and (<= #x21 code #xff)
                       (/= code #x7f))))
              value)))

(defun %websocket-http-header-pairs (headers)
  (mapcar
   (lambda (header)
     (unless (http-header-p header)
       (%websocket-http-fail
        "HTTP headers must contain HTTP-HEADER values."
        :detail (type-of header)
        :operation :headers))
     (let ((name (http-header-name header))
           (content (http-header-content header)))
       (unless (%websocket-http-token-p name)
         (%websocket-http-fail
          "HTTP header names must be tokens."
          :detail name
          :operation :headers))
       (unless (stringp content)
         (%websocket-http-fail
          "HTTP header values must be strings."
          :detail name
          :operation :headers))
       (unless (%websocket-http-header-value-p content)
         (%websocket-http-fail
          "HTTP header values contain a forbidden control."
          :detail name
          :operation :headers))
       (cons name content)))
   headers))

(defun %websocket-http-header-values-p (headers name)
  (loop for pair in headers
        when (string-equal (car pair) name)
          collect (cdr pair)))

(defun %websocket-http-comma-separated-values (value)
  (let ((start 0)
        (result '()))
    (loop
      (let ((comma (position #\, value :start start)))
        (push (string-trim '(#\Space #\Tab)
                           (subseq value start (or comma (length value))))
              result)
        (if comma
            (setf start (1+ comma))
            (return (nreverse result)))))))

(defun %websocket-http-decimal-string-p (value)
  (and (stringp value)
       (plusp (length value))
       (every (lambda (character)
                (and (char>= character #\0)
                     (char<= character #\9)))
              value)))

(defun %websocket-http-bounded-integer
    (value radix name operation &optional maximum)
  (let ((limit (min most-positive-fixnum
                    (or maximum most-positive-fixnum)))
        (result 0))
    (unless (and (stringp value)
                 (plusp (length value)))
      (%websocket-http-fail
       "HTTP numeric values must be non-negative integers."
       :detail (list name value)
       :operation operation))
    (loop for character across value
          for digit = (digit-char-p character radix)
          do
             (unless digit
               (%websocket-http-fail
                "HTTP numeric values contain an invalid digit."
                :detail (list name value)
                :operation operation))
             (when (> result (floor (- limit digit) radix))
               (%websocket-http-fail
                "HTTP numeric value is outside the implementation range."
                :detail (list name value)
                :operation operation))
             (setf result (+ (* result radix) digit)))
    result))

(defun %websocket-http-decimal (value name &optional maximum)
  (unless (%websocket-http-decimal-string-p value)
    (%websocket-http-fail
     "HTTP numeric header values must be decimal ASCII integers."
     :detail (list name value)
     :operation :headers))
  (%websocket-http-bounded-integer value 10 name :headers maximum))

(defun %websocket-http-content-length (headers &optional maximum)
  (let ((values (%websocket-http-header-values-p headers "Content-Length")))
    (when values
      (let ((lengths
              (mapcan (lambda (value)
                        (mapcar (lambda (item)
                                  (%websocket-http-decimal
                                   (string-trim '(#\Space #\Tab) item)
                                   "Content-Length"
                                   maximum))
                                (%websocket-http-comma-separated-values value)))
                      values)))
        (unless (and lengths (apply #'= lengths))
          (%websocket-http-fail
           "Repeated Content-Length values must agree."
           :detail values
           :operation :headers))
        (first lengths)))))

(defun %websocket-http-transfer-codings (headers)
  (let ((values (%websocket-http-header-values-p headers "Transfer-Encoding")))
    (when values
      (let ((codings
              (mapcan (lambda (value)
                        (mapcar (lambda (item)
                                  (string-downcase
                                   (string-trim '(#\Space #\Tab) item)))
                                (%websocket-http-comma-separated-values value)))
                      values)))
        (unless (and (equal codings '("chunked")))
          (%websocket-http-fail
           "Only Transfer-Encoding: chunked is supported."
           :detail values
           :operation :headers))
        codings))))

(defun %websocket-http-connection-tokens (headers)
  (let ((pairs (if (every #'consp headers)
                   headers
                   (%websocket-http-header-pairs headers))))
    (mapcan
     (lambda (value)
       (mapcar (lambda (item)
                 (let ((token (string-trim '(#\Space #\Tab) item)))
                   (unless (%websocket-http-token-p token)
                     (%websocket-http-fail
                      "Connection field values must be non-empty tokens."
                      :detail token
                      :operation :headers))
                   (string-downcase token)))
               (%websocket-http-comma-separated-values value)))
     (%websocket-http-header-values-p pairs "Connection"))))

(defun %websocket-http-expect-continue-p (headers)
  (let ((values (%websocket-http-header-values-p headers "Expect")))
    (when values
      (let ((expectations
              (mapcan (lambda (value)
                        (mapcar
                         (lambda (item)
                           (string-downcase
                            (string-trim '(#\Space #\Tab) item)))
                         (%websocket-http-comma-separated-values value)))
                      values)))
        (unless (and expectations
                     (every (lambda (item)
                             (string= item "100-continue"))
                            expectations))
          (%websocket-http-fail
           "Only Expect: 100-continue is supported."
           :detail values
           :operation :headers))
        t))))

(defun %websocket-http-effective-headers
    (headers body trailers &key (no-body-p nil) (head-p nil) status)
  (let* ((pairs (%websocket-http-header-pairs headers))
         (trailer-pairs
           (%websocket-http-validate-trailer-pairs
            (%websocket-http-header-pairs trailers)))
         (content-length (%websocket-http-content-length pairs))
         (transfer-codings (%websocket-http-transfer-codings pairs))
         (status-no-body-p
           (and status (%websocket-http-no-body-status-p status)))
         (content-length-forbidden-p
           (and status
                (or (and (<= 100 status) (< status 200))
                    (= status 204)))))
    (%websocket-http-connection-tokens pairs)
    (when (and transfer-codings content-length)
      (%websocket-http-fail
       "Content-Length and Transfer-Encoding cannot both be sent."
       :operation :headers))
    (when (and trailer-pairs content-length)
      (%websocket-http-fail
       "HTTP trailers cannot be combined with Content-Length."
       :operation :trailers))
    (when (and content-length-forbidden-p content-length)
      (%websocket-http-fail
       "This response status cannot include Content-Length."
       :detail (list status content-length)
       :operation :headers))
    (when (and status-no-body-p
               transfer-codings
               (not (and status (= status 304))))
      (%websocket-http-fail
       "A response status that cannot carry a body cannot use Transfer-Encoding."
       :detail status
       :operation :headers))
    (when (and trailer-pairs
               (not (or transfer-codings
                        (and (null no-body-p) (not head-p)))))
      (%websocket-http-fail
       "HTTP trailers require chunked transfer coding."
       :operation :trailers))
    (let* ((chunked-p (or transfer-codings trailer-pairs))
           (body-valid-p (%websocket-http-octets-p body)))
      (unless body-valid-p
        (%websocket-http-fail
         "HTTP message bodies must be one-dimensional octet vectors."
         :detail (type-of body)
         :operation :body))
      (let* ((body-length (length body))
             (declared-length (or content-length body-length)))
        (when (and chunked-p (null transfer-codings))
          (push (cons "Transfer-Encoding" "chunked") pairs))
        (when (and no-body-p (plusp body-length))
          (%websocket-http-fail
           "A response that cannot carry a body received body bytes."
           :detail body-length
           :operation :body))
        (when (and content-length
                   (not head-p)
                   (not no-body-p)
                   (/= content-length body-length))
          (%websocket-http-fail
           "Content-Length does not match the HTTP body."
           :detail (list content-length body-length)
           :operation :body))
        (when (and no-body-p
                   content-length
                   (not (and status (= status 304)))
                   (/= content-length 0))
          (%websocket-http-fail
           "A response that cannot carry a body must have Content-Length zero."
           :detail content-length
           :operation :body))
        (when (and (not chunked-p)
                   (null content-length)
                   (not (and no-body-p (not head-p))))
          (push (cons "Content-Length" (princ-to-string body-length)) pairs))
        (when (and (eq no-body-p :no-body)
                   (null content-length))
          (push (cons "Content-Length" "0") pairs))
        (when (and status
                   (= status 205)
                   (null content-length))
          (push (cons "Content-Length" "0") pairs))
        (values pairs
                (cond (no-body-p :none)
                      (chunked-p :chunked)
                      (t :length))
                declared-length)))))

(defun %websocket-http-wire-header-name (name)
  (string-capitalize name))

(defun %websocket-http-append-headers (builder headers)
  (dolist (pair headers)
    (%websocket-http-builder-append-string
     builder
     (%websocket-http-wire-header-name (car pair)))
    (%websocket-http-builder-append-string builder ": ")
    (%websocket-http-builder-append-string builder (cdr pair))
    (%websocket-http-builder-append-string builder (string #\Return))
    (%websocket-http-builder-append-string builder (string #\Newline)))
  (%websocket-http-builder-append-string builder (string #\Return))
  (%websocket-http-builder-append-string builder (string #\Newline))
  builder)

(defun %websocket-http-append-body (builder body mode trailers)
  (ecase mode
    (:none nil)
    (:length
     (%websocket-http-builder-append-octets builder body))
    (:chunked
     (when (plusp (length body))
       (%websocket-http-builder-append-string
        builder
        (format nil "~X~C~C" (length body) #\Return #\Newline))
       (%websocket-http-builder-append-octets builder body)
       (%websocket-http-builder-append-string
        builder
        (format nil "~C~C" #\Return #\Newline)))
     (%websocket-http-builder-append-string
      builder
      (format nil "0~C~C" #\Return #\Newline))
     (dolist (pair trailers)
       (%websocket-http-builder-append-string
        builder
        (%websocket-http-wire-header-name (car pair)))
       (%websocket-http-builder-append-string builder ": ")
       (%websocket-http-builder-append-string builder (cdr pair))
       (%websocket-http-builder-append-string
        builder
        (format nil "~C~C" #\Return #\Newline)))
     (%websocket-http-builder-append-string
      builder
      (format nil "~C~C" #\Return #\Newline)))))

(defun serialize-http-request (request &key (include-body-p t))
  (unless (http-request-p request)
    (%websocket-http-fail
     "SERIALIZE-HTTP-REQUEST requires an HTTP request model."
     :detail (type-of request)
     :operation :serialize))
  (let* ((target (http-request-target request))
         (method (http-request-method request))
         (version (http-request-protocol-version request))
         (body (http-request-body request))
         (trailers (http-request-trailers request)))
    (unless (and (%websocket-http-token-p method)
                 (stringp version)
                 (string= version "HTTP/1.1"))
      (%websocket-http-fail
       "HTTP/1.1 serialization requires a token method and HTTP/1.1 version."
       :detail (list method version)
       :operation :serialize))
    (unless (%websocket-http-request-target-p target)
      (%websocket-http-fail
       "HTTP request-target is not a valid wire token."
       :detail target
       :operation :serialize))
    (%websocket-http-target-uri
     target
     (http-request-headers request)
     method
     nil)
    (%websocket-http-expect-continue-p
     (%websocket-http-header-pairs (http-request-headers request)))
    (multiple-value-bind (headers mode length)
        (%websocket-http-effective-headers
         (http-request-headers request) body trailers)
      (declare (ignore length))
      (let ((builder (%websocket-http-builder)))
        (%websocket-http-builder-append-string
         builder
         (format nil "~A ~A ~A~C~C"
                 method
                 target
                 version
                 #\Return
                 #\Newline))
        (%websocket-http-append-headers builder headers)
        (when include-body-p
          (%websocket-http-append-body
           builder body mode (%websocket-http-header-pairs trailers)))
        (%websocket-http-builder-result builder)))))

(defun serialize-http-request-body (request)
  (unless (http-request-p request)
    (%websocket-http-fail
     "SERIALIZE-HTTP-REQUEST-BODY requires an HTTP request model."
     :detail (type-of request)
     :operation :serialize))
  (serialize-http-request request :include-body-p nil)
  (let ((body (http-request-body request))
        (trailers (http-request-trailers request)))
    (multiple-value-bind (headers mode length)
        (%websocket-http-effective-headers
         (http-request-headers request) body trailers)
      (declare (ignore headers length))
      (let ((builder (%websocket-http-builder)))
        (%websocket-http-append-body
         builder body mode (%websocket-http-header-pairs trailers))
        (%websocket-http-builder-result builder)))))

(defun serialize-http-response (response &key head-p)
  (unless (http-response-p response)
    (%websocket-http-fail
     "SERIALIZE-HTTP-RESPONSE requires an HTTP response model."
     :detail (type-of response)
     :operation :serialize))
  (let* ((status (http-response-status response))
         (version (http-response-protocol-version response))
         (body (http-response-body response))
         (trailers (http-response-trailers response)))
    (unless (and (integerp status)
                 (<= 100 status 999))
      (%websocket-http-fail
       "HTTP response status must be a three-digit value."
       :detail status
       :operation :serialize))
    (unless (%websocket-http-header-value-p (http-response-reason response))
      (%websocket-http-fail
       "HTTP response reason contains a forbidden control."
       :detail (http-response-reason response)
       :operation :serialize))
    (unless (and (stringp version)
                 (string= version "HTTP/1.1"))
      (%websocket-http-fail
       "HTTP/1.1 serialization requires an HTTP/1.1 response version."
       :detail version
       :operation :serialize))
    (let ((no-body-p (or (and (<= 100 status) (< status 200))
                         (= status 204)
                         (= status 205)
                         (= status 304))))
      (multiple-value-bind (headers mode length)
          (%websocket-http-effective-headers
           (http-response-headers response)
           body
           trailers
           :no-body-p (and no-body-p :status)
           :head-p head-p
           :status status)
        (declare (ignore length))
        (let ((builder (%websocket-http-builder)))
          (%websocket-http-builder-append-string
           builder
           (format nil "~A ~D ~A~C~C"
                   version
                   status
                   (http-response-reason response)
                   #\Return
                   #\Newline))
          (%websocket-http-append-headers builder headers)
          (%websocket-http-append-body
           builder body (if head-p :none mode)
           (%websocket-http-header-pairs trailers))
          (%websocket-http-builder-result builder))))))

(defun write-http-request
    (request output-stream &key timeout deadline
             (include-body-p t)
             (clock-function #'%websocket-monotonic-time))
  (let ((effective-deadline
          (%websocket-http-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
       (write-sequence
        (serialize-http-request request :include-body-p include-body-p)
        output-stream)
       (force-output output-stream)
       request)
     effective-deadline
     clock-function
     :http-write)))

(defun write-http-request-body
    (request output-stream &key timeout deadline
             (clock-function #'%websocket-monotonic-time))
  (let ((effective-deadline
          (%websocket-http-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
       (write-sequence (serialize-http-request-body request) output-stream)
       (force-output output-stream)
       request)
     effective-deadline
     clock-function
     :http-write)))

(defun write-http-response
    (response output-stream &key head-p timeout deadline
             (clock-function #'%websocket-monotonic-time))
  (let ((effective-deadline
          (%websocket-http-deadline timeout deadline clock-function)))
    (%websocket-call-with-deadline
     (lambda ()
       (write-sequence (serialize-http-response response :head-p head-p)
                       output-stream)
       (force-output output-stream)
       response)
     effective-deadline
     clock-function
     :http-write)))

(defstruct (%websocket-http-reader
            (:constructor %make-websocket-http-reader
                (source stream-p position count max-header-bytes
                 header-count max-body-bytes deadline clock-function)))
  source
  stream-p
  position
  count
  max-header-bytes
  header-count
  max-body-bytes
  deadline
  clock-function)

(defun %websocket-http-check-deadline (reader operation)
  (when (and (%websocket-http-reader-deadline reader)
             (>= (funcall (%websocket-http-reader-clock-function reader))
                 (%websocket-http-reader-deadline reader)))
    (error 'websocket-timeout
           :kind operation
           :operation operation
           :message "The HTTP operation exceeded its deadline."
           :detail operation)))

(defun %websocket-http-reader-next (reader)
  (%websocket-http-check-deadline reader :read)
  (let ((source (%websocket-http-reader-source reader))
        (byte nil)
        (eof-p nil))
    (if (%websocket-http-reader-stream-p reader)
        (multiple-value-setq (byte eof-p)
          (%websocket-call-with-deadline
           (lambda () (read-byte source nil nil))
           (%websocket-http-reader-deadline reader)
           (%websocket-http-reader-clock-function reader)
           :http-read))
        (if (< (%websocket-http-reader-position reader) (length source))
            (progn
              (setf byte (aref source (%websocket-http-reader-position reader)))
              (incf (%websocket-http-reader-position reader)))
            (setf eof-p t)))
    (if eof-p
        (values nil t)
        (progn
          (incf (%websocket-http-reader-count reader))
          (values byte nil)))))

(defun %websocket-http-reader-next-header-byte (reader)
  (multiple-value-bind (byte eof-p)
      (%websocket-http-reader-next reader)
    (unless eof-p
      (incf (%websocket-http-reader-header-count reader)))
    (values byte eof-p)))

(defun %websocket-http-reader-section-count (reader start header-p)
  (if header-p
      (- (%websocket-http-reader-header-count reader) start)
      (- (%websocket-http-reader-count reader) start)))

(defun %websocket-http-reader-header-count-ok-p (reader start &key (header-p t))
  (or (null (%websocket-http-reader-max-header-bytes reader))
      (<= (%websocket-http-reader-section-count reader start header-p)
          (%websocket-http-reader-max-header-bytes reader))))

(defun %websocket-http-reader-line-count-ok-p
    (reader start max-line-bytes)
  (or (null max-line-bytes)
      (<= (%websocket-http-reader-section-count reader start nil)
          max-line-bytes)))

(defun %websocket-http-reader-line
    (reader header-start &key allow-eof-p (count-header-p t)
                                 max-line-bytes)
  (let ((characters '())
        (line-start (%websocket-http-reader-count reader)))
    (loop
      (multiple-value-bind
          (byte eof-p)
          (if count-header-p
              (%websocket-http-reader-next-header-byte reader)
              (%websocket-http-reader-next reader))
        (when eof-p
          (if (and allow-eof-p (null characters))
              (return (values nil t))
              (%websocket-http-fail
               "Unexpected end of stream inside an HTTP line."
               :operation :parse)))
        (cond
          ((= byte #x0d)
           (multiple-value-bind (next next-eof-p)
               (if count-header-p
                   (%websocket-http-reader-next-header-byte reader)
                   (%websocket-http-reader-next reader))
             (when (or next-eof-p (/= next #x0a))
               (%websocket-http-fail
                "HTTP lines must end with CRLF."
                :operation :parse)))
           (unless (%websocket-http-reader-line-count-ok-p
                    reader line-start max-line-bytes)
             (%websocket-http-size-fail
              "An HTTP line exceeded its configured byte limit."
              max-line-bytes
              (%websocket-http-reader-section-count reader line-start nil)
              :header-limit))
           (unless (%websocket-http-reader-header-count-ok-p
                    reader
                    (if count-header-p header-start line-start)
                    :header-p count-header-p)
             (%websocket-http-size-fail
              "The HTTP header section exceeded its byte limit."
              (%websocket-http-reader-max-header-bytes reader)
              (%websocket-http-reader-section-count
               reader
               (if count-header-p header-start line-start)
               count-header-p)
              :header-limit))
           (return (values (coerce (nreverse characters) 'string) nil)))
          ((= byte #x0a)
           (%websocket-http-fail
            "HTTP lines must end with CRLF rather than bare LF."
            :operation :parse))
          (t
           (push (code-char byte) characters)
           (unless (%websocket-http-reader-line-count-ok-p
                    reader line-start max-line-bytes)
             (%websocket-http-size-fail
              "An HTTP line exceeded its configured byte limit."
              max-line-bytes
              (%websocket-http-reader-section-count reader line-start nil)
              :header-limit))
           (unless (%websocket-http-reader-header-count-ok-p
                    reader
                    (if count-header-p header-start line-start)
                    :header-p count-header-p)
             (%websocket-http-size-fail
              "The HTTP header section exceeded its byte limit."
              (%websocket-http-reader-max-header-bytes reader)
              (%websocket-http-reader-section-count
               reader
               (if count-header-p header-start line-start)
               count-header-p)
              :header-limit))))))))

(defun %websocket-http-header-name-p (name)
  (%websocket-http-token-p name))

(defun %websocket-http-forbidden-trailer-name-p (name)
  (member name '("Connection"
                 "Content-Length"
                 "Host"
                 "Keep-Alive"
                 "Proxy-Authenticate"
                 "Proxy-Authentication-Info"
                 "Proxy-Authorization"
                 "TE"
                 "Trailer"
                 "Transfer-Encoding"
                 "Upgrade")
          :test #'string-equal))

(defun %websocket-http-validate-trailer-pairs (pairs)
  (dolist (pair pairs pairs)
    (when (%websocket-http-forbidden-trailer-name-p (car pair))
      (%websocket-http-fail
       "An HTTP trailer contains a field that cannot be sent as a trailer."
       :detail (car pair)
       :operation :trailers))))

(defun %websocket-http-parse-headers
    (reader header-start max-fields &optional (initial-count 0))
  (let ((headers '())
        (field-count initial-count))
    (loop
      (let ((line (%websocket-http-reader-line reader header-start)))
        (when (zerop (length line))
          (return (values (nreverse headers) field-count)))
        (when (member (char line 0) '(#\Space #\Tab))
          (%websocket-http-fail
           "Obsolete folded HTTP header lines are not accepted."
           :operation :headers))
        (let ((colon (position #\: line)))
          (unless (and colon (plusp colon))
            (%websocket-http-fail
             "HTTP header lines must contain a field name and colon."
             :detail line
             :operation :headers))
          (let* ((name (subseq line 0 colon))
                 (value (string-trim '(#\Space #\Tab)
                                     (subseq line (1+ colon)))))
            (unless (%websocket-http-header-name-p name)
              (%websocket-http-fail
               "An HTTP header field name is not a token."
               :detail name
               :operation :headers))
            (unless (%websocket-http-header-value-p value)
              (%websocket-http-fail
               "An HTTP header field value contains a forbidden control."
               :detail name
               :operation :headers))
            (incf field-count)
            (when (and max-fields (> field-count max-fields))
              (%websocket-http-size-fail
               "The HTTP header field count exceeded its limit."
               max-fields
               field-count
               :header-limit))
            (push (make-http-header name value) headers)))))))

(defun %websocket-http-parse-request-line (line)
  (let* ((first-space (position #\Space line))
         (second-space (and first-space
                           (position #\Space line :start (1+ first-space)))))
    (unless (and first-space second-space
                 (plusp first-space)
                 (> second-space (1+ first-space))
                 (< (1+ second-space) (length line)))
      (%websocket-http-fail
       "An HTTP request line does not contain exactly three fields."
       :detail line
       :operation :request-line))
    (let ((method (subseq line 0 first-space))
          (target (subseq line (1+ first-space) second-space))
          (version (subseq line (1+ second-space))))
      (when (or (find #\Space version)
                (find #\Tab version)
                (not (%websocket-http-token-p method))
                (not (%websocket-http-request-target-p target)))
        (%websocket-http-fail
         "The HTTP request line contains invalid whitespace or tokens."
         :detail line
         :operation :request-line))
      (unless (string= version "HTTP/1.1")
        (%websocket-http-fail
         "Only HTTP/1.1 request lines are accepted."
         :detail version
         :operation :request-line))
      (values method target version))))

(defun %websocket-http-parse-response-line (line)
  (let ((space (position #\Space line)))
    (unless (and space (= space 8) (< (1+ space) (length line)))
      (%websocket-http-fail
       "An HTTP response line has an invalid protocol prefix."
       :detail line
       :operation :status-line))
    (let* ((version (subseq line 0 space))
           (status-start (1+ space))
           (second-space (position #\Space line :start status-start))
           (status-end (or second-space (length line)))
           (status-text (subseq line status-start status-end))
           (reason (if second-space
                       (string-trim '(#\Space #\Tab)
                                    (subseq line (1+ second-space)))
                       "")))
      (unless (and (string= version "HTTP/1.1")
                   (= (length status-text) 3)
                   (every (lambda (character)
                            (and (char>= character #\0)
                                 (char<= character #\9)))
                          status-text))
        (%websocket-http-fail
         "The HTTP response status line is invalid."
         :detail line
         :operation :status-line))
      (let ((status (parse-integer status-text)))
        (unless (<= 100 status 999)
          (%websocket-http-fail
           "The HTTP response status must be a three-digit value."
           :detail line
           :operation :status-line))
        (unless (%websocket-http-header-value-p reason)
          (%websocket-http-fail
           "The HTTP response reason contains a forbidden control."
           :detail reason
           :operation :status-line))
        (values version status reason)))))

(defun %websocket-http-port-text-p (value)
  (handler-case
      (progn
        (%websocket-http-decimal value "authority port" 65535)
        t)
    (error () nil)))

(defun %websocket-http-authority-p (authority)
  (and (stringp authority)
       (plusp (length authority))
       (every (lambda (character)
                (<= #x21 (char-code character) #x7e))
              authority)
       (not (find-if (lambda (character)
                       (find character "/?#@" :test #'char=))
                     authority))
       (let* ((length (length authority))
              (bracketed-p (char= (char authority 0) #\[))
              (closing-bracket
                (and bracketed-p (position #\] authority)))
              (host-end (if bracketed-p
                            closing-bracket
                            (or (position #\: authority) length)))
              (port-start
                (cond
                  ((not bracketed-p) (position #\: authority))
                  ((and closing-bracket
                        (< (1+ closing-bracket) length)
                        (char= (char authority (1+ closing-bracket)) #\:))
                   (1+ closing-bracket))))
              (port-text (and port-start
                              (subseq authority (1+ port-start)))))
         (and host-end
              (> host-end (if bracketed-p 1 0))
              (if bracketed-p
                  (and (= (count #\[ authority) 1)
                       (= (count #\] authority) 1)
                       (or (= (1+ closing-bracket) length)
                           (and port-start
                                (%websocket-http-port-text-p port-text))))
                  (and (not (find #\[ authority))
                       (not (find #\] authority))
                       (or (null port-start)
                           (%websocket-http-port-text-p port-text))))
              (handler-case
                  (let ((uri (parse-http-uri
                              (format nil "http://~A/" authority))))
                    (and (stringp (http-uri-host uri))
                         (plusp (length (http-uri-host uri)))))
                (error () nil))))))

(defun %websocket-http-authority-header (headers default-authority)
  (let ((values (http-header-values headers "Host")))
    (let ((authority
            (cond ((and values (null (cdr values)))
                   (first values))
                  ((and (null values) default-authority)
                   default-authority)
                  (values
                   (%websocket-http-fail
                    "An HTTP request must contain exactly one Host field."
                    :detail values
                    :operation :request))
                  (t
                   (%websocket-http-fail
                    "An HTTP/1.1 request requires a Host field."
                    :operation :request)))))
      (unless (%websocket-http-authority-p authority)
        (%websocket-http-fail
         "The HTTP Host field is not a valid authority."
         :detail authority
         :operation :request))
      authority)))

(defun %websocket-http-connect-authority-p (target)
  (and (%websocket-http-authority-p target)
       (if (char= (char target 0) #\[)
           (let ((closing-bracket (position #\] target)))
             (and closing-bracket
                  (< (1+ closing-bracket) (length target))
                  (char= (char target (1+ closing-bracket)) #\:)))
           (position #\: target))))

(defun %websocket-http-target-uri (target headers method default-authority)
  (when (find #\# target)
    (%websocket-http-fail
     "An HTTP request-target must not contain a URI fragment."
     :detail target
     :operation :request))
  (let ((authority (%websocket-http-authority-header
                    headers default-authority)))
    (handler-case
        (cond
          ((or (and (>= (length target) 7)
                    (string-equal target "http://" :end1 7))
               (and (>= (length target) 8)
                    (string-equal target "https://" :end1 8)))
           (let ((uri (parse-http-uri target)))
             (unless (string-equal (http-uri-authority uri) authority)
               (%websocket-http-fail
                "Absolute-form request-target authority must match Host."
                :detail (list (http-uri-authority uri) authority)
                :operation :request))
             uri))
          ((string= target "*")
           (make-http-uri :scheme "http" :authority authority :path "/"))
          ((string= method "CONNECT")
           (unless (%websocket-http-connect-authority-p target)
             (%websocket-http-fail
              "CONNECT request-target must use authority-form host:port."
              :detail target
              :operation :request))
           (unless (string-equal target authority)
             (%websocket-http-fail
              "CONNECT request-target authority must match Host."
              :detail (list target authority)
              :operation :request))
           (parse-http-uri (format nil "http://~A/" target)))
          ((and (plusp (length target))
                (char= (char target 0) #\/))
           (let ((question (position #\? target)))
             (make-http-uri
              :scheme "http"
              :authority authority
              :path (if question (subseq target 0 question) target)
              :query (and question (subseq target (1+ question))))))
          (t
           (%websocket-http-fail
            "The HTTP request-target form is unsupported."
            :detail target
            :operation :request)))
      (websocket-http-error (condition)
        (error condition))
      (error (condition)
        (%websocket-http-fail
         "The HTTP request-target could not be converted to a URI."
         :detail (list target condition)
         :operation :request)))))

(defun %websocket-http-limit (value name)
  (unless (or (null value)
              (and (integerp value) (>= value 0)))
    (%websocket-http-fail
     "HTTP resource limits must be non-negative integers or NIL."
     :detail (list name value)
     :operation :limits))
  value)

(defun %websocket-http-deadline (timeout deadline clock-function)
  (unless (functionp clock-function)
    (%websocket-http-fail
     "The HTTP clock-function must be callable."
     :detail clock-function
     :operation :deadline))
  (when (and timeout
             (or (not (realp timeout)) (< timeout 0)))
    (%websocket-http-fail
     "HTTP timeout must be a non-negative real number or NIL."
     :detail timeout
     :operation :deadline))
  (when (and deadline
             (or (not (realp deadline)) (minusp deadline)))
    (%websocket-http-fail
     "HTTP deadline must be a non-negative real number or NIL."
     :detail deadline
     :operation :deadline))
  (let ((relative (and timeout
                       (+ (funcall clock-function) timeout))))
    (cond ((and relative deadline) (min relative deadline))
          (relative relative)
          (deadline deadline)
          (t nil))))

(defun %websocket-http-make-reader
    (input timeout deadline max-header-bytes max-body-bytes clock-function)
  (unless (or (streamp input) (%websocket-http-octets-p input))
    (%websocket-http-fail
     "HTTP input must be a binary stream or an octet vector."
     :detail (type-of input)
     :operation :parse))
  (let ((header-limit (%websocket-http-limit
                      max-header-bytes "max-header-bytes"))
        (body-limit (%websocket-http-limit
                     max-body-bytes "max-body-bytes")))
    (%make-websocket-http-reader
     input
     (streamp input)
     0
     0
     header-limit
     0
     body-limit
     (%websocket-http-deadline timeout deadline clock-function)
     clock-function)))

(defun %websocket-http-body-limit-ok-p (reader total additional)
  (or (null (%websocket-http-reader-max-body-bytes reader))
      (<= (+ total additional)
          (%websocket-http-reader-max-body-bytes reader))))

(defun %websocket-http-body-fail (reader total)
  (%websocket-http-size-fail
   "The HTTP message body exceeded its configured byte limit."
   (%websocket-http-reader-max-body-bytes reader)
   total
   :body-limit))

(defun %websocket-http-body-builder-result (builder)
  (if builder
      (let ((result (make-array (length builder)
                                :element-type '(unsigned-byte 8))))
        (replace result builder)
        result)
      (make-array 0 :element-type '(unsigned-byte 8))))

(defun %websocket-http-read-exact
    (reader length on-body-chunk collect-body-p &optional (total 0))
  (unless (%websocket-http-body-limit-ok-p reader total length)
    (%websocket-http-body-fail reader (+ total length)))
  (let ((builder (and collect-body-p (%websocket-http-builder)))
        (remaining length)
        (body-total total))
    (loop while (plusp remaining)
          do (let* ((chunk-length (min remaining 8192))
                    (chunk (make-array chunk-length
                                       :element-type '(unsigned-byte 8))))
               (loop for index below chunk-length
                     do (multiple-value-bind (byte eof-p)
                            (%websocket-http-reader-next reader)
                          (when eof-p
                            (%websocket-http-fail
                             "The HTTP message ended before Content-Length bytes were read."
                             :detail (list :expected length
                                           :observed (- length remaining))
                             :operation :body))
                          (setf (aref chunk index) byte)))
               (when on-body-chunk
                 (funcall on-body-chunk chunk))
               (when builder
                 (%websocket-http-builder-append-octets builder chunk))
               (decf remaining chunk-length)
               (incf body-total chunk-length)))
    (values (%websocket-http-body-builder-result builder) body-total)))

(defun %websocket-http-read-until-eof
    (reader on-body-chunk collect-body-p &optional (total 0))
  (unless (%websocket-http-body-limit-ok-p reader total 0)
    (%websocket-http-body-fail reader total))
  (let* ((builder (and collect-body-p (%websocket-http-builder)))
         (body-total total)
         (body-limit (%websocket-http-reader-max-body-bytes reader))
         (chunk-size (if body-limit
                         (max 1 (min 8192 (max 0 (- body-limit total))))
                         8192))
         (chunk (make-array chunk-size :element-type '(unsigned-byte 8)))
         (chunk-length 0))
    (labels ((flush-chunk ()
               (when (plusp chunk-length)
                 (let ((output (subseq chunk 0 chunk-length)))
                   (unless (%websocket-http-body-limit-ok-p
                            reader body-total chunk-length)
                     (%websocket-http-body-fail
                      reader (+ body-total chunk-length)))
                   (when on-body-chunk
                     (funcall on-body-chunk output))
                   (when builder
                     (%websocket-http-builder-append-octets builder output))
                   (incf body-total chunk-length)
                   (setf chunk-length 0)))))
      (loop
        (multiple-value-bind (byte eof-p) (%websocket-http-reader-next reader)
          (when eof-p
            (flush-chunk)
            (return))
          (unless (%websocket-http-body-limit-ok-p reader body-total 1)
            (%websocket-http-body-fail reader (1+ body-total)))
          (setf (aref chunk chunk-length) byte)
          (incf chunk-length)
          (when (= chunk-length (length chunk))
            (flush-chunk))))
    (values (%websocket-http-body-builder-result builder) body-total))))

(defun %websocket-http-read-crlf (reader operation)
  (multiple-value-bind (return-byte return-eof-p)
      (%websocket-http-reader-next reader)
    (multiple-value-bind (linefeed-byte linefeed-eof-p)
        (%websocket-http-reader-next reader)
      (unless (and (not return-eof-p)
                   (not linefeed-eof-p)
                   (= return-byte #x0d)
                   (= linefeed-byte #x0a))
        (%websocket-http-fail
         "An HTTP chunk was not followed by CRLF."
        :detail operation
        :operation :body)))))

(defun %websocket-http-chunk-quoted-text-p (character)
  (let ((code (char-code character)))
    (or (= code #x09)
        (= code #x20)
        (= code #x21)
        (<= #x23 code #x5b)
        (<= #x5d code #x7e)
        (<= #x80 code #xff))))

(defun %websocket-http-chunk-quoted-pair-p (character)
  (let ((code (char-code character)))
    (or (= code #x09)
        (= code #x20)
        (<= #x21 code #x7e)
        (<= #x80 code #xff))))

(defun %websocket-http-chunk-extension-value-end (line start)
  (if (and (< start (length line))
           (char= (char line start) #\"))
      (let ((index (1+ start)))
        (loop while (< index (length line))
              for character = (char line index)
              do (cond
                   ((char= character #\")
                    (return-from %websocket-http-chunk-extension-value-end
                      (1+ index)))
                   ((char= character #\\)
                    (incf index)
                    (when (or (>= index (length line))
                              (not (%websocket-http-chunk-quoted-pair-p
                                    (char line index))))
                      (%websocket-http-fail
                       "An HTTP chunk extension has an invalid quoted-pair."
                       :detail line
                       :operation :body))
                    (incf index))
                   ((%websocket-http-chunk-quoted-text-p character)
                    (incf index))
                   (t
                    (%websocket-http-fail
                     "An HTTP chunk extension has an invalid quoted-string."
                     :detail line
                     :operation :body))))
        (%websocket-http-fail
         "An HTTP chunk extension has an unterminated quoted-string."
         :detail line
         :operation :body))
      (let ((index start))
        (loop while (and (< index (length line))
                         (not (find (char line index) '(#\Space #\Tab #\= #\;))))
              do (incf index))
        (unless (and (< start index)
                     (%websocket-http-token-p (subseq line start index)))
          (%websocket-http-fail
           "An HTTP chunk extension value is not a token."
           :detail line
           :operation :body))
        index)))

(defun %websocket-http-validate-chunk-extensions (line semicolon)
  (when semicolon
    (let ((index semicolon)
          (length (length line)))
      (labels ((skip-bws ()
                 (loop while (and (< index length)
                                  (find (char line index)
                                        '(#\Space #\Tab)))
                       do (incf index))))
        (loop
          (skip-bws)
          (unless (and (< index length)
                       (char= (char line index) #\;))
            (%websocket-http-fail
             "An HTTP chunk extension must start with semicolon."
             :detail line
             :operation :body))
          (incf index)
          (skip-bws)
          (let ((name-start index))
            (loop while (and (< index length)
                             (not (find (char line index)
                                        '(#\Space #\Tab #\= #\;))))
                  do (incf index))
            (unless (and (< name-start index)
                         (%websocket-http-token-p
                          (subseq line name-start index)))
              (%websocket-http-fail
               "An HTTP chunk extension name is not a token."
               :detail line
               :operation :body)))
          (skip-bws)
          (when (and (< index length) (char= (char line index) #\=))
            (incf index)
            (skip-bws)
            (setf index
                  (%websocket-http-chunk-extension-value-end line index)))
          (skip-bws)
          (when (= index length)
            (return))
          (unless (char= (char line index) #\;)
            (%websocket-http-fail
             "An HTTP chunk extension contains unexpected characters."
             :detail line
             :operation :body)))))))

(defun %websocket-http-chunk-size (line &optional maximum)
  (let* ((semicolon (position #\; line))
         (size-text (string-trim '(#\Space #\Tab)
                                 (if semicolon
                                     (subseq line 0 semicolon)
                                     line))))
    (unless (and (plusp (length size-text))
                 (every (lambda (character)
                          (%websocket-hex-digit-p character))
                        size-text))
      (%websocket-http-fail
       "An HTTP chunk-size line is not hexadecimal."
       :detail line
       :operation :body))
    (%websocket-http-validate-chunk-extensions line semicolon)
    (%websocket-http-bounded-integer
     size-text 16 "chunk-size" :body maximum)))

(defun %websocket-http-read-chunked
    (reader header-start max-fields initial-field-count
            on-body-chunk collect-body-p)
  (let ((builder (and collect-body-p (%websocket-http-builder)))
        (body-total 0)
        (trailers '())
        (field-count initial-field-count))
    (declare (ignorable field-count))
    (loop
      (let ((size (%websocket-http-chunk-size
                 (%websocket-http-reader-line
                    reader header-start
                    :count-header-p nil
                    :max-line-bytes
                    (%websocket-http-reader-max-header-bytes reader)))))
        (when (zerop size)
          (multiple-value-setq (trailers field-count)
            (%websocket-http-parse-headers
             reader header-start max-fields field-count))
          (%websocket-http-validate-trailer-pairs
           (%websocket-http-header-pairs trailers))
          (return))
        (unless (%websocket-http-body-limit-ok-p reader body-total size)
          (%websocket-http-body-fail reader (+ body-total size)))
        (multiple-value-bind (chunk chunk-total)
            (%websocket-http-read-exact
             reader size on-body-chunk collect-body-p body-total)
          (declare (ignore chunk-total))
          (when builder
            (%websocket-http-builder-append-octets builder chunk))
          (incf body-total size))
        (%websocket-http-read-crlf reader :chunk)))
    (values (%websocket-http-body-builder-result builder)
            body-total
            trailers)))

(defun %websocket-http-no-body-status-p (status)
  (or (and (<= 100 status) (< status 200))
      (= status 204)
      (= status 205)
      (= status 304)))

(defun %websocket-http-message-framing
    (headers &key request-p status request-method head-p allow-eof-p)
  (let* ((pairs (%websocket-http-header-pairs headers))
         (content-length (%websocket-http-content-length pairs))
         (transfer-codings (%websocket-http-transfer-codings pairs))
         (connect-p (and request-method
                         status
                         (<= 200 status)
                         (< status 300)
                (string= request-method "CONNECT")))
         (no-body-p (or head-p
                        connect-p
                        (and status (%websocket-http-no-body-status-p status)))))
    (when (and content-length transfer-codings)
      (%websocket-http-fail
       "Content-Length and Transfer-Encoding cannot both frame a message."
       :operation :headers))
    (when (and no-body-p transfer-codings
               (not (or head-p connect-p
                        (and status (= status 304)))))
      (%websocket-http-fail
       "A response status that cannot carry a body cannot use Transfer-Encoding."
       :operation :headers))
    (when (and content-length status
               (or (and (<= 100 status) (< status 200))
                   (= status 204)))
      (%websocket-http-fail
       "This response status cannot contain Content-Length."
       :operation :headers))
    (when (and no-body-p content-length
               (not (or head-p connect-p
                        (and status (= status 304))))
               (/= content-length 0))
      (%websocket-http-fail
       "A response that cannot carry a body must have Content-Length zero."
       :operation :headers))
    (cond
      (no-body-p
       (values :none content-length))
      (transfer-codings
       (values :chunked nil))
      (content-length
       (values :length content-length))
      (request-p
       (values :none 0))
      (allow-eof-p
       (values :eof nil))
      (t
       (%websocket-http-fail
        "A response body needs Content-Length, chunked encoding, or allow-eof-p."
        :operation :body)))))

(defun %websocket-http-read-body
    (reader mode length header-start max-fields initial-field-count
            on-body-chunk collect-body-p)
  (ecase mode
    (:none
     (values (make-array 0 :element-type '(unsigned-byte 8)) 0 '()))
    (:length
     (multiple-value-bind (body total)
         (%websocket-http-read-exact
          reader length on-body-chunk collect-body-p)
       (values body total '())))
    (:chunked
     (%websocket-http-read-chunked
      reader header-start max-fields initial-field-count
      on-body-chunk collect-body-p))
    (:eof
     (multiple-value-bind (body total)
         (%websocket-http-read-until-eof
          reader on-body-chunk collect-body-p)
       (values body total '())))))

(defun %websocket-http-model-failure (condition operation detail)
  (if (typep condition 'websocket-error)
      (error condition)
      (%websocket-http-fail
       "The HTTP message model rejected parsed wire data."
       :detail detail
       :operation operation)))

(defun %websocket-http-parse-request-from-reader
    (reader max-fields default-authority on-headers on-body-chunk
            collect-body-p allow-eof-p)
  (let ((header-start (%websocket-http-reader-header-count reader)))
    (multiple-value-bind (line eof-p)
        (%websocket-http-reader-line reader header-start
                                     :allow-eof-p allow-eof-p)
      (when eof-p
        (return-from %websocket-http-parse-request-from-reader
          (values nil 0)))
      (multiple-value-bind (method target version)
          (%websocket-http-parse-request-line line)
        (declare (ignore version))
        (multiple-value-bind (headers field-count)
            (%websocket-http-parse-headers reader header-start max-fields)
          (%websocket-http-connection-tokens headers)
          (let ((target-uri (%websocket-http-target-uri
                             target headers method default-authority)))
            (multiple-value-bind (mode length)
                (%websocket-http-message-framing headers :request-p t)
              (%websocket-http-expect-continue-p
               (%websocket-http-header-pairs headers))
              (let ((header-request
                      (handler-case
                          (make-http-request
                           :method method
                           :uri target-uri
                           :request-target target
                           :headers headers
                           :trailers nil
                           :body (make-array
                                  0 :element-type '(unsigned-byte 8))
                           :protocol-version "HTTP/1.1")
                        (error (condition)
                          (%websocket-http-model-failure
                           condition :request (list method target))))))
                (when on-headers
                  (funcall on-headers header-request mode length))
                (multiple-value-bind (body body-length trailers)
                    (%websocket-http-read-body
                     reader mode length header-start max-fields field-count
                     on-body-chunk collect-body-p)
                  (declare (ignore body-length))
                  (handler-case
                      (values
                       (make-http-request
                        :method method
                        :uri target-uri
                        :request-target target
                        :headers headers
                        :trailers trailers
                        :body body
                        :protocol-version "HTTP/1.1")
                       field-count)
                    (error (condition)
                      (%websocket-http-model-failure
                       condition :request (list method target)))))))))))))

(defun %websocket-http-parse-response-from-reader
    (reader max-fields on-body-chunk collect-body-p request-method head-p
            allow-eof-p)
  (let* ((header-start (%websocket-http-reader-header-count reader))
         (line (%websocket-http-reader-line reader header-start)))
    (multiple-value-bind (version status reason)
        (%websocket-http-parse-response-line line)
      (multiple-value-bind (headers field-count)
          (%websocket-http-parse-headers reader header-start max-fields)
        (%websocket-http-connection-tokens headers)
        (multiple-value-bind (mode length)
            (%websocket-http-message-framing
             headers :status status
             :request-method request-method
             :head-p (or head-p
                         (and request-method
                              (string= request-method "HEAD")))
             :allow-eof-p allow-eof-p)
          (multiple-value-bind (body body-length trailers)
              (%websocket-http-read-body
               reader mode length header-start max-fields field-count
               on-body-chunk collect-body-p)
            (declare (ignore body-length))
            (handler-case
                (values
                 (make-http-response
                  :status status
                  :reason reason
                  :headers headers
                  :trailers trailers
                  :body body
                  :protocol-version version)
                 field-count)
              (error (condition)
                (%websocket-http-model-failure
                 condition :response (list status reason))))))))))

(defun parse-http-request
    (input &key timeout deadline
             (max-header-bytes +websocket-default-max-header-bytes+)
             (max-fields +websocket-default-max-header-fields+)
             (max-body-bytes +websocket-default-max-body-bytes+)
             default-authority on-headers on-body-chunk
             (collect-body-p t) allow-eof-p
             (clock-function #'%websocket-monotonic-time))
  "Parse one binary-safe HTTP/1.1 request.

The first value is an HTTP-REQUEST and the second is the number of bytes
consumed.  A vector input is parsed without reading beyond its end.  A stream
input is read incrementally; ON-BODY-CHUNK receives each body chunk before it is
optionally collected.  When ALLOW-EOF-P is true, clean EOF before the next
request line returns NIL and the consumed byte count instead of signalling.
ON-HEADERS receives a header-only request, its framing mode, and declared body
length before any body bytes are read."
  (unless (or (null max-fields)
              (and (integerp max-fields) (>= max-fields 0)))
    (%websocket-http-fail
     "max-fields must be a non-negative integer or NIL."
     :detail max-fields
     :operation :limits))
  (unless (or (null on-body-chunk) (functionp on-body-chunk))
    (%websocket-http-fail
     "on-body-chunk must be callable or NIL."
     :detail on-body-chunk
     :operation :body))
  (unless (or (null on-headers) (functionp on-headers))
    (%websocket-http-fail
     "on-headers must be callable or NIL."
     :detail on-headers
     :operation :headers))
  (let ((reader (%websocket-http-make-reader
                 input timeout deadline max-header-bytes
                 max-body-bytes clock-function)))
    (multiple-value-bind (request fields)
        (%websocket-http-parse-request-from-reader
         reader max-fields default-authority on-headers on-body-chunk
         collect-body-p allow-eof-p)
      (declare (ignore fields))
      (values request (%websocket-http-reader-count reader)))))

(defun parse-http-response
    (input &key timeout deadline
             (max-header-bytes +websocket-default-max-header-bytes+)
             (max-fields +websocket-default-max-header-fields+)
             (max-body-bytes +websocket-default-max-body-bytes+)
             on-body-chunk (collect-body-p t) request-method head-p
             allow-eof-p (clock-function #'%websocket-monotonic-time))
  "Parse one binary-safe HTTP/1.1 response.

REQUEST-METHOD or HEAD-P suppresses a response body for a HEAD exchange.
ALLOW-EOF-P enables close-delimited response bodies and should be used only
when the caller is prepared to close the underlying connection."
  (unless (or (null max-fields)
              (and (integerp max-fields) (>= max-fields 0)))
    (%websocket-http-fail
     "max-fields must be a non-negative integer or NIL."
     :detail max-fields
     :operation :limits))
  (unless (or (null on-body-chunk) (functionp on-body-chunk))
    (%websocket-http-fail
     "on-body-chunk must be callable or NIL."
     :detail on-body-chunk
     :operation :body))
  (let ((reader (%websocket-http-make-reader
                 input timeout deadline max-header-bytes
                 max-body-bytes clock-function)))
    (multiple-value-bind (response fields)
        (%websocket-http-parse-response-from-reader
         reader max-fields on-body-chunk collect-body-p
         request-method head-p allow-eof-p)
      (declare (ignore fields))
      (values response (%websocket-http-reader-count reader)))))

(defun read-http-request (input-stream &rest options)
  (apply #'parse-http-request input-stream options))

(defun read-http-response (input-stream &rest options)
  (apply #'parse-http-response input-stream options))

(defun %websocket-http-reusable-version-p (version)
  (string= version "HTTP/1.1"))

(defun %websocket-http-connection-close-p (headers)
  (member "close"
          (%websocket-http-connection-tokens headers)
          :test #'string=))

(defun http-request-reusable-p (request)
  "Return true when a parsed request permits persistent HTTP/1.1 reuse."
  (and (http-request-p request)
       (%websocket-http-reusable-version-p
        (http-request-protocol-version request))
       (not (%websocket-http-connection-close-p
             (http-request-headers request)))
       (handler-case
           (let* ((headers (%websocket-http-header-pairs
                            (http-request-headers request)))
                  (content-length (%websocket-http-content-length headers))
                  (transfer-codings
                    (%websocket-http-transfer-codings headers)))
             (and (not (and content-length transfer-codings))
                  (or transfer-codings
                      (null content-length)
                      (= content-length
                         (length (http-request-body request))))))
         (websocket-error () nil)
         (error () nil))))

(defun http-response-reusable-p
    (response &key request-method head-p generated-p)
  "Return true when a response is self-delimiting and permits reuse.

REQUEST-METHOD or HEAD-P applies HEAD response semantics.  GENERATED-P says
the response will be serialized by this library, which supplies missing
payload framing."
  (and (http-response-p response)
       (%websocket-http-reusable-version-p
        (http-response-protocol-version response))
       (not (%websocket-http-connection-close-p
             (http-response-headers response)))
       (handler-case
           (let* ((status (http-response-status response))
                  (headers (%websocket-http-header-pairs
                            (http-response-headers response)))
                  (body (http-response-body response))
                  (content-length (%websocket-http-content-length headers))
                  (transfer-codings
                    (%websocket-http-transfer-codings headers))
                  (head-p (or head-p
                              (and request-method
                                   (string= request-method "HEAD"))))
                  (connect-p
                    (and request-method
                         (<= 200 status)
                         (< status 300)
                         (string= request-method "CONNECT")))
                  (status-no-body-p
                    (%websocket-http-no-body-status-p status)))
             (cond
               ((and content-length transfer-codings) nil)
               ((and (<= 100 status) (< status 200)) nil)
               (connect-p nil)
               ((and status-no-body-p
                     (or (and transfer-codings (/= status 304))
                         (and (= status 204) content-length)
                         (and content-length
                              (/= status 304)
                              (/= content-length 0))
                         (plusp (length body))))
                nil)
               ((or head-p status-no-body-p) t)
               (transfer-codings t)
               (content-length (= content-length (length body)))
               (generated-p t)
               (t nil)))
         (websocket-error () nil)
         (error () nil))))

(defun %websocket-http-response-with-connection-close (response)
  (if (%websocket-http-connection-close-p
       (http-response-headers response))
      response
      (make-http-response
       :status (http-response-status response)
       :reason (http-response-reason response)
       :headers (append (http-response-headers response)
                        (list (make-http-header "Connection" "close")))
       :trailers (http-response-trailers response)
       :body (http-response-body response)
       :protocol-version (http-response-protocol-version response))))

(defun %websocket-http-informational-response-p (status)
  (and (<= 100 status)
       (< status 200)
       (/= status 101)))

(defun serve-http-connection
    (stream handler &key timeout deadline idle-timeout max-requests
             (max-header-bytes +websocket-default-max-header-bytes+)
             (max-fields +websocket-default-max-header-fields+)
             (max-body-bytes +websocket-default-max-body-bytes+)
             default-authority on-headers on-body-chunk (collect-body-p t)
             on-error (close-stream-p t)
             (clock-function #'%websocket-monotonic-time))
  "Serve sequential HTTP/1.1 requests on STREAM.

HANDLER receives one parsed request and must return an HTTP response.  The
first return value is the number of requests handled and the second is one of
  :EOF, :MAX-REQUESTS, :CLOSED, :HANDLER-CLOSED, :TIMEOUT, or :ERROR.  The stream is
closed on exit when CLOSE-STREAM-P is true.  TIMEOUT and DEADLINE bound request
parsing and response I/O, while IDLE-TIMEOUT bounds waiting for the next
request.  HANDLER execution is not asynchronously interrupted.  ON-ERROR,
when supplied, is called with a condition and the request being processed;
without it, handler and parse errors are re-signalled.  ON-HEADERS receives a
header-only request before its body is read.  When it is NIL, an
Expect: 100-continue request with a body receives an automatic 100 response."
  (unless (streamp stream)
    (%websocket-http-fail
     "SERVE-HTTP-CONNECTION requires a stream."
     :detail (type-of stream)
     :operation :serve))
  (unless (functionp handler)
    (%websocket-http-fail
     "SERVE-HTTP-CONNECTION requires a callable handler."
     :detail handler
     :operation :serve))
  (dolist (entry `((,max-header-bytes . "max-header-bytes")
                   (,max-fields . "max-fields")
                   (,max-body-bytes . "max-body-bytes")))
    (%websocket-http-limit (car entry) (cdr entry)))
  (unless (or (null max-requests)
              (and (integerp max-requests) (>= max-requests 0)))
    (%websocket-http-fail
     "max-requests must be a non-negative integer or NIL."
     :detail max-requests
     :operation :serve))
  (unless (or (null on-body-chunk) (functionp on-body-chunk))
    (%websocket-http-fail
     "on-body-chunk must be callable or NIL."
     :detail on-body-chunk
     :operation :body))
  (unless (or (null on-headers) (functionp on-headers))
    (%websocket-http-fail
     "on-headers must be callable or NIL."
     :detail on-headers
     :operation :headers))
  (unless (or (null on-error) (functionp on-error))
    (%websocket-http-fail
     "on-error must be callable or NIL."
     :detail on-error
     :operation :serve))
  (unless (functionp clock-function)
    (%websocket-http-fail
     "The HTTP clock-function must be callable."
     :detail clock-function
     :operation :deadline))
  (let ((validation-deadline
          (%websocket-http-deadline timeout deadline clock-function)))
    (declare (ignore validation-deadline)))
  (let ((validation-deadline
          (%websocket-http-deadline idle-timeout nil clock-function)))
    (declare (ignore validation-deadline)))
  (let ((handled 0)
        (request nil))
    (unwind-protect
         (handler-case
             (if (and max-requests (zerop max-requests))
                 (values 0 :max-requests)
                 (loop
                   (let* ((request-deadline
                            (%websocket-http-deadline
                             timeout deadline clock-function))
                          (read-deadline
                            (%websocket-http-deadline
                             idle-timeout request-deadline clock-function))
                          (header-callback
                            (or on-headers
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
                                     :deadline request-deadline
                                      :clock-function clock-function))))))
                     (multiple-value-bind (next-request consumed)
                         (read-http-request
                          stream
                          :deadline read-deadline
                          :max-header-bytes max-header-bytes
                          :max-fields max-fields
                          :max-body-bytes max-body-bytes
                          :default-authority default-authority
                          :on-headers header-callback
                          :on-body-chunk on-body-chunk
                          :collect-body-p collect-body-p
                          :allow-eof-p t
                          :clock-function clock-function)
                       (declare (ignore consumed))
                       (unless next-request
                         (return-from serve-http-connection
                           (values handled :eof)))
                       (setf request next-request)
                       (let ((response (funcall handler request)))
                         (when (null response)
                           (return-from serve-http-connection
                             (values handled :handler-closed)))
                         (unless (http-response-p response)
                           (%websocket-http-fail
                            "The HTTP handler must return an HTTP response."
                            :detail (type-of response)
                            :operation :handler))
                         (incf handled)
                         (let* ((request-reusable-p
                                  (http-request-reusable-p request))
                                (response-reusable-p
                                  (http-response-reusable-p
                                   response
                                   :request-method
                                   (http-request-method request)
                                   :generated-p t))
                                (max-request-p
                                  (and max-requests
                                       (>= handled max-requests)))
                                (close-p
                                  (or (not request-reusable-p)
                                      (not response-reusable-p)
                                      max-request-p))
                                (wire-response
                                  (if close-p
                                      (%websocket-http-response-with-connection-close
                                       response)
                                      response)))
                           (write-http-response
                            wire-response
                            stream
                            :head-p (string-equal
                                    (http-request-method request)
                                    "HEAD")
                            :deadline request-deadline
                            :clock-function clock-function)
                           (when close-p
                             (return-from serve-http-connection
                               (values handled
                                       (if max-request-p
                                           :max-requests
                                           :closed))))))))))
           (websocket-timeout (condition)
             (when on-error
               (funcall on-error condition request))
             (return-from serve-http-connection
               (values handled :timeout)))
           (error (condition)
             (if on-error
                 (progn
                   (funcall on-error condition request)
                   (return-from serve-http-connection
                     (values handled :error)))
                 (error condition)))))
      (when close-stream-p
        (ignore-errors (close stream :abort t)))))

(defun perform-http-request
    (request stream &key timeout deadline
             (max-header-bytes +websocket-default-max-header-bytes+)
             (max-fields +websocket-default-max-header-fields+)
             (max-body-bytes +websocket-default-max-body-bytes+)
             on-body-chunk (collect-body-p t) allow-eof-p
             (max-informational-responses 16) on-informational
             (expect-continue-timeout 1.0)
             (clock-function #'%websocket-monotonic-time))
  "Write REQUEST and read its final HTTP/1.1 response from STREAM.

Interim responses other than 101 are consumed and optionally passed to
ON-INFORMATIONAL.  For a non-empty request carrying Expect: 100-continue,
headers are sent first; the body is sent after 100 Continue or after
EXPECT-CONTINUE-TIMEOUT expires.  If an early final response arrives, the
body is not sent.  The first return value is the final response and the
second says whether both request and response permit connection reuse.  This
function does not close STREAM."
  (unless (http-request-p request)
    (%websocket-http-fail
     "PERFORM-HTTP-REQUEST requires an HTTP request model."
     :detail (type-of request)
     :operation :client))
  (unless (streamp stream)
    (%websocket-http-fail
     "PERFORM-HTTP-REQUEST requires a stream."
     :detail (type-of stream)
     :operation :client))
  (dolist (entry `((,max-header-bytes . "max-header-bytes")
                   (,max-fields . "max-fields")
                   (,max-body-bytes . "max-body-bytes")
                   (,max-informational-responses .
                    "max-informational-responses")))
    (%websocket-http-limit (car entry) (cdr entry)))
  (unless (or (null on-body-chunk) (functionp on-body-chunk))
    (%websocket-http-fail
     "on-body-chunk must be callable or NIL."
     :detail on-body-chunk
     :operation :body))
  (unless (or (null on-informational) (functionp on-informational))
    (%websocket-http-fail
     "on-informational must be callable or NIL."
     :detail on-informational
     :operation :client))
  (%websocket-http-deadline expect-continue-timeout nil clock-function)
  (let ((request-deadline
          (%websocket-http-deadline timeout deadline clock-function))
        (informational-count 0)
        (request-header-pairs
          (%websocket-http-header-pairs (http-request-headers request)))
        (request-body (http-request-body request)))
    (labels ((response-reusable-p (response)
               (and (http-request-reusable-p request)
                    (http-response-reusable-p
                     response
                     :request-method (http-request-method request))))
             (read-response-sequence (response-deadline stop-at-continue-p)
               (loop
                 (multiple-value-bind (response consumed)
                     (read-http-response
                      stream
                      :deadline response-deadline
                      :max-header-bytes max-header-bytes
                      :max-fields max-fields
                      :max-body-bytes max-body-bytes
                      :on-body-chunk on-body-chunk
                      :collect-body-p collect-body-p
                      :request-method (http-request-method request)
                      :allow-eof-p allow-eof-p
                      :clock-function clock-function)
                   (declare (ignore consumed))
                   (if (%websocket-http-informational-response-p
                        (http-response-status response))
                       (progn
                         (incf informational-count)
                         (when (and max-informational-responses
                                    (> informational-count
                                       max-informational-responses))
                           (%websocket-http-fail
                            "Too many informational HTTP responses were received."
                            :detail informational-count
                            :operation :client))
                         (when on-informational
                           (funcall on-informational response))
                         (when (and stop-at-continue-p
                                    (= (http-response-status response) 100))
                           (return (values response :continue))))
                       (return (values response :final)))))))
      (let ((expect-continue-p
              (and (%websocket-http-expect-continue-p request-header-pairs)
                   (%websocket-http-octets-p request-body)
                   (plusp (length request-body)))))
        (if expect-continue-p
            (progn
              (write-http-request
               request stream
               :include-body-p nil
               :deadline request-deadline
               :clock-function clock-function)
              (let ((continue-deadline
                      (%websocket-http-deadline
                       expect-continue-timeout request-deadline
                       clock-function)))
                (handler-case
                    (multiple-value-bind (response disposition)
                        (read-response-sequence continue-deadline t)
                      (if (eq disposition :continue)
                          (progn
                            (write-http-request-body
                             request stream
                             :deadline request-deadline
                             :clock-function clock-function)
                            (multiple-value-bind (final ignored)
                                (read-response-sequence request-deadline nil)
                              (declare (ignore ignored))
                              (values final (response-reusable-p final))))
                          (values response (response-reusable-p response))))
                  (websocket-timeout (condition)
                    (if (and continue-deadline
                             (or (null request-deadline)
                                 (< continue-deadline request-deadline))
                             (member (websocket-timeout-kind condition)
                                     '(:http-read :read)
                                     :test #'eq))
                        (progn
                          (write-http-request-body
                           request stream
                           :deadline request-deadline
                           :clock-function clock-function)
                          (multiple-value-bind (final ignored)
                              (read-response-sequence request-deadline nil)
                            (declare (ignore ignored))
                            (values final (response-reusable-p final))))
                        (error condition))))))
            (progn
              (write-http-request
               request stream
               :deadline request-deadline
               :clock-function clock-function)
              (multiple-value-bind (response ignored)
                  (read-response-sequence request-deadline nil)
                (declare (ignore ignored))
                (values response (response-reusable-p response)))))))))
