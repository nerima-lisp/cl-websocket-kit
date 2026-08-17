(in-package #:websocket-kit/test)

(defun ascii-octets (string)
  (let ((result (make-array (length string)
                            :element-type '(unsigned-byte 8))))
    (loop for character across string
          for index from 0
          do (setf (aref result index) (char-code character)))
    result))

(defun http-octets (&rest lines)
  (ascii-octets
   (with-output-to-string (stream)
     (dolist (line lines)
       (write-string line stream)
       (write-char #\Return stream)
       (write-char #\Newline stream)))))

(describe "HTTP/1.1 wire codec"
  (it "serializes and parses a request with an implicit content length"
    (let* ((request (make-http-request
                     :method "GET"
                     :uri "http://example.test/chat"
                     :headers (list (make-http-header "Host" "example.test"))))
           (wire (serialize-http-request request)))
      (expect wire
              :to-equalp
              (http-octets
               "GET /chat HTTP/1.1"
               "Content-Length: 0"
               "Host: example.test"
               ""))
      (multiple-value-bind (parsed consumed)
          (parse-http-request wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-request-method parsed) :to-equalp "GET")
        (expect (http-request-target parsed) :to-equalp "/chat")
        (expect (http-request-body parsed) :to-equalp (octets))
        (expect (http-header-value (http-request-headers parsed) "host")
                :to-equalp "example.test"))))

  (it "splits an Expect request into headers and body"
    (let* ((request
             (make-http-request
              :method "POST"
              :uri "http://example.test/upload"
              :headers (list (make-http-header "Host" "example.test")
                             (make-http-header "Expect" "100-continue"))
              :body (ascii-octets "abc")))
           (header-wire
             (serialize-http-request request :include-body-p nil))
           (body-wire (serialize-http-request-body request)))
      (expect header-wire
              :to-equalp
              (http-octets
               "POST /upload HTTP/1.1"
               "Content-Length: 3"
               "Host: example.test"
               "Expect: 100-continue"
               ""))
      (expect body-wire :to-equalp (ascii-octets "abc"))
      (expect (concatenate '(vector (unsigned-byte 8))
                           header-wire body-wire)
              :to-equalp
              (serialize-http-request request))))

  (it "delivers request headers before reading an expected body"
    (let* ((request
             (make-http-request
              :method "POST"
              :uri "http://example.test/upload"
              :headers (list (make-http-header "Host" "example.test")
                             (make-http-header "Expect" "100-continue"))
              :body (ascii-octets "abc")))
           (wire
             (concatenate '(vector (unsigned-byte 8))
                          (serialize-http-request request :include-body-p nil)
                          (ascii-octets "abc")))
           (events nil)
           (header-body nil)
           (header-mode nil)
           (header-length nil))
      (multiple-value-bind (parsed consumed)
          (parse-http-request
           wire
           :on-headers
           (lambda (header-request mode length)
             (push :headers events)
             (setf header-body (http-request-body header-request)
                   header-mode mode
                   header-length length))
           :on-body-chunk
           (lambda (chunk)
             (declare (ignore chunk))
             (push :body events)))
        (expect consumed :to-equalp (length wire))
        (expect (nreverse events) :to-equalp '(:headers :body))
        (expect header-body :to-equalp (octets))
        (expect header-mode :to-equalp :length)
        (expect header-length :to-equalp 3)
        (expect (http-request-body parsed)
                :to-equalp
                (ascii-octets "abc")))))

  (it "rejects unsupported Expect extensions"
    (signals websocket-http-error
      (serialize-http-request
       (make-http-request
        :method "POST"
        :uri "http://example.test/upload"
        :headers (list (make-http-header "Expect"
                                         "100-continue, fancy-extension"))
        :body (ascii-octets "abc")))))

  (it "requires authority-form request targets for CONNECT"
    (multiple-value-bind (parsed consumed)
        (parse-http-request
         (http-octets
          "CONNECT example.test:443 HTTP/1.1"
          "Host: example.test:443"
          ""))
      (expect consumed :to-equalp
              (length
               (http-octets
                "CONNECT example.test:443 HTTP/1.1"
                "Host: example.test:443"
                "")))
      (expect (http-request-method parsed) :to-equalp "CONNECT")
      (expect (http-request-target parsed) :to-equalp "example.test:443"))
    (signals websocket-http-error
      (parse-http-request
       (http-octets
        "CONNECT backend.example.test:443 HTTP/1.1"
        "Host: public.example.test:443"
        "")))
    (dolist (target '("/" "https://example.test/" "example.test"))
      (signals websocket-http-error
        (parse-http-request
         (http-octets
          (format nil "CONNECT ~A HTTP/1.1" target)
          "Host: example.test:443"
          "")))))

  (it "requires an absolute-form authority to match Host"
    (signals websocket-http-error
      (parse-http-request
       (http-octets
        "GET http://other.test/chat HTTP/1.1"
        "Host: example.test"
        "")))
    (multiple-value-bind (request consumed)
        (parse-http-request
         (http-octets
          "GET http://Example.test/chat HTTP/1.1"
          "Host: example.test"
          ""))
      (expect consumed :to-equalp
              (length
               (http-octets
                "GET http://Example.test/chat HTTP/1.1"
                "Host: example.test"
                "")))
      (expect (http-request-target request) :to-equalp
              "http://Example.test/chat")))

  (it "requires Host and a semantically valid request-target when serializing"
    (signals websocket-http-error
      (serialize-http-request
       (make-http-request
        :method "GET"
        :uri "http://example.test/chat")))
    (signals websocket-http-error
      (serialize-http-request
       (make-http-request
        :method "GET"
        :uri "http://example.test/chat"
        :request-target "http://other.test/chat"
        :headers (list (make-http-header "Host" "example.test"))))))

  (it "validates request authority before delivering body chunks"
    (let ((delivered-p nil))
      (signals websocket-http-error
        (parse-http-request
         (concatenate '(vector (unsigned-byte 8))
                      (http-octets
                       "POST /upload HTTP/1.1"
                       "Host: example.test"
                       "Host: duplicate.test"
                       "Content-Length: 3"
                       "")
                      (ascii-octets "abc"))
         :on-body-chunk (lambda (chunk)
                          (declare (ignore chunk))
                          (setf delivered-p t))))
      (expect delivered-p :to-equalp nil)))

  (it "adds transfer coding when trailers require chunking"
    (let* ((request (make-http-request
                     :method "POST"
                     :uri "http://example.test/upload"
                     :headers (list (make-http-header "Host" "example.test"))
                     :trailers (list (make-http-header "X-Checksum" "ok"))
                     :body (octets 1 2 3)))
           (wire (serialize-http-request request)))
      (expect wire
              :to-equalp
              (concatenate '(vector (unsigned-byte 8))
                           (http-octets
                            "POST /upload HTTP/1.1"
                            "Transfer-Encoding: chunked"
                            "Host: example.test"
                            ""
                            "3")
                           (octets 1 2 3)
                           (http-octets "" "0" "X-Checksum: ok" "")))
      (multiple-value-bind (parsed consumed)
          (parse-http-request wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-request-body parsed) :to-equalp (octets 1 2 3))
                (expect (http-header-value (http-request-trailers parsed)
                                   "x-checksum")
                :to-equalp "ok"))))

  (it "rejects content length with trailers"
    (signals websocket-http-error
      (serialize-http-request
       (make-http-request
        :method "POST"
        :uri "http://example.test/upload"
        :headers (list (make-http-header "Content-Length" "3"))
        :trailers (list (make-http-header "X-Checksum" "ok"))
        :body (octets 1 2 3)))))

  (it "does not duplicate chunked request bodies"
    (let ((wire
            (concatenate '(vector (unsigned-byte 8))
                         (http-octets
                          "POST /upload HTTP/1.1"
                          "Host: example.test"
                          "Transfer-Encoding: chunked"
                          ""
                          "3")
                         (ascii-octets "abc")
                         (http-octets "" "0" ""))))
      (multiple-value-bind (request consumed)
          (parse-http-request wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-request-body request) :to-equalp (ascii-octets "abc")))))

  (it "validates chunk extensions and delivers each chunk once"
    (let ((chunks '())
          (wire (concatenate '(vector (unsigned-byte 8))
                             (http-octets
                              "HTTP/1.1 200 OK"
                              "Transfer-Encoding: chunked"
                              ""
                              "3;foo=bar")
                             (ascii-octets "abc")
                             (http-octets "" "0" ""))))
      (multiple-value-bind (response consumed)
          (parse-http-response
           wire
           :on-body-chunk (lambda (chunk) (push chunk chunks))
           :collect-body-p nil)
        (expect consumed :to-equalp (length wire))
        (expect (http-response-body response) :to-equalp (octets))
        (expect (nreverse chunks) :to-equalp (list (ascii-octets "abc")))))
    (signals websocket-http-error
      (parse-http-response
       (http-octets
        "HTTP/1.1 200 OK"
       "Transfer-Encoding: chunked"
        ""
        "3;foo=bad?"))))

  (it "bounds chunk extension lines"
    (let ((wire
            (concatenate '(vector (unsigned-byte 8))
                         (http-octets
                          "HTTP/1.1 200 OK"
                          "Transfer-Encoding: chunked"
                          "")
                         (http-octets
                          (format nil "1;~A"
                                  (make-string 80 :initial-element #\a)))
                         (ascii-octets "a")
                         (http-octets "" "0" ""))))
      (signals websocket-size-limit-exceeded
        (parse-http-response wire :max-header-bytes 64))))

  (it "rejects request fragments and malformed Host authorities"
    (dolist (target '("/path#fragment" "http://example.test/path#fragment"))
      (signals websocket-http-error
        (parse-http-request
         (http-octets
          (format nil "GET ~A HTTP/1.1" target)
          "Host: example.test"
          ""))))
    (dolist (host '("example.test:"
                    "example.test:abc"
                    "example.test:65536"
                    "[::1"))
      (signals websocket-http-error
        (parse-http-request
         (http-octets
          "GET / HTTP/1.1"
          (format nil "Host: ~A" host)
          "")))))

  (it "validates Connection tokens before reading request or response bodies"
    (signals websocket-http-error
      (parse-http-request
       (concatenate '(vector (unsigned-byte 8))
                    (http-octets
                     "POST / HTTP/1.1"
                     "Host: example.test"
                     "Connection: keep-alive,"
                     "Content-Length: 3"
                     "")
                    (ascii-octets "abc"))))
    (signals websocket-http-error
      (parse-http-response
       (concatenate '(vector (unsigned-byte 8))
                    (http-octets
                     "HTTP/1.1 200 OK"
                     "Connection: keep-alive,"
                     "Content-Length: 3"
                     "")
                    (ascii-octets "abc"))))
    (signals websocket-http-error
      (serialize-http-request
       (make-http-request
        :method "GET"
        :uri "http://example.test/"
        :headers (list (make-http-header "Connection" "keep-alive,")))))
    (signals websocket-http-error
      (serialize-http-response
       (make-http-response
        :status 200
        :headers (list (make-http-header "Connection" "keep-alive,"))))))

  (it "does not count chunk data against the header limit"
    (let* ((prefix
             (http-octets
              "POST /upload HTTP/1.1"
              "Host: example.test"
              "Transfer-Encoding: chunked"
              ""
              "5"))
           (wire (concatenate '(vector (unsigned-byte 8))
                              prefix
                              (ascii-octets "abcde")
                              (http-octets "" "0" ""))))
      (multiple-value-bind (request consumed)
          (parse-http-request wire :max-header-bytes (length prefix))
        (expect consumed :to-equalp (length wire))
        (expect (http-request-body request) :to-equalp (ascii-octets "abcde")))))

  (it "rejects forbidden trailer fields"
    (dolist (name '("Connection"
                    "Content-Length"
                    "Host"
                    "Keep-Alive"
                    "Proxy-Authenticate"
                    "Proxy-Authentication-Info"
                    "Proxy-Authorization"
                    "TE"
                    "Trailer"
                    "Transfer-Encoding"
                    "Upgrade"))
      (signals websocket-http-error
        (serialize-http-request
         (make-http-request
          :method "POST"
          :uri "http://example.test/upload"
          :trailers (list (make-http-header name "value"))
          :body (ascii-octets "abc"))))
      (signals websocket-http-error
        (parse-http-request
         (http-octets
          "POST /upload HTTP/1.1"
          "Host: example.test"
          "Transfer-Encoding: chunked"
          ""
          "0"
          (format nil "~A: value" name)
          "")))))

  (it "serializes and parses a length-delimited response"
    (let* ((response (make-http-response
                      :status 200
                      :headers (list (make-http-header "Connection" "keep-alive"))
                      :body (octets 65 66)))
           (wire (serialize-http-response response)))
      (expect wire
              :to-equalp
              (concatenate '(vector (unsigned-byte 8))
                           (http-octets
                            "HTTP/1.1 200 OK"
                            "Content-Length: 2"
                            "Connection: keep-alive"
                            "")
                           (ascii-octets "AB")))
      (multiple-value-bind (parsed consumed)
          (parse-http-response wire :request-method "GET")
        (expect consumed :to-equalp (length wire))
        (expect (http-response-status parsed) :to-equalp 200)
        (expect (http-response-body parsed) :to-equalp (octets 65 66))
        (expect (and (http-response-reusable-p parsed) t) :to-equalp t))))

  (it "suppresses a HEAD response body while preserving its declared length"
    (let ((wire (http-octets "HTTP/1.1 200 OK" "Content-Length: 4" "")))
      (multiple-value-bind (response consumed)
          (parse-http-response wire :request-method "HEAD")
        (expect consumed :to-equalp (length wire))
        (expect (http-response-body response) :to-equalp (octets))
        (expect (http-header-value (http-response-headers response)
                "content-length")
                :to-equalp "4"))))

  (it "treats lowercase HEAD and CONNECT as ordinary methods"
    (let ((wire (concatenate '(vector (unsigned-byte 8))
                             (http-octets "HTTP/1.1 200 OK"
                                          "Content-Length: 3"
                                          "")
                             (ascii-octets "abc"))))
      (dolist (method '("head" "connect"))
        (multiple-value-bind (response consumed)
            (parse-http-response wire :request-method method)
          (expect consumed :to-equalp (length wire))
          (expect (http-response-body response)
                  :to-equalp (ascii-octets "abc"))))))

  (it "uses status-specific response framing"
    (dolist (status '(100 101 204 205 304))
      (let ((wire
              (serialize-http-response
               (make-http-response :status status :reason "No Body"))))
        (multiple-value-bind (response consumed)
            (parse-http-response wire)
          (expect consumed :to-equalp (length wire))
          (expect (http-response-status response) :to-equalp status)
          (expect (http-response-body response) :to-equalp (octets))
          (expect (http-header-value (http-response-headers response)
                                     "content-length")
                  :to-equalp (if (= status 205) "0" nil)))))
    (let ((wire
            (serialize-http-response
             (make-http-response
              :status 304
              :reason "Not Modified"
              :headers (list (make-http-header "Content-Length" "37"))))))
      (multiple-value-bind (response consumed)
          (parse-http-response wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-header-value (http-response-headers response)
                                   "content-length")
                :to-equalp "37")
        (expect (http-response-body response) :to-equalp (octets))))
    (let ((wire
            (serialize-http-response
             (make-http-response
              :status 304
              :reason "Not Modified"
              :headers (list (make-http-header
                              "Transfer-Encoding" "chunked"))))))
      (multiple-value-bind (response consumed)
          (parse-http-response wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-header-value (http-response-headers response)
                                   "transfer-encoding")
                :to-equalp "chunked")
        (expect (http-response-body response) :to-equalp (octets))
        (expect (http-response-reusable-p response) :to-equalp t)))
    (signals websocket-http-error
      (parse-http-response
       (http-octets "HTTP/1.1 304 Not Modified"
                    "Transfer-Encoding: gzip"
                    "")))
    (signals websocket-http-error
      (serialize-http-response
       (make-http-response
        :status 204
        :reason "No Content"
        :headers (list (make-http-header "Content-Length" "0")))))
    (signals websocket-http-error
      (serialize-http-response
       (make-http-response
        :status 101
        :reason "Switching Protocols"
        :headers (list (make-http-header "Transfer-Encoding" "chunked"))))))
    (signals websocket-http-error
      (parse-http-response
       (http-octets "HTTP/1.1 204 No Content" "Content-Length: 0" "")))
    (signals websocket-http-error
      (parse-http-response
       (http-octets "HTTP/1.1 205 Reset Content" "Content-Length: 1" ""
                    "x")))
    (signals websocket-http-error
      (parse-http-response
       (http-octets "HTTP/1.1 101 Switching Protocols"
                    "Content-Length: 0"
                    "")))

  (it "does not reuse a switching-protocols response"
    (let ((response
            (parse-http-response
             (http-octets "HTTP/1.1 101 Switching Protocols" ""))))
      (expect (http-response-reusable-p response) :to-equalp nil)))

  (it "uses request semantics when deciding response reuse"
    (let ((head-response
            (parse-http-response
             (http-octets "HTTP/1.1 200 OK" "")
             :request-method "HEAD"))
          (generated-response
            (make-http-response
             :status 200
             :body (ascii-octets "OK"))))
      (expect (http-response-reusable-p
               head-response :request-method "HEAD")
              :to-equalp t)
      (expect (http-response-reusable-p generated-response)
              :to-equalp nil)
      (expect (http-response-reusable-p generated-response :generated-p t)
              :to-equalp t)))

  (it "does not reuse a response with ambiguous framing"
    (let ((response
            (make-http-response
             :status 200
             :headers (list (make-http-header "Content-Length" "2")
                            (make-http-header "Transfer-Encoding" "chunked"))
             :body (ascii-octets "OK"))))
      (expect (http-response-reusable-p response) :to-equalp nil)))

  (it "treats a successful CONNECT response as the tunnel boundary"
    (let ((wire (http-octets "HTTP/1.1 200 Connection Established" "")))
      (multiple-value-bind (response consumed)
          (parse-http-response wire :request-method "CONNECT")
        (expect consumed :to-equalp (length wire))
        (expect (http-response-status response) :to-equalp 200)
        (expect (http-response-body response) :to-equalp (octets)))))

  (it "delivers body chunks without retaining the body"
    (let ((chunks '())
          (wire (concatenate '(vector (unsigned-byte 8))
                             (http-octets
                              "HTTP/1.1 200 OK"
                              "Content-Length: 3"
                              "")
                             (ascii-octets "abc"))))
      (multiple-value-bind (response consumed)
          (parse-http-response
           wire
           :on-body-chunk (lambda (chunk) (push chunk chunks))
           :collect-body-p nil)
        (expect consumed :to-equalp (length wire))
        (expect (http-response-body response) :to-equalp (octets))
        (expect (nreverse chunks) :to-equalp (list (ascii-octets "abc"))))))

  (it "supports an explicitly close-delimited response"
    (let ((wire (concatenate '(vector (unsigned-byte 8))
                             (http-octets "HTTP/1.1 200 OK" "")
                             (ascii-octets "abc"))))
      (multiple-value-bind (response consumed)
          (parse-http-response wire :allow-eof-p t)
        (expect consumed :to-equalp (length wire))
        (expect (http-response-body response) :to-equalp (ascii-octets "abc")))))

  (it "enforces the body limit while reading close-delimited responses"
    (signals websocket-size-limit-exceeded
      (parse-http-response
       (concatenate '(vector (unsigned-byte 8))
                    (http-octets "HTTP/1.1 200 OK" "")
                    (ascii-octets "abc"))
       :allow-eof-p t
       :max-body-bytes 2)))

  (it "rejects ambiguous or malformed framing"
    (let ((wire (concatenate '(vector (unsigned-byte 8))
                             (http-octets
                              "POST / HTTP/1.1"
                              "Host: example.test"
                              "Content-Length: 3"
                              "Content-Length: 3"
                              "")
                             (ascii-octets "abc"))))
      (multiple-value-bind (request consumed)
          (parse-http-request wire)
        (expect consumed :to-equalp (length wire))
        (expect (http-request-body request) :to-equalp (ascii-octets "abc"))))
    (signals websocket-http-error
      (parse-http-request
       (http-octets
        "POST / HTTP/1.1"
        "Host: example.test"
        "Content-Length: 1"
        "Content-Length: 2"
        "")))
    (signals websocket-http-error
      (parse-http-request
       (http-octets
        "POST / HTTP/1.1"
        "Host: example.test"
        "Transfer-Encoding: gzip, chunked"
        "")))
    (signals websocket-http-error
      (parse-http-request
       (ascii-octets
        (format nil "GET / HTTP/1.1~CHost: example.test~C~C"
                #\Newline
                #\Newline
                #\Newline))))
    (signals websocket-http-error
      (parse-http-request
       (http-octets "GET / HTTP/1.1" " Host: example.test" "")))
    (signals websocket-http-error
      (parse-http-response
       (http-octets "HTTP/1.1 099 Invalid" "")))
    (signals websocket-size-limit-exceeded
      (parse-http-request
       (http-octets "GET / HTTP/1.1" "Host: example.test" "")
       :max-header-bytes 8))
    (signals websocket-size-limit-exceeded
      (parse-http-request
       (http-octets "GET / HTTP/1.1" "Host: example.test" "")
       :max-fields 0)))

  (it "rejects numeric framing before unbounded integer conversion"
    (let ((huge-decimal (make-string 256 :initial-element #\9))
          (huge-hex (make-string 256 :initial-element #\F)))
      (signals websocket-http-error
        (parse-http-request
         (http-octets "POST / HTTP/1.1" "Host: example.test"
                      (format nil "Content-Length: ~A" huge-decimal)
                      "")))
      (signals websocket-http-error
        (parse-http-response
         (http-octets "HTTP/1.1 200 OK" "Transfer-Encoding: chunked"
                      "" huge-hex "")))))

  (it "reports a clean EOF without inventing a request"
    (multiple-value-bind (request consumed)
        (parse-http-request (octets) :allow-eof-p t)
      (expect request :to-equalp nil)
      (expect consumed :to-equalp 0)))

  (it "serves persistent requests and closes at the request limit"
    (let* ((request-wire
             (serialize-http-request
              (make-http-request
               :method "GET"
               :uri "http://example.test/socket"
               :headers (list (make-http-header "Host" "example.test")))))
           (input (concatenate '(vector (unsigned-byte 8))
                               request-wire
                               request-wire)))
      (multiple-value-bind (result output)
          (with-binary-two-way
              input
            (lambda (stream)
              (serve-http-connection
               stream
               (lambda (request)
                 (declare (ignore request))
                 (make-http-response
                  :status 200
                  :body (ascii-octets "OK")))
               :max-requests 2
               :close-stream-p nil)))
        (expect (first result) :to-equalp 2)
        (expect (second result) :to-equalp :max-requests)
        (multiple-value-bind (first-response first-consumed)
            (parse-http-response output :request-method "GET")
          (expect (http-response-status first-response) :to-equalp 200)
          (expect (http-response-body first-response)
                  :to-equalp (ascii-octets "OK"))
          (multiple-value-bind (second-response second-consumed)
              (parse-http-response
               (subseq output first-consumed)
               :request-method "GET")
            (expect second-consumed :to-equalp
                   (- (length output) first-consumed))
            (expect (http-header-value
                     (http-response-headers second-response)
                     "connection")
                    :to-equalp "close"))))))

  (it "bounds waiting for the next request with the idle timeout"
    (let ((request-wire
            (serialize-http-request
             (make-http-request
              :method "GET"
              :uri "http://example.test/socket"
              :headers (list (make-http-header "Host" "example.test")))))
          (observed-condition nil))
      (multiple-value-bind (result output)
          (with-binary-two-way
              request-wire
            (lambda (stream)
              (serve-http-connection
               stream
               (lambda (request)
                 (declare (ignore request))
                 (make-http-response :status 200))
               :idle-timeout 0
               :clock-function (lambda () 1)
               :on-error (lambda (condition request)
                           (declare (ignore request))
                           (setf observed-condition condition))
               :close-stream-p nil)))
        (expect (typep observed-condition 'websocket-timeout)
                :to-be t)
        (expect result :to-equalp '(0 :timeout))
        (expect output :to-equalp (octets)))))

  (it "sends 100 Continue before reading an expected request body"
    (let* ((request
             (make-http-request
              :method "POST"
              :uri "http://example.test/upload"
              :headers (list (make-http-header "Host" "example.test")
                             (make-http-header "Expect" "100-continue"))
              :body (ascii-octets "abc")))
           (header-wire (serialize-http-request request :include-body-p nil))
           (input (concatenate '(vector (unsigned-byte 8))
                               header-wire
                               (ascii-octets "abc")))
           (saw-body-p nil))
      (multiple-value-bind (result output)
          (with-binary-two-way
              input
            (lambda (stream)
              (serve-http-connection
               stream
               (lambda (received)
                 (setf saw-body-p
                       (equalp (http-request-body received)
                               (ascii-octets "abc")))
                 (make-http-response
                  :status 200
                  :reason "OK"
                  :body (ascii-octets "OK")))
               :max-requests 1
               :close-stream-p nil)))
        (expect result :to-equalp '(1 :max-requests))
        (expect saw-body-p :to-equalp t)
        (multiple-value-bind (interim consumed)
            (parse-http-response output)
          (expect (http-response-status interim) :to-equalp 100)
          (multiple-value-bind (final ignored)
              (parse-http-response
               (subseq output consumed)
               :request-method "POST")
            (declare (ignore ignored))
            (expect (http-response-status final) :to-equalp 200)
            (expect (http-response-body final)
                    :to-equalp (ascii-octets "OK")))))))

  (it "waits for 100 Continue before sending the request body"
    (let* ((request
             (make-http-request
              :method "POST"
              :uri "http://example.test/upload"
              :headers (list (make-http-header "Host" "example.test")
                             (make-http-header "Expect" "100-continue"))
              :body (ascii-octets "abc")))
           (header-wire (serialize-http-request request :include-body-p nil))
           (body-wire (ascii-octets "abc"))
           (input (concatenate '(vector (unsigned-byte 8))
                               (http-octets
                                "HTTP/1.1 100 Continue"
                                "")
                               (http-octets
                                "HTTP/1.1 200 OK"
                                "Content-Length: 2"
                                "")
                               (ascii-octets "OK")))
           (statuses '()))
      (multiple-value-bind (result output)
          (with-binary-two-way
              input
            (lambda (stream)
              (perform-http-request
               request stream
               :on-informational
               (lambda (response)
                 (push (http-response-status response) statuses)))))
        (expect (http-response-status (first result)) :to-equalp 200)
        (expect (second result) :to-equalp t)
        (expect (nreverse statuses) :to-equalp '(100))
        (expect output
                :to-equalp
                (concatenate '(vector (unsigned-byte 8))
                             header-wire body-wire)))))

  (it "does not send an expected body after an early final response"
    (let* ((request
             (make-http-request
              :method "POST"
              :uri "http://example.test/upload"
              :headers (list (make-http-header "Host" "example.test")
                             (make-http-header "Expect" "100-continue"))
              :body (ascii-octets "abc")))
           (header-wire (serialize-http-request request :include-body-p nil))
           (input (http-octets
                   "HTTP/1.1 417 Expectation Failed"
                   "Content-Length: 0"
                   "")))
      (multiple-value-bind (result output)
          (with-binary-two-way
              input
            (lambda (stream)
              (perform-http-request request stream)))
        (expect (http-response-status (first result)) :to-equalp 417)
        (expect output :to-equalp header-wire))))

  (it "consumes informational responses before the final response"
    (let* ((request
             (make-http-request
              :method "GET"
              :uri "http://example.test/socket"
              :headers (list (make-http-header "Host" "example.test"))))
           (input (concatenate '(vector (unsigned-byte 8))
                               (http-octets
                                "HTTP/1.1 100 Continue"
                                "")
                               (http-octets
                                "HTTP/1.1 200 OK"
                                "Content-Length: 2"
                                "")
                               (ascii-octets "OK")))
           (statuses '()))
      (multiple-value-bind (result output)
          (with-binary-two-way
              input
            (lambda (stream)
              (perform-http-request
               request stream
               :on-informational
               (lambda (response)
                 (push (http-response-status response) statuses)))))
        (let ((response (first result)))
          (expect (http-response-status response) :to-equalp 200)
          (expect (second result) :to-equalp t)
          (expect (nreverse statuses) :to-equalp '(100)))
        (multiple-value-bind (written-request consumed)
            (parse-http-request output)
          (expect (http-request-method written-request) :to-equalp "GET")
          (expect consumed :to-equalp (length output))))))

  (it "rejects invalid response model values"
    (signals http-invalid-status
      (serialize-http-response
       (make-http-response
        :status 200
        :reason (format nil "OK~CInjected" #\Return))))
    (signals http-invalid-status
      (serialize-http-response
       (make-http-response :status 99 :reason "Invalid"))))

  (it "rejects control characters in request targets"
    (signals websocket-http-error
      (parse-http-request
       (ascii-octets
        (format nil "GET /bad~Ctarget HTTP/1.1~C~CHost: example.test~C~C"
                #\Tab
                #\Return
                #\Newline
                #\Return
                #\Newline)))))

  (it "enforces the configured body limit"
    (signals websocket-size-limit-exceeded
      (parse-http-response
       (concatenate '(vector (unsigned-byte 8))
                    (http-octets "HTTP/1.1 200 OK" "Content-Length: 3" "")
                    (ascii-octets "abc"))
       :max-body-bytes 2))))
