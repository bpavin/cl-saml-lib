;;;; encoding.lisp - Encoding operations interface

(in-package :saml-idp.interfaces)

;;; Base64 Encoding

(defgeneric encode-base64 (data &key padded)
  (:documentation "Encode binary data to Base64 string.
DATA: (array (unsigned-byte 8)) or string
PADDED: if true (default), include padding characters
Returns: string")
  (:method (data &key (padded t))
    (declare (ignorable data padded))
    (error 'saml-encoding-error :operation :encode-base64)))

(defgeneric decode-base64 (string)
  (:documentation "Decode Base64 string to binary data.
STRING: Base64 encoded string
Returns: (array (unsigned-byte 8))")
  (:method (string)
    (error 'saml-encoding-error :operation :decode-base64)))

;;; URL-Safe Base64

(defgeneric encode-base64url (data)
  (:documentation "Encode binary data to URL-safe Base64 string.
Replaces + with -, / with _, removes padding.
DATA: (array (unsigned-byte 8)) or string
Returns: string"))

(defgeneric decode-base64url (string)
  (:documentation "Decode URL-safe Base64 string to binary data.
STRING: URL-safe Base64 string
Returns: (array (unsigned-byte 8))"))

;;; Compression (for Redirect binding)

(defgeneric deflate-compress (data &key (level 6))
  (:documentation "Compress data using Deflate algorithm.
DATA: string or octet array
LEVEL: compression level (0-9), default 6
Returns: (array (unsigned-byte 8))")

(defgeneric inflate-decompress (data)
  (:documentation "Decompress Deflate-compressed data.
DATA: compressed octet array
Returns: (array (unsigned-byte 8))"))

;;; URL Encoding (for query parameters)

(defgeneric url-encode (string &key encoding)
  (:documentation "URL-encode a string.
STRING: string to encode
ENCODING: character encoding (default UTF-8)
Returns: string")

(defgeneric url-decode (string &key encoding)
  (:documentation "URL-decode a string.
STRING: URL-encoded string
ENCODING: character encoding (default UTF-8)
Returns: string"))

;;; Convenience combined operations for SAML bindings

(defgeneric encode-saml-request (request-xml &key compress)
  (:documentation "Encode SAML request for URL binding.
REQUEST-XML: string or xml-document
COMPRESS: if true, deflate compress first
Returns: encoded string suitable for URL")

(defgeneric decode-saml-request (encoded-string &key decompress)
  (:documentation "Decode SAML request from URL.
ENCODED-STRING: URL-encoded string
DECOMPRESS: if true, inflate decompress
Returns: string containing SAML XML")

(defgeneric encode-saml-response (response-xml)
  (:documentation "Encode SAML response for HTTP-POST binding.
RESPONSE-XML: string or xml-document
Returns: Base64 encoded string")

(defgeneric decode-saml-response (encoded-string)
  (:documentation "Decode SAML response from HTTP-POST.
ENCODED-STRING: Base64 string
Returns: string containing SAML XML"))