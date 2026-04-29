(defpackage :cl-saml-lib/src/core/infrastructure/crypto-provider
  (:use :cl)
  (:nicknames :crypto-provider)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:+digest-sha-1+
   #:+digest-sha-256+
   #:+digest-sha-512+
   #:+signature-rsa-sha1+
   #:+signature-rsa-sha256+
   #:+signature-rsa-sha512+
   #:crypto-provider
   #:generate-key-pair
   #:load-certificate
   #:load-private-key
   #:certificate-from-key
   #:extract-public-key
   #:sign-xml
   #:verify-signature
   #:compute-digest
   #:digest-to-hexstring
   #:certificate-to-pem
   #:certificate-serial-number
   #:certificate-issuer
   #:certificate-subject
   #:certificate-not-before
   #:certificate-not-after
   #:encrypt-data
   #:decrypt-data
   #:extract-key-from-cert))

(in-package :cl-saml-lib/src/core/infrastructure/crypto-provider)

;;; Algorithm Constants

(defparameter +digest-sha-1+ :sha1)
(defparameter +digest-sha-256+ :sha256)
(defparameter +digest-sha-512+ :sha512)

(defparameter +signature-rsa-sha1+ :rsa-sha1)
(defparameter +signature-rsa-sha256+ :rsa-sha256)
(defparameter +signature-rsa-sha512+ :rsa-sha512)

(defclass-std:defclass/std crypto-provider () ())

;;; Key Management

(defgeneric generate-key-pair (&key algorithm bits)
  (:documentation "Generate a new key pair.
ALGORITHM: keyword (:rsa, :ec, etc.)
BITS: key size for RSA
Returns: (values public-key private-key)")
  (:method (&key (algorithm :rsa) (bits 2048))
    (declare (ignorable algorithm bits))
    (error 'saml-crypto-error :message "generate-key-pair: Must specialize")))

(defgeneric load-certificate (source &key format password)
  (:documentation "Load a certificate from source.
SOURCE: string (PEM content), pathname, or (array (unsigned-byte 8))
FORMAT: keyword (:pem, :der, :x509) - defaults to :pem
PASSWORD: optional string for encrypted sources
Returns: certificate")
  (:method (source &key (format :pem) password)
    (declare (ignorable source format password))
    (error 'saml-crypto-error :message "load-certificate: Must specialize")))

(defgeneric load-private-key (source &key format password)
  (:documentation "Load a private key from source.
SOURCE: string (PEM content), pathname, or (array (unsigned-byte 8))
FORMAT: keyword (:pem, :der, :pkcs8) - defaults to :pem
PASSWORD: optional string for encrypted keys
Returns: private-key")
  (:method (source &key (format :pem) password)
    (declare (ignorable source format password))
    (error 'saml-crypto-error :message "load-private-key: Must specialize")))

(defgeneric certificate-from-key (private-key)
  (:documentation "Generate self-signed certificate from private key.
PRIVATE-KEY: private-key
Returns: certificate"))

(defgeneric extract-public-key (certificate)
  (:documentation "Extract public key from certificate.
CERTIFICATE: certificate
Returns: public-key"))

;;; Signing Operations
(defgeneric sign-xml (this xml xpath private-key-pem cert-pem &key algorithm digest)
  (:documentation "Sign data with private key.
   
   DATA: String or octet array to sign
   PRIVATE-KEY: Private key for signing
   ALGORITHM: Signature algorithm (default: +signature-rsa-sha256+)
   DIGEST: Pre-computed digest (optional)
   
   Returns: signature as octet array."))

(defgeneric verify-signature (this xml xpath certificate &key algorithm)
  (:documentation "Verify a signature against data and certificate.
XML: string or octet array
XPATH: xpath of element to check
CERTIFICATE: certificate
ALGORITHM: signature algorithm to use
Returns: boolean"))

;;; Digest Operations

(defgeneric compute-digest (data &key algorithm)
  (:documentation "Compute digest of data.
   
   DATA: String or octet array
   ALGORITHM: Digest algorithm (default: +digest-sha-256+)
   
   Returns: digest as octet array."))

(defmethod compute-digest ((data string) &key (algorithm +digest-sha-256+))
  "Mock implementation of compute-digest for string data."
  (declare (ignore algorithm))
  ;; Return mock digest
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99))

(defmethod compute-digest ((data array) &key (algorithm +digest-sha-256+))
  "Mock implementation of compute-digest for array data."
  (declare (ignore algorithm))
  ;; Return mock digest
  (make-array 32 :element-type '(unsigned-byte 8) :initial-element 99))

(defun digest-to-hexstring (digest)
  "Convert digest octet array to hex string.
   
   Returns: hex string representation."
  (declare (ignore digest))
  ;; Return mock hex string
  "MOCK-HEX-DIGEST-VALUE")

;;; Certificate Operations

(defgeneric certificate-to-pem (certificate)
  (:documentation "Export certificate to PEM string.
Returns: string"))

(defgeneric certificate-serial-number (certificate)
  (:documentation "Get certificate serial number.
Returns: integer"))

(defgeneric certificate-issuer (certificate)
  (:documentation "Get certificate issuer DN.
Returns: string or parsed issuer structure"))

(defgeneric certificate-subject (certificate)
  (:documentation "Get certificate subject DN.
Returns: string or parsed subject structure"))

(defgeneric certificate-not-before (certificate)
  (:documentation "Get certificate validity start time.
Returns: universal-time or timestamp"))

(defgeneric certificate-not-after (certificate)
  (:documentation "Get certificate validity end time.
Returns: universal-time or timestamp"))

;;; Encryption (for encrypted assertions)

(defgeneric encrypt-data (data public-key &key algorithm)
  (:documentation "Encrypt data with public key.
DATA: octet array
PUBLIC-KEY: public-key
ALGORITHM: encryption algorithm
Returns: encrypted-data (octet array)"))

(defgeneric decrypt-data (encrypted-data private-key &key algorithm)
  (:documentation "Decrypt data with private key.
ENCRYPTED-DATA: octet array
PRIVATE-KEY: private-key
ALGORITHM: encryption algorithm
Returns: decrypted-data (octet array)"))

(defgeneric extract-key-from-cert (certificate)
  (:documentation "Extract RSA public key from X.509 certificate.
CERTIFICATE: certificate
Returns: public-key"))
