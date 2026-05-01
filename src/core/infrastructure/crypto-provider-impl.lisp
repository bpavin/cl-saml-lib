(defpackage :cl-saml-lib/src/core/infrastructure/crypto-provider-impl
  (:use :cl)
  (:nicknames :crypto-provider-impl)
  (:import-from :log4cl)
  (:import-from :cffi)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:export
   #:crypto-provider-impl
   #:cleanup))

(in-package :cl-saml-lib/src/core/infrastructure/crypto-provider-impl)

(defclass-std:defclass/std crypto-provider-impl (crypto-provider:crypto-provider)
  ())

(push (asdf:system-source-directory :cl-saml-lib) cffi:*foreign-library-directories*)

(cffi:define-foreign-library saml-signer
  (:unix (:default "src/xmlsec-wrapper/libsaml_signer")))

(cffi:use-foreign-library saml-signer)

(cffi:defcfun ("saml_signer_init" %sign-init) :int)

(cffi:defcfun ("saml_signer_shutdown" %sign-shutdown) :void)

(cffi:defcfun ("saml_signer_error_to_string" %error-to-string) :string
  (error-code :int))

(cffi:defcfun ("sign_xml_xpath" %sign-xml-xpath) :int
  (xml-input :string)
  (xpath-expr :string)
  (key-pem :string)
  (cert-pem :string)
  (out :pointer))

(cffi:defcfun ("verify_xml_signature_xpath" %verify-xml-xpath) :int
  (xml-input :string)
  (xpath-expr :string)
  (cert-pem :string))

(defmethod initialize-instance :after ((this crypto-provider-impl) &key)
  (init this))

(defmethod init ((this crypto-provider-impl))
  (let ((res (%sign-init)))
    (if (zerop res)
        (log:info "Init successful. [code=~A]" res)
        (error "Init failed. [code=~A]" res))))

(defmethod cleanup ((this crypto-provider-impl))
  (%sign-shutdown))

(defmethod crypto-provider:sign-xml ((this crypto-provider-impl) xml xpath key-pem cert-pem &key algorithm digest)
  (cffi:with-foreign-object (out :pointer)
    (let ((res (%sign-xml-xpath xml xpath key-pem cert-pem out)))
      (if (zerop res)
          (let ((cstr (cffi:mem-ref out :pointer)))
            (prog1
                (cffi:foreign-string-to-lisp cstr)
              (cffi:foreign-free cstr)))
          (error (format nil "Signing failed. [code=~A, reason=~A]" res (%error-to-string res)))))))

(defmethod crypto-provider:verify-signature (this xml xpath cert-pem &key algorithm)
  (let ((res (%verify-xml-xpath xml xpath cert-pem)))
    (if (zerop res)
        (log:info "Verification was successful. [code=~A]" res)
        (error (format nil "Verification failed. [code=~A, reason=~A]" res (%error-to-string res))))))
