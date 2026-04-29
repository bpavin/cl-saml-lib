(defpackage :cl-saml-lib/src/core/actions/decode-authn-request
  (:use :cl)
  (:nicknames :decode-authn-request)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/domain/saml/authn-request)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:decode-authn-request
   #:validation-error
   #:validation-error-message
   #:run))

(in-package :cl-saml-lib/src/core/actions/decode-authn-request)

;;; Validation Error Condition

(defclass-std:defclass/std decode-authn-request ()
  ((xml-parser :type xml:xml-parser)))

(defmethod run ((this decode-authn-request) authn-req-xml)
  "Validate authn-request using the domain function.
Returns T on success, signals validation-error on failure."
  (let ((xml-document (xml:parse-xml (xml-parser this) authn-req-xml)))
    (authn-request:parse-authn-request xml-document)))
