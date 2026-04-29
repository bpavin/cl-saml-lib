(defpackage :cl-saml-lib/src/core/infrastructure/identifiers
  (:use :cl)
  (:nicknames :identifiers)
  (:export
   #:generate-saml-id
   #:generate-uuid
   #:valid-saml-id-p
   #:extract-id-from-samlxml
   #:extract-id-from-authnrequest))

(in-package :cl-saml-lib/src/core/infrastructure/identifiers)

;;; SAML ID Format
;; SAML IDs must begin with a letter (_) and contain only alphanumeric, hyphen, underscore, period

(defparameter +saml-id-prefix+ "_"
  "SAML IDs conventionally start with underscore")

;;; ID Generation

(defun generate-saml-id ()
  "Generate a unique SAML ID string.
Format: _<hex-string> or based on UUID
Returns: string"
  (format nil "~A~A" +saml-id-prefix+ (generate-uuid)))

(defun generate-uuid ()
  "Generate a UUID string.
Returns: string in standard UUID format (8-4-4-4-12)"
  (format nil "~A" (uuid:make-v4-uuid)))

;;; Validation

(defun valid-saml-id-p (str)
  "Check if string is a valid SAML ID.
Returns: boolean"
  (handler-case
      (uuid:make-uuid-from-string str)
    (error (e)
      (declare (ignore e))
      nil)))

;;; Message ID extraction

(defun extract-id-from-samlxml (xml-string)
  "Extract ID attribute from SAML XML root element.
XML-STRING: string containing SAML XML
Returns: string (the ID value)"
  )

(defun extract-id-from-authnrequest (xml-string)
  "Extract ID from AuthnRequest XML.
XML-STRING: string containing AuthnRequest XML
Returns: string (the ID value)")
