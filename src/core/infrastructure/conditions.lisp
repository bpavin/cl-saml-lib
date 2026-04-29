;;;; conditions.lisp - Error conditions for SAML operations

(in-package :saml-idp.interfaces)

(define-condition saml-error (error)
  ((message
    :initarg :message
    :reader saml-error-message))
  (:report (lambda (c s)
             (format s "SAML Error: ~A" (saml-error-message c)))))

(define-condition saml-xml-error (saml-error)
  ((xml-message
    :initarg :xml-message
    :reader saml-xml-error-message))
  (:report (lambda (c s)
             (format s "SAML XML Error: ~A~%Details: ~A"
                     (saml-error-message c)
                     (saml-xml-error-message c)))))

(define-condition saml-crypto-error (saml-error)
  ((crypto-context
    :initarg :context
    :reader saml-crypto-error-context))
  (:report (lambda (c s)
             (format s "SAML Crypto Error: ~A"
                     (saml-error-message c)))))

(define-condition saml-validation-error (saml-error)
  ((validation-type
    :initarg :validation-type
    :reader saml-validation-error-type)
   (failed-value
    :initarg :failed-value
    :reader saml-validation-error-value))
  (:report (lambda (c s)
             (format s "SAML Validation Error: ~A~%Failed: ~A"
                     (saml-error-message c)
                     (saml-validation-error-value c)))))

(define-condition saml-encoding-error (saml-error)
  ((encoding-operation
    :initarg :operation
    :reader saml-encoding-error-operation))
  (:report (lambda (c s)
             (format s "SAML Encoding Error: ~A"
                     (saml-error-message c)))))