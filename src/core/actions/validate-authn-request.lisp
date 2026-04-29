(defpackage :cl-saml/src/core/actions/validate-authn-request
  (:use :cl)
  (:nicknames :validate-authn-request)
  (:import-from :defclass-std)
  (:import-from :cl-saml/src/core/domain/saml/authn-request)
  (:import-from :cl-saml/src/core/infrastructure/time)
  (:import-from :cl-saml/src/core/infrastructure/idp-config)
  (:export
   #:validate-authn-request
   #:validation-error
   #:validation-error-message
   #:run))

(in-package :cl-saml/src/core/actions/validate-authn-request)

;;; Validation Error Condition

(define-condition validation-error (error)
  ((message
    :initarg :message
    :reader validation-error-message
    :type string))
  (:report (lambda (condition stream)
             (format stream "SAML AuthnRequest validation failed: ~A"
                     (validation-error-message condition)))))

;;; Validate AuthnRequest Action

(defclass-std:defclass/std validate-authn-request ()
  ((idp-config :type idp-config:idp-config)))

(defmethod run ((this validate-authn-request) (authn-req authn-request:authn-request))
  "Validate an AuthnRequest.
THIS: validate-authn-request instance
AUTHN-REQUEST: authn-request instance
Returns: T on success, signals validation-error on failure"
  (multiple-value-bind (valid-p error-message)
      (authn-request:validate-authn-request authn-req)
    (if valid-p
        t
        (error 'validation-error :message error-message))))
