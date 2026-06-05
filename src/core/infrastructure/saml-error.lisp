(defpackage :cl-saml-lib/src/core/infrastructure/saml-error
  (:use :cl)
  (:nicknames :saml-error)
  (:export
   #:saml-error
   #:text
   #:signing-error
   #:code
   #:signature-verification-error))

(in-package :cl-saml-lib/src/core/infrastructure/saml-error)

(define-condition saml-error (error)
  ((text :initarg :text :accessor text))
  (:report (lambda (condition stream)
             (format stream "~A" (text condition)))))

(define-condition signing-error (saml-error)
  ((code :initarg :code :accessor code)))

(define-condition signature-verification-error (saml-error)
  ((code :initarg :code :accessor code)))
