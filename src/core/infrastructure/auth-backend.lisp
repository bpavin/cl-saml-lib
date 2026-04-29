(defpackage :cl-saml/src/core/infrastructure/auth-backend
  (:use :cl)
  (:nicknames :auth-backend)
  (:import-from :defclass-std)
  (:export
   #:auth-backend
   #:authenticate-user
   #:get-user-attributes))

(in-package :cl-saml/src/core/infrastructure/auth-backend)

(defclass-std:defclass/std auth-backend ()
  ((name :type string)))

(defgeneric authenticate-user (backend username password)
  (:documentation "Authenticate user with username/password.
BACKEND: auth-backend instance
USERNAME: string
PASSWORD: string
Returns: user object or nil if authentication fails."))

(defgeneric get-user-attributes (backend user)
  (:documentation "Get user attributes for SAML assertion.
BACKEND: auth-backend instance
USER: user object returned from authenticate-user
Returns: alist of (attribute-name . value) pairs for SAML assertion."))
