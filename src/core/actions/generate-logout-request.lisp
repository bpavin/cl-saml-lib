(defpackage :cl-saml-lib/src/core/actions/generate-logout-request
  (:use :cl)
  (:nicknames :generate-logout-request)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/logout/logout-request)
  (:export
   #:generate-logout-request
   #:run
   #:from-logout-request-object))

(in-package :cl-saml-lib/src/core/actions/generate-logout-request)

(defclass-std:defclass/std generate-logout-request ()
  ((idp-config :type idp-config:idp-config)
   (crypto-provider :type crypto-provider:crypto-provider)))

(defmethod run ((this generate-logout-request) &key name-id session-index)
  "Generate SAML LogoutRequest XML string.
THIS: generate-logout-request instance
NAME-ID: optional name-id object for the user session to terminate
SESSION-INDEX: optional string - session index
Returns: LogoutRequest XML string"
  (logout-request:generate-logout-request-xml
   (idp-config this)
   :name-id name-id
   :session-index session-index))

(defmethod from-logout-request-object ((this generate-logout-request) logout-req)
  "Generate XML string from an existing logout-request object.
THIS: generate-logout-request instance
LOGOUT-REQ: logout-request instance
Returns: LogoutRequest XML string"
  (logout-request:logout-request-to-string logout-req))