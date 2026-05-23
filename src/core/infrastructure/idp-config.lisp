(defpackage :cl-saml-lib/src/core/infrastructure/idp-config
  (:use :cl)
  (:nicknames :idp-config)
  (:import-from :defclass-std)
  (:export
   #:idp-config
   #:entity-id
   #:idp-private-key
   #:idp-certificate
   #:sso-url
   #:slo-url
   #:get-idp-config))

(in-package :cl-saml-lib/src/core/infrastructure/idp-config)

(defclass-std:defclass/std idp-config ()
  ((entity-id :type string
              :doc "The unique Entity ID (issuer identifier) for the Identity Provider")
   (idp-private-key :type (or null string)
                    :doc "The Identity Provider's private key (PEM string)")
   (idp-certificate :type (or null string) 
                    :doc "The Identity Provider's X.509 certificate (PEM string)")
   (sso-url :type (or null string)
            :doc "The Single Sign-On URL for SAML authentication requests")
   (slo-url :type (or null string)
            :doc "The Single Logout Service URL for logout requests")))
