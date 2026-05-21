(defpackage :cl-saml-lib/src/core/infrastructure/sp-config
  (:use :cl)
  (:nicknames :sp-config)
  (:import-from :defclass-std)
  (:export
   #:sp-config
   #:entity-id
   #:sp-private-key
   #:sp-certificate
   #:acs-url
   #:slo-url
   #:get-sp-config
   #:want-assertions-signed))

(in-package :cl-saml-lib/src/core/infrastructure/sp-config)

(defclass-std:defclass/std sp-config ()
  ((entity-id :type string
              :doc "The unique Entity ID (issuer identifier) for the Service Provider")
   (sp-private-key :type t
                   :doc "The Service Provider's private key (PEM string)")
   (sp-certificate :type t
                   :doc "The Service Provider's X.509 certificate (PEM string)")
   (acs-url :type (or null string)
            :doc "The Assertion Consumer Service URL where SAML responses are sent")
   (slo-url :type (or null string)
            :doc "The Single Logout Service URL for logout requests")
   (want-assertions-signed :doc "Whether the Service Provider requires signed assertions")))