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
  ((entity-id :type string)
   (idp-private-key :type t)
   (idp-certificate :type t)
   (sso-url :type (or null string))
   (slo-url :type (or null string))))

