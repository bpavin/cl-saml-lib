(defpackage :cl-saml/src/core/infrastructure/sp-config
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
   #:get-sp-config))

(in-package :cl-saml/src/core/infrastructure/sp-config)

(defclass-std:defclass/std sp-config ()
  ((entity-id :type string)
   (sp-private-key :type t)
   (sp-certificate :type t)
   (acs-url :type (or null string))
   (slo-url :type (or null string))))