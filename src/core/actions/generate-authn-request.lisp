(defpackage :cl-saml-lib/src/core/actions/generate-authn-request
  (:use :cl)
  (:nicknames :generate-authn-request)
  (:import-from :defclass-std)
  (:import-from :log4cl)
  (:import-from :cl-saml-lib/src/core/infrastructure/sp-config)
  (:import-from :cl-saml-lib/src/core/domain/saml/authn-request)
  (:export
   :generate-authn-request
   :run))

(in-package :cl-saml-lib/src/core/actions/generate-authn-request)

(defclass-std:defclass/std generate-authn-request ()
  ())

(defmethod run ((this generate-authn-request) &key sp-entity-id sp-cert acs-url slo-url)
  "Generate a SAML authentication request."
  (let ((config (make-instance 'sp-config:sp-config
                               :entity-id sp-entity-id
                               :sp-certificate sp-cert
                               :acs-url acs-url
                               :slo-url slo-url)))
    (authn-request:generate-authn-request-xml config)))