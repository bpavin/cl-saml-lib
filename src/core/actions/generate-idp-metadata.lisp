(defpackage :cl-saml-lib/src/core/actions/generate-idp-metadata
  (:use :cl)
  (:nicknames :generate-idp-metadata)
  (:import-from :defclass-std)
  (:import-from :log4cl)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/entity-descriptor)
  (:export
   :generate-idp-metadata
   :run))

(in-package :cl-saml-lib/src/core/actions/generate-idp-metadata)

(defclass-std:defclass/std generate-idp-metadata ()
  ())

(defmethod run ((this generate-idp-metadata) &key idp-entity-id idp-cert idp-sso-url idp-slo-url)
  "Generate Identity Provider metadata XML."
  (let ((config (make-instance 'idp-config:idp-config
                               :entity-id idp-entity-id
                               :idp-certificate idp-cert
                               :sso-url idp-sso-url
                               :slo-url idp-slo-url)))
    (entity-descriptor:generate-idp-metadata-xml config)))
