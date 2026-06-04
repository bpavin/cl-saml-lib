(defpackage :cl-saml-lib/src/core/actions/generate-sp-metadata
  (:use :cl)
  (:nicknames :generate-sp-metadata)
  (:import-from :defclass-std)
  (:import-from :log4cl)
  (:import-from :cl-saml-lib/src/core/domain/metadata/entity-descriptor)
  (:export
   :generate-sp-metadata
   :run))

(in-package :cl-saml-lib/src/core/actions/generate-sp-metadata)

(defclass-std:defclass/std generate-sp-metadata ()
  ())

(defmethod run ((this generate-sp-metadata) &key sp-entity-id sp-cert sp-acs-url sp-slo-url sp-metadata-url want-assertions-signed)
  "Generate Service Provider metadata XML."
  (let* ((config (make-instance 'sp-config:sp-config
                                :entity-id sp-entity-id
                                :sp-certificate sp-cert
                                :acs-url sp-acs-url
                                :slo-url sp-slo-url
                                :want-assertions-signed want-assertions-signed)))
   (entity-descriptor:generate-sp-metadata-xml config)))
