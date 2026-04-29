(defpackage :cl-saml/src/core/actions/generate-sp-metadata
  (:use :cl)
  (:nicknames :generate-sp-metadata)
  (:import-from :defclass-std)
  (:import-from :log4cl)
  (:import-from :cl-saml/src/core/domain/metadata/entity-descriptor)
  (:export
   :generate-sp-metadata
   :run))

(in-package :cl-saml/src/core/actions/generate-sp-metadata)

(defclass-std:defclass/std generate-sp-metadata ()
  ())

(defmethod run ((this generate-sp-metadata) &key sp-entity-id sp-cert sp-acs-url sp-slo-url sp-metadata-url)
  "Generate Service Provider metadata XML."
  (let* ((config (make-instance 'sp-config:sp-config
                                :entity-id sp-entity-id
                                :sp-certificate sp-cert
                                :acs-url sp-acs-url
                                :slo-url sp-slo-url)))
   (entity-descriptor:generate-sp-metadata-xml config)))
