(defpackage :cl-saml-lib/src/core/actions/decode-sp-metadata
  (:use :cl)
  (:nicknames :decode-sp-metadata)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/domain/metadata/entity-descriptor)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:decode-sp-metadata
   #:validation-error
   #:validation-error-message
   #:run))

(in-package :cl-saml-lib/src/core/actions/decode-sp-metadata)

;;; Validation Error Condition

(defclass-std:defclass/std decode-sp-metadata ()
  ((xml-parser :type xml:xml-parser)))

(defmethod run ((this decode-sp-metadata) sp-metadata-xml)
  "Decode sp-metadata xml using the domain function.
Returns sp-config on success."
  (let* ((xml-document (xml:parse-xml (xml-parser this) sp-metadata-xml))
         (descriptor (entity-descriptor:parse-entity-descriptor-xml xml-document))
         (sp-desc (entity-descriptor:sp-sso-descriptor descriptor))
         (acs (when sp-desc (car (sp-sso-descriptor:assertion-consumer-service sp-desc))))
         (acs-url (when acs (endpoint:location acs)))
         (slo (when sp-desc (car (sp-sso-descriptor:single-logout-service sp-desc))))
         (slo-url (when slo (endpoint:location slo))))

    (unless sp-desc
      (error 'validation-error :text "There is no valid sp-descriptor."))

    (let* ((kds (role-descriptor:key-descriptors sp-desc))
           (key (find :signing kds :key #'key-descriptor:key-use)))
      (make-instance 'sp-config:sp-config
                     :entity-id (entity-descriptor:entity-id descriptor)
                     :sp-certificate (when key (key-descriptor:key-certificate key))
                     :acs-url acs-url
                     :slo-url slo-url))))

(define-condition validation-error (error)
  ())
