(defpackage :cl-saml-lib/src/core/actions/decode-idp-metadata
  (:use :cl)
  (:nicknames :decode-idp-metadata)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/domain/metadata/entity-descriptor)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:export
   #:decode-idp-metadata
   #:validation-error
   #:validation-error-message
   #:run))

(in-package :cl-saml-lib/src/core/actions/decode-idp-metadata)

(defclass-std:defclass/std decode-idp-metadata ()
  ((xml-parser :type xml:xml-parser)))

(defmethod run ((this decode-idp-metadata) idp-metadata-xml)
  "Decode sp-metadata xml using the domain function.
Returns sp-config on success."
  (let* ((xml-document (xml:parse-xml (xml-parser this) idp-metadata-xml))
         (descriptor (entity-descriptor:parse-entity-descriptor-xml xml-document))
         (idp-desc (entity-descriptor:idp-descriptor descriptor))
         (sso (when idp-desc (car (idp-sso-descriptor:single-sign-on-service idp-desc))))
         (sso-url (when sso (endpoint:location sso)))
         (slo (when idp-desc (car (idp-sso-descriptor:single-logout-service idp-desc))))
         (slo-url (when slo (endpoint:location slo))))

    (unless idp-desc
      (error 'validation-error :text "There is no valid idp-descriptor."))

    (let* ((kds (role-descriptor:key-descriptors idp-desc))
           (key (find :signing kds :key #'key-descriptor:key-use)))
      (make-instance 'idp-config:idp-config
                     :entity-id (entity-descriptor:entity-id descriptor)
                     :idp-certificate (create-certificate key)
                     :sso-url sso-url
                     :slo-url slo-url))))

(defun create-certificate (key)
  (when (and key (not (search "BEGIN " (key-descriptor:key-certificate key))))
    (format nil "-----BEGIN CERTIFICATE-----~%~A~%-----END CERTIFICATE-----"
            (key-descriptor:key-certificate key))))

(define-condition validation-error (error)
  ())
