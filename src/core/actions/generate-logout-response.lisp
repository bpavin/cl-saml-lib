(defpackage :cl-saml-lib/src/core/actions/generate-logout-response
  (:use :cl)
  (:nicknames :generate-logout-response)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-status)
  (:import-from :cl-saml-lib/src/core/domain/logout/logout-response)
  (:export
   :generate-logout-response
   :run))

(in-package :cl-saml-lib/src/core/actions/generate-logout-response)

(defclass-std:defclass/std generate-logout-response ()
  ((idp-config :type idp-config:idp-config)
   (crypto-provider :type crypto-provider:crypto-provider)))

(defmethod run ((this generate-logout-response) &key idp-config sign-response in-response-to status)
  "Generate a SAML LogoutResponse XML string.
THIS: generate-logout-response instance
IN-RESPONSE-TO: string - the ID of the LogoutRequest being responded to (required)
STATUS: optional saml-status instance (default: success status)
Returns: LogoutResponse XML string"
  (let* ((response (logout-response:generate-logout-response-from-config
                    idp-config
                    :in-response-to in-response-to
                    :status (when status
                              (make-instance 'saml-status:saml-status
                                             :status-code status))))
         (xml (logout-response:build-logout-response-xml response)))
    (if sign-response
        (setf xml
              (crypto-provider:sign-xml (crypto-provider this)
                                        xml (format nil "//*[@ID='~A']" (logout-response:id response))
                                        (idp-config:idp-private-key (idp-config this))
                                        (idp-config:idp-certificate (idp-config this)))))

    xml))
