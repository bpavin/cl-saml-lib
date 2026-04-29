(defpackage :cl-saml-lib/src/core/actions/validate-saml-response
  (:use :cl)
  (:nicknames :validate-saml-response)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/infrastructure/cxml-impl)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-response)
  (:export
   :validate-saml-response
   :run))

(in-package :cl-saml-lib/src/core/actions/validate-saml-response)

(defclass-std:defclass/std validate-saml-response ()
  ((xml-parser :type xml:xml-parser)
   (crypto-provider :type crypto-provider:crypto-provider)))

(defmethod run ((this validate-saml-response) saml-response-xml idp-config
                &key (verify-response-signature-p T) (verify-assertions-signature-p T))
  (let* ((xml (xml:parse-xml (xml-parser this) saml-response-xml))
         (response (saml-response:parse-response-xml xml))
         (response-has-id (not (string-equal "" (saml-response:id response)))))

    (when (and response-has-id verify-response-signature-p)
      (let* ((xpath (if response-has-id
                        (format nil "//*[@ID='~A']" (saml-response:id response))
                        (format nil "/*"))))

        (log:info "Verifing node with id = ~A" xpath)
        (crypto-provider:verify-signature (crypto-provider this)
                                          saml-response-xml
                                          xpath
                                          (idp-config:idp-certificate idp-config))))

    (when verify-assertions-signature-p
      (dolist (assertion (saml-response:assertions response))
        (log:info "Verifing node with id = //*[@ID='~A']" (assertion:id assertion))
        (crypto-provider:verify-signature (crypto-provider this)
                                          saml-response-xml
                                          (format nil "//*[@ID='~A']" (assertion:id assertion))
                                          (idp-config:idp-certificate idp-config))))

    response))
