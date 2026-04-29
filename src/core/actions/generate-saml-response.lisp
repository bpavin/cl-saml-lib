(defpackage :cl-saml-lib/src/core/actions/generate-saml-response
  (:use :cl)
  (:nicknames :generate-saml-response)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/saml/authn-request)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-status)
  (:export
   #:generate-saml-response
   #:run))

(in-package :cl-saml-lib/src/core/actions/generate-saml-response)

(defclass-std:defclass/std generate-saml-response ()
  ((idp-config :type idp-config:idp-config)
   (crypto-provider :type crypto-provider:crypto-provider)))

(defmethod run (this authn-request username user-attributes)
  "Generate SAML Response from AuthnRequest.
THIS: generate-saml-response instance
AUTHN-REQUEST: authn-request instance
USERNAME: string - authenticated username
USER-ATTRIBUTES: alist of (attribute-name . value) pairs
Returns: signed SAMLResponse XML string"

  (let* ((name-id (make-instance 'name-id:name-id :value username))
         (subject (make-instance 'subject:subject :name-id name-id))
         (issuer (make-instance 'issuer:issuer
                                :value (idp-config:entity-id (idp-config this))))
         (assertion (make-instance 'assertion:assertion
                                   :issuer issuer
                                   :subject subject))
         (status (make-instance 'saml-status:saml-status
                                :status-code namespaces:+status-success+))
         (issuer (make-instance 'issuer:issuer
                                :value (idp-config:entity-id (idp-config this))))
         (response (saml-response:make-saml-response
                    status
                    :in-response-to (authn-request:id authn-request)
                    :destination (authn-request:assertion-consumer-service-url authn-request)
                    :issuer issuer
                    :assertions
                    (list assertion)))
         (xml (saml-response:build-response-xml response))
         (signed-assertion (crypto-provider:sign-xml (crypto-provider this)
                                           xml (format nil "//*[@ID='~A']" (assertion:id assertion))
                                           (idp-config:idp-private-key (idp-config this))
                                           (idp-config:idp-certificate (idp-config this))))

         (signed-response (crypto-provider:sign-xml (crypto-provider this)
                                           signed-assertion "/samlp:Response"
                                           (idp-config:idp-private-key (idp-config this))
                                           (idp-config:idp-certificate (idp-config this)))))
    signed-response))
