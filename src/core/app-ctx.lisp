(defpackage :cl-saml-lib/src/core/app-ctx
  (:use :cl)
  (:nicknames :app-ctx)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider-impl)
  (:import-from :cl-saml-lib/src/core/infrastructure/cxml-impl)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:import-from :cl-saml-lib/src/core/infrastructure/sp-config)
  (:import-from :cl-saml-lib/src/core/actions/decode-authn-request)
  (:import-from :cl-saml-lib/src/core/actions/validate-authn-request)
  (:import-from :cl-saml-lib/src/core/actions/validate-saml-response)
  (:import-from :cl-saml-lib/src/core/actions/generate-saml-response)
  (:import-from :cl-saml-lib/src/core/actions/decode-sp-metadata)
  (:import-from :cl-saml-lib/src/core/actions/decode-idp-metadata)
  (:import-from :cl-saml-lib/src/core/actions/generate-sp-metadata)
  (:import-from :cl-saml-lib/src/core/actions/generate-idp-metadata)
  (:import-from :cl-saml-lib/src/core/actions/generate-authn-request)
  (:import-from :cl-saml-lib/src/core/actions/generate-logout-request)
  (:import-from :cl-saml-lib/src/core/actions/generate-logout-response)
  (:import-from :cl-saml-lib/src/core/actions/decode-logout-request)
  (:export
   #:app-ctx
   #:idp-config
   #:sp-config
   #:crypto-provider
   #:xml-parser
   #:decode-authn-request
   #:validate-authn-request
   #:validate-saml-response
   #:generate-saml-response
   #:decode-sp-metadata
   #:decode-idp-metadata
   #:generate-sp-metadata
   #:generate-idp-metadata
   #:generate-authn-request
   #:generate-logout-request
   #:generate-logout-response
   #:decode-logout-request
   #:shutdown))

(in-package :cl-saml-lib/src/core/app-ctx)

(defclass-std:defclass/std app-ctx ()
  ((crypto-provider :type crypto-provider:crypto-provider)
   (xml-parser :type xml:xml-parser)
   (idp-config :type idp-config:idp-config)
   (sp-config :type sp-config:sp-config)
   (decode-authn-request :type decode-authn-request:decode-authn-request)
   (validate-authn-request :type validate-authn-request:validate-authn-request)
   (validate-saml-response :type validate-saml-response:validate-saml-response)
   (generate-saml-response :type generate-saml-response:generate-saml-response)
   (decode-sp-metadata :type decode-sp-metadata:decode-sp-metadata)
   (decode-idp-metadata :type decode-idp-metadata:decode-idp-metadata)
   (generate-sp-metadata :type generate-sp-metadata:generate-sp-metadata)
   (generate-idp-metadata :type generate-idp-metadata:generate-idp-metadata)
   (generate-authn-request :type generate-authn-request:generate-authn-request)
   (generate-logout-request :type generate-logout-request:generate-logout-request)
   (generate-logout-response :type generate-logout-response:generate-logout-response)
   (decode-logout-request :type decode-logout-request:decode-logout-request)))

;; https://sptest.iamshowcase.com/ixs?idp=69dc12aa2ca82c62e8c4016899d961e798eac60c
(defmethod initialize-instance :after ((this app-ctx) &key)
  (setf (crypto-provider this)
        (make-instance 'crypto-provider-impl:crypto-provider-impl))

  (setf (xml-parser this)
        (make-instance 'cxml-impl:cxml-parser))

  (setf (idp-config this)
        (create-idp-config))
  (setf (sp-config this)
        (create-sp-config))

  (setf (decode-authn-request this)
        (make-instance 'decode-authn-request:decode-authn-request
                       :xml-parser (xml-parser this)))
  (setf (validate-authn-request this)
        (make-instance 'validate-authn-request:validate-authn-request))

  (setf (validate-saml-response this)
        (make-instance 'validate-saml-response:validate-saml-response
                       :xml-parser (xml-parser this)
                       :crypto-provider (crypto-provider this)))

  (setf (decode-idp-metadata this)
        (make-instance 'decode-idp-metadata:decode-idp-metadata
                       :xml-parser (xml-parser this)))
  (setf (decode-sp-metadata this)
        (make-instance 'decode-sp-metadata:decode-sp-metadata
                       :xml-parser (xml-parser this)))
  (setf (generate-sp-metadata this)
        (make-instance 'generate-sp-metadata:generate-sp-metadata))
  (setf (generate-idp-metadata this)
        (make-instance 'generate-idp-metadata:generate-idp-metadata))
  (setf (generate-saml-response this)
        (make-instance 'generate-saml-response:generate-saml-response
                       :idp-config (idp-config this)
                       :crypto-provider (crypto-provider this)))
  (setf (generate-authn-request this)
        (make-instance 'generate-authn-request:generate-authn-request))
  (setf (generate-logout-request this)
        (make-instance 'generate-logout-request:generate-logout-request
                       :idp-config (idp-config this)
                       :crypto-provider (crypto-provider this)))
  (setf (generate-logout-response this)
        (make-instance 'generate-logout-response:generate-logout-response
                       :idp-config (idp-config this)
                       :crypto-provider (crypto-provider this)))
  (setf (decode-logout-request this)
        (make-instance 'decode-logout-request:decode-logout-request
                       :xml-parser (xml-parser this))))

(defun create-idp-config ()
  (let* ((project (asdf:system-source-directory :cl-saml-lib))
         (private-raw (alexandria:read-file-into-string (merge-pathnames "certs/key.pem" project)))
         (cert-raw (alexandria:read-file-into-string (merge-pathnames "certs/cert.pem" project))))
    (make-instance 'idp-config:idp-config
                   :entity-id "local-idp"
                   :sso-url "http://localhost:5000/saml/idp/login"
                   :idp-private-key private-raw
                   :idp-certificate cert-raw)))

(defun create-sp-config ()
  (let* ((project (asdf:system-source-directory :cl-saml-lib))
         (private-raw (alexandria:read-file-into-string (merge-pathnames "certs/key.pem" project)))
         (cert-raw (alexandria:read-file-into-string (merge-pathnames "certs/cert.pem" project))))
    (make-instance 'sp-config:sp-config
                   :entity-id "local-sp"
                   :acs-url "http://localhost:5000/saml/sp/login"
                   :sp-private-key private-raw
                   :sp-certificate cert-raw)))

(defmethod shutdown ((this app-ctx) &key)
  (log:info "app-ctx shutdown")
  (crypto-provider-impl:cleanup (crypto-provider this)))