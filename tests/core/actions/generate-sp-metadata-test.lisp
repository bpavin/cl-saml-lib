(defpackage :cl-saml/tests/core/actions/generate-sp-metadata-test
  (:use :cl)
  (:nicknames :generate-sp-metadata-test)
  (:import-from :rove)
  (:import-from :cl-saml-lib/src/core/app-ctx)
  (:import-from :generate-sp-metadata)
  (:import-from :sp-config)
  (:export))

(in-package :cl-saml/tests/core/actions/generate-sp-metadata-test)

;; Test parameters
(defparameter +test-entity-id+ "https://example.com/sp")
(defparameter +test-acs-url+ "https://example.com/saml/acs")
(defparameter +test-slo-url+ "https://example.com/saml/slo")
(defparameter +test-cert-path+ "certs/sp-cert.pem")

(defparameter app nil)

(rove:setup
  (setf app (make-instance 'app-ctx:app-ctx)))

(rove:deftest test-sp-metadata-generation-with-parameters
  "Test SP metadata generation with explicit parameters."
  (let* ((action (app-ctx:generate-sp-metadata app))
         (generated (generate-sp-metadata:run action
                        :sp-entity-id +test-entity-id+
                        :sp-cert +test-cert-path+
                        :sp-acs-url +test-acs-url+)))
    (rove:ok (stringp generated) "Generated metadata is a string")
    (rove:ok (plusp (length generated)) "Generated metadata is not empty")
    ;; Verify essential SAML metadata elements
    (rove:ok (search "EntityDescriptor" generated) "Contains EntityDescriptor element")
    (rove:ok (search +test-entity-id+ generated) "Contains entityID")
    (rove:ok (search "SPSSODescriptor" generated) "Contains SPSSODescriptor element")
    (rove:ok (search "AssertionConsumerService" generated) "Contains AssertionConsumerService")
    (rove:ok (search +test-acs-url+ generated) "Contains ACS URL")
    (rove:ok (search "WantAssertionsSigned" generated) "Contains WantAssertionsSigned attribute")
    (rove:ok (search "KeyDescriptor" generated) "Contains KeyDescriptor for certificate")))

(rove:deftest test-sp-metadata-generation-with-slo
  "Test SP metadata generation includes SingleLogoutService when SLO URL provided."
  (let* ((action (app-ctx:generate-sp-metadata app))
         (generated (generate-sp-metadata:run action
                        :sp-entity-id +test-entity-id+
                        :sp-cert +test-cert-path+
                        :sp-acs-url +test-acs-url+
                        :sp-slo-url +test-slo-url+)))
    (rove:ok (search "SingleLogoutService" generated) "Contains SingleLogoutService when SLO URL provided")
    (rove:ok (search +test-slo-url+ generated) "Contains SLO URL")))

(rove:deftest test-sp-metadata-generation-defaults
  "Test SP metadata generation works with minimal parameters."
  (let* ((action (app-ctx:generate-sp-metadata app))
         (generated (generate-sp-metadata:run action
                        :sp-entity-id +test-entity-id+
                        :sp-acs-url +test-acs-url+)))
    (rove:ok (stringp generated) "Generated metadata is a string with minimal params")
    (rove:ok (search "EntityDescriptor" generated) "Contains EntityDescriptor")))

(rove:deftest test-sp-metadata-certificate-element
  "Test SP metadata contains a certificate element in KeyDescriptor."
  (let* ((action (app-ctx:generate-sp-metadata app))
         (generated (generate-sp-metadata:run action
                        :sp-entity-id +test-entity-id+
                        :sp-cert +test-cert-path+
                        :sp-acs-url +test-acs-url+)))
    ;; Verify KeyDescriptor element exists (contains the certificate)
    (rove:ok (search "KeyDescriptor" generated)
             "Generated XML contains KeyDescriptor element")
    ;; Verify it's marked for signing use
    (rove:ok (search "use=\"signing\"" generated)
             "KeyDescriptor has signing use attribute")
    ;; Verify KeyInfo element exists (holds the key data)
    (rove:ok (search "KeyInfo" generated)
             "Generated XML contains KeyInfo element")))
