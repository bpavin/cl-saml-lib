(defpackage :cl-saml/tests/core/actions/generate-idp-metadata-test
  (:use :cl)
  (:nicknames :generate-idp-metadata-test)
  (:import-from :rove)
  (:import-from :cl-saml/src/core/app-ctx)
  (:export))

(in-package :cl-saml/tests/core/actions/generate-idp-metadata-test)

(defparameter app nil)

(rove:setup
  (setf app (make-instance 'app-ctx:app-ctx)))

(rove:deftest test-idp-metadata-generation
  (let* ((action (app-ctx:generate-idp-metadata app))
         (generated (generate-idp-metadata:run action
                                               :idp-entity-id "idp-entity-id"
                                               :idp-cert "certificate"
                                               :idp-sso-url "https://idp.login.url/saml"
                                               :idp-slo-url "https://idp.logout.url/saml")))

    (rove:ok (search "md:EntityDescriptor" generated))
    (rove:ok (search "md:IDPSSODescriptor WantAuthnRequestsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"" generated))
    (rove:ok (search "md:KeyDescriptor use=\"signing\"" generated))
    (rove:ok (search "ds:X509Data" generated))
    (rove:ok (search "ds:X509Certificate>cert" generated))
    (rove:ok (search "md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat" generated))
    (rove:ok (search "md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://idp.login.url/saml\"" generated))))
