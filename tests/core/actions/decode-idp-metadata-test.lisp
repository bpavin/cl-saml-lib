(defpackage :cl-saml-lib/tests/core/actions/decode-idp-metadata-test
  (:use :cl)
  (:nicknames :decode-idp-metadata-test)
  (:import-from :rove)
  (:import-from :cl-saml-lib/src/core/app-ctx)
  (:import-from :cl-saml-lib/src/core/actions/decode-idp-metadata)
  (:import-from :cl-saml-lib/src/core/infrastructure/idp-config)
  (:export))

(in-package :cl-saml-lib/tests/core/actions/decode-idp-metadata-test)

;; Dummy IDP Metadata XML with all fields (entity-id, certificate, SSO, SLO)
(defparameter +idp-metadata-full+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://idp.example.com\">
  <IDPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                    WantAuthnRequestsSigned=\"false\">
    <KeyDescriptor use=\"signing\">
      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3F</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                         Location=\"https://idp.example.com/sso/login\"/>
    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"
                         Location=\"https://idp.example.com/slo/logout\"/>
  </IDPSSODescriptor>
</EntityDescriptor>")

;; Dummy IDP Metadata XML with only required fields (entity-id and SSO)
(defparameter +idp-metadata-minimal+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://minimal-idp.example.com\">
  <IDPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                    WantAuthnRequestsSigned=\"false\">
    <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                         Location=\"https://minimal-idp.example.com/sso/login\"/>
  </IDPSSODescriptor>
</EntityDescriptor>")

;; Invalid metadata with no IDP descriptor (only SP descriptor)
(defparameter +sp-metadata-invalid-for-idp+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://sp.example.com\">
  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                   AuthnRequestsSigned=\"false\"
                   WantAssertionsSigned=\"true\">
    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                               Location=\"https://sp.example.com/acs\"
                               index=\"0\"/>
  </SPSSODescriptor>
</EntityDescriptor>")

(defparameter app nil)

(rove:setup
  (setf app (make-instance 'app-ctx:app-ctx)))

(rove:deftest test-decode-idp-metadata-full
  "Test decoding IDP metadata with all fields: entity-id, certificate, SSO, and SLO."
  (let* ((action (app-ctx:decode-idp-metadata app))
         (result (decode-idp-metadata:run action +idp-metadata-full+)))
    (rove:ok (typep result 'idp-config:idp-config) "Result is an idp-config instance")
    (rove:ok (string= (idp-config:entity-id result) "https://idp.example.com")
             "Entity ID is correctly parsed")
    (rove:ok (string= (idp-config:idp-certificate result) "-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3F
-----END CERTIFICATE-----")
             "IDP certificate is correctly parsed")
    (rove:ok (string= (idp-config:sso-url result) "https://idp.example.com/sso/login")
             "SSO URL is correctly parsed")
    (rove:ok (string= (idp-config:slo-url result) "https://idp.example.com/slo/logout")
             "SLO URL is correctly parsed")))

(rove:deftest test-decode-idp-metadata-minimal
  "Test decoding IDP metadata with only required fields: entity-id and SSO."
  (let* ((action (app-ctx:decode-idp-metadata app))
         (result (decode-idp-metadata:run action +idp-metadata-minimal+)))
    (rove:ok (typep result 'idp-config:idp-config) "Result is an idp-config instance")
    (rove:ok (string= (idp-config:entity-id result) "https://minimal-idp.example.com")
             "Entity ID is correctly parsed")
    (rove:ok (null (idp-config:idp-certificate result))
             "IDP certificate is nil when not present")
    (rove:ok (string= (idp-config:sso-url result) "https://minimal-idp.example.com/sso/login")
             "SSO URL is correctly parsed")
    (rove:ok (null (idp-config:slo-url result))
             "SLO URL is nil when not present")))

(rove:deftest test-decode-idp-metadata-error-no-idp-descriptor
  "Test that decoding fails with appropriate error when metadata contains no IDP descriptor."
  (let* ((action (app-ctx:decode-idp-metadata app)))
    (rove:ok (rove:signals
                 (decode-idp-metadata:run action +sp-metadata-invalid-for-idp+)
                 'decode-idp-metadata:validation-error)
             "Signals validation error when no IDP descriptor present")))
