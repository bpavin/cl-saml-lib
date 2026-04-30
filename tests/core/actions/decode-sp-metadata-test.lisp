(defpackage :cl-saml-lib/tests/core/actions/decode-sp-metadata-test
  (:use :cl)
  (:nicknames :decode-sp-metadata-test)
  (:import-from :rove)
  (:import-from :cl-saml-lib/src/core/app-ctx)
  (:import-from :cl-saml-lib/src/core/actions/decode-sp-metadata)
  (:import-from :cl-saml-lib/src/core/infrastructure/sp-config)
  (:export))

(in-package :cl-saml-lib/tests/core/actions/decode-sp-metadata-test)

;; Dummy SP Metadata XML with all fields (entity-id, certificate, ACS, SLO)
(defparameter +sp-metadata-full+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://sp.example.com\">
  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                   AuthnRequestsSigned=\"false\"
                   WantAssertionsSigned=\"true\">
    <KeyDescriptor use=\"signing\">
      <ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">
        <ds:X509Data>
          <ds:X509Certificate>MIICpDCCAYwCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3F</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </KeyDescriptor>
    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                               Location=\"https://sp.example.com/acs\"
                               index=\"0\"/>
    <SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\"
                         Location=\"https://sp.example.com/slo/logout\"/>
  </SPSSODescriptor>
</EntityDescriptor>")

;; Dummy SP Metadata XML with only required fields (entity-id and ACS)
(defparameter +sp-metadata-minimal+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://minimal-sp.example.com\">
  <SPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                   AuthnRequestsSigned=\"false\"
                   WantAssertionsSigned=\"true\">
    <AssertionConsumerService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                               Location=\"https://minimal-sp.example.com/acs\"
                               index=\"0\"/>
  </SPSSODescriptor>
</EntityDescriptor>")

;; Invalid metadata with no SP descriptor (only IDP descriptor)
(defparameter +idp-metadata-invalid-for-sp+
  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                  entityID=\"https://idp.example.com\">
  <IDPSSODescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"
                    WantAuthnRequestsSigned=\"false\">
    <SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\"
                         Location=\"https://idp.example.com/sso/login\"/>
  </IDPSSODescriptor>
</EntityDescriptor>")

(defparameter app nil)

(rove:setup
  (setf app (make-instance 'app-ctx:app-ctx)))

(rove:deftest test-decode-sp-metadata-full
  "Test decoding SP metadata with all fields: entity-id, certificate, ACS, and SLO."
  (let* ((action (app-ctx:decode-sp-metadata app))
         (result (decode-sp-metadata:run action +sp-metadata-full+)))
    (rove:ok (typep result 'sp-config:sp-config) "Result is an sp-config instance")
    (rove:ok (string= (sp-config:entity-id result) "https://sp.example.com")
             "Entity ID is correctly parsed")
    (rove:ok (string= (sp-config:sp-certificate result) "MIICpDCCAYwCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3FTCCQDU+pQ4P3M3F")
             "SP certificate is correctly parsed")
    (rove:ok (string= (sp-config:acs-url result) "https://sp.example.com/acs")
             "ACS URL is correctly parsed")
    (rove:ok (string= (sp-config:slo-url result) "https://sp.example.com/slo/logout")
             "SLO URL is correctly parsed")))

(rove:deftest test-decode-sp-metadata-minimal
  "Test decoding SP metadata with only required fields: entity-id and ACS."
  (let* ((action (app-ctx:decode-sp-metadata app))
         (result (decode-sp-metadata:run action +sp-metadata-minimal+)))
    (rove:ok (typep result 'sp-config:sp-config) "Result is an sp-config instance")
    (rove:ok (string= (sp-config:entity-id result) "https://minimal-sp.example.com")
             "Entity ID is correctly parsed")
    (rove:ok (null (sp-config:sp-certificate result))
             "SP certificate is nil when not present")
    (rove:ok (string= (sp-config:acs-url result) "https://minimal-sp.example.com/acs")
             "ACS URL is correctly parsed")
    (rove:ok (null (sp-config:slo-url result))
             "SLO URL is nil when not present")))

(rove:deftest test-decode-sp-metadata-error-no-sp-descriptor
  "Test that decoding fails with appropriate error when metadata contains no SP descriptor."
  (let* ((action (app-ctx:decode-sp-metadata app)))
    (rove:ok (rove:signals 
                 (decode-sp-metadata:run action +idp-metadata-invalid-for-sp+)
                 'decode-sp-metadata:validation-error)
             "Signals validation error when no SP descriptor present")))
