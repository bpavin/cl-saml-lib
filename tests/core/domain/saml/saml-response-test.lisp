(defpackage :cl-saml/tests/core/domain/saml/saml-response-test
  (:use :cl)
  (:import-from :rove)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-response)
  (:export))

(in-package :cl-saml/tests/core/domain/saml/saml-response-test)

(defparameter *saml-response-1*
  "
<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\" Destination=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\">
  <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/>
  </samlp:Status>
  <saml:Assertion xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\" Version=\"2.0\" IssueInstant=\"2014-07-17T01:01:48Z\">
    <saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>
    <saml:Subject>
      <saml:NameID SPNameQualifier=\"http://sp.example.com/demo1/metadata.php\" Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\">_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7</saml:NameID>
      <saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\">
        <saml:SubjectConfirmationData NotOnOrAfter=\"2024-01-18T06:21:48Z\" Recipient=\"http://sp.example.com/demo1/index.php?acs\" InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore=\"2014-07-17T01:01:18Z\" NotOnOrAfter=\"2024-01-18T06:21:48Z\">
      <saml:AudienceRestriction>
        <saml:Audience>http://sp.example.com/demo1/metadata.php</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant=\"2014-07-17T01:01:48Z\" SessionNotOnOrAfter=\"2024-07-17T09:01:48Z\" SessionIndex=\"_be9967abd904ddcae3c0eb4189adbe3f71e327cf93\">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name=\"uid\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
        <saml:AttributeValue xsi:type=\"xs:string\">test</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=\"mail\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
        <saml:AttributeValue xsi:type=\"xs:string\">test@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name=\"eduPersonAffiliation\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\">
        <saml:AttributeValue xsi:type=\"xs:string\">users</saml:AttributeValue>
        <saml:AttributeValue xsi:type=\"xs:string\">examplerole1</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
")

(rove:deftest test-creating-and-generating-saml-response
  (let* ((xml-parser (make-instance 'cxml-impl:cxml-parser))
         (parsed (xml:parse-xml xml-parser *saml-response-1*))
         (saml-response (saml-response:parse-response-xml parsed)))

    (assert-saml-response-object saml-response)

    (let* ((saml-response-xml (saml-response:build-response-xml saml-response)))

      (assert-saml-response-xml saml-response-xml))))

(defun assert-saml-response-object (saml-response)
  (rove:ok (typep saml-response 'saml-response:saml-response) "Should be a valid saml-response object")
  
  ;; Extract all response fields to dedicated variables for clarity
  (let* ((id (saml-response:id saml-response))
         (version (saml-response:version saml-response))
         (issue-instant (saml-response:issue-instant saml-response))
         (destination (saml-response:destination saml-response))
         (in-response-to (saml-response:in-response-to saml-response))
         (issuer (saml-response:issuer saml-response))
         (status (saml-response:status saml-response))
         (assertions (saml-response:assertions saml-response))
         (assertion (first assertions)))
    
    ;; Assert response field values match expected values from *saml-response-1*
    (rove:ok (string= id "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6") "Response ID should match XML")
    (rove:ok (string= version "2.0") "Response version should be 2.0")
    ;; IssueInstant is parsed to integer timestamp - check it's not nil
    (rove:ok issue-instant "Response IssueInstant should be parsed")
    (rove:ok (string= destination "http://sp.example.com/demo1/index.php?acs") "Response destination should match XML")
    (rove:ok (string= in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685") "Response InResponseTo should match XML")
    ;; Check issuer (should be an issuer object with value)
    (rove:ok issuer "Response issuer should be present")
    (rove:ok (string= (issuer:issuer-value issuer) "http://idp.example.com/metadata.php") "Response issuer should match")
    ;; Check status (should be a saml-status object)
    (rove:ok status "Response status should be present")
    ;; Check assertions (should be a list with at least one assertion)
    (rove:ok assertions "Response assertions should be present")
    (rove:ok (= (length assertions) 1) "Response should have exactly 1 assertion")
    
    ;; Validate assertion fields
    (assert-assertion assertion)))

(defun assert-assertion (assertion)
  (when assertion
    (let* ((assertion-id (assertion:id assertion))
           (assertion-version (assertion:version assertion))
           (assertion-issue-instant (assertion:issue-instant assertion))
           (assertion-issuer (assertion:issuer assertion))
           (assertion-subject (assertion:subject assertion))
           (assertion-conditions (assertion:conditions assertion))
           (assertion-authn-statement (assertion:authn-statement assertion))
           (assertion-attribute-statement (assertion:attribute-statement assertion)))

      ;; Check assertion ID matches expected value from XML
      (rove:ok (string= assertion-id "_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75") "Assertion ID should match XML")
      (rove:ok (string= assertion-version "2.0") "Assertion version should be 2.0")
      (rove:ok assertion-issue-instant "Assertion IssueInstant should be parsed")

      ;; Check assertion issuer matches expected value
      (rove:ok assertion-issuer "Assertion issuer should be present")
      (rove:ok (string= (issuer:issuer-value assertion-issuer) "http://idp.example.com/metadata.php") "Assertion issuer should match")

      (assert-subject assertion-subject)

      (when assertion-conditions
        (let ((not-before (saml-conditions:conditions-not-before assertion-conditions))
              (not-on-or-after (saml-conditions:conditions-not-on-or-after assertion-conditions))
              (audience-restrictions (saml-conditions:conditions-audience-restrictions assertion-conditions)))

          (rove:ok not-before "Conditions NotBefore should be parsed")
          (rove:ok not-on-or-after "Conditions NotOnOrAfter should be parsed")
          (rove:ok audience-restrictions "Conditions audience restrictions should be present")
          (rove:ok (= (length audience-restrictions) 1) "Should have exactly 1 audience restriction")
          (when audience-restrictions
            (rove:ok (string= (first audience-restrictions) "http://sp.example.com/demo1/metadata.php") "Audience restriction should match XML"))))

      (let ((authn-instant (authn-statement:authn-instant assertion-authn-statement))
            (session-index (authn-statement:session-index assertion-authn-statement))
            (session-not-on-or-after (authn-statement:session-not-on-or-after assertion-authn-statement))
            (authn-context (authn-statement:authn-context assertion-authn-statement)))

        (rove:ok authn-instant "AuthnStatement AuthnInstant should be parsed")
        (rove:ok (string= session-index "_be9967abd904ddcae3c0eb4189adbe3f71e327cf93") "AuthnStatement SessionIndex should match XML")
        (rove:ok session-not-on-or-after "AuthnStatement SessionNotOnOrAfter should be parsed")
        (rove:ok authn-context "AuthnStatement AuthnContext should be present")

        (when authn-context
          (let ((authn-context-class-ref (authn-statement:class-ref authn-context)))
            (rove:ok (string= authn-context-class-ref "urn:oasis:names:tc:SAML:2.0:ac:classes:Password") "AuthnContext ClassRef should match XML"))))

      (when assertion-attribute-statement
        (let ((attributes (attributes:attribute-statement-attributes assertion-attribute-statement)))

          (rove:ok attributes "AttributeStatement attributes should be present")
          (rove:ok (= (length attributes) 3) "Should have exactly 3 attributes")

          ;; Validate uid attribute
          (let ((uid-attr (find "uid" attributes :key (lambda (attr) (attributes:name attr)) :test #'string=)))
            (rove:ok uid-attr "uid attribute should be present")
            (when uid-attr
              (let ((uid-values (attributes:attribute-values uid-attr)))
                (rove:ok uid-values "uid attribute values should be present")
                (rove:ok (= (length uid-values) 1) "uid should have exactly 1 value")
                (when uid-values
                  (rove:ok (string= (first uid-values) "test") "uid attribute value should match XML")))))

          ;; Validate mail attribute
          (let ((mail-attr (find "mail" attributes :key (lambda (attr) (attributes:name attr)) :test #'string=)))
            (rove:ok mail-attr "mail attribute should be present")
            (when mail-attr
              (let ((mail-values (attributes:attribute-values mail-attr)))
                (rove:ok mail-values "mail attribute values should be present")
                (rove:ok (= (length mail-values) 1) "mail should have exactly 1 value")
                (when mail-values
                  (rove:ok (string= (first mail-values) "test@example.com") "mail attribute value should match XML")))))

          ;; Validate eduPersonAffiliation attribute
          (let ((edu-attr (find "eduPersonAffiliation" attributes :key (lambda (attr) (attributes:name attr)) :test #'string=)))
            (rove:ok edu-attr "eduPersonAffiliation attribute should be present")
            (when edu-attr
              (let ((edu-values (attributes:attribute-values edu-attr)))
                (rove:ok edu-values "eduPersonAffiliation attribute values should be present")
                (rove:ok (= (length edu-values) 2) "eduPersonAffiliation should have exactly 2 values")
                (when edu-values
                  (rove:ok (string= (first edu-values) "users") "First eduPersonAffiliation value should match XML")
                  (rove:ok (string= (second edu-values) "examplerole1") "Second eduPersonAffiliation value should match XML"))))))))))

(defun assert-subject (assertion-subject)
  (when assertion-subject
    (let* ((name-id (subject:subject-name-id assertion-subject))
           (subject-confirmations (subject:subject-confirmations assertion-subject)))

      ;; Validate NameID
      (when name-id
        (let ((name-id-value (name-id:name-id-value name-id))
              (name-id-format (name-id:name-id-format name-id))
              (sp-name-qualifier (name-id:name-id-sp-name-qualifier name-id)))

          (rove:ok (string= name-id-value "_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7") "NameID value should match XML")
          (rove:ok (string= name-id-format "urn:oasis:names:tc:SAML:2.0:nameid-format:transient") "NameID format should match XML")
          (rove:ok (string= sp-name-qualifier "http://sp.example.com/demo1/metadata.php") "NameID SPNameQualifier should match XML")))

      ;; Validate SubjectConfirmations
      (rove:ok subject-confirmations "Subject confirmations should be present")
      (rove:ok (= (length subject-confirmations) 1) "Should have exactly 1 subject confirmation")

      (when subject-confirmations
        (let* ((confirmation (first subject-confirmations))
               (method (subject:confirmation-method confirmation))
               (confirmation-data (subject:confirmation-data confirmation))
               (recipient (subject:confirmation-recipient confirmation))
               (confirmation-in-response-to (subject:confirmation-in-response-to confirmation))
               (not-on-or-after (subject:confirmation-not-on-or-after confirmation)))

          (rove:ok (string= method "urn:oasis:names:tc:SAML:2.0:cm:bearer") "Subject confirmation method should match XML")
          (rove:ok (string= recipient "http://sp.example.com/demo1/index.php?acs") "Subject confirmation recipient should match XML")
          (rove:ok (string= confirmation-in-response-to "ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685") "Subject confirmation InResponseTo should match XML")
          (rove:ok not-on-or-after "Subject confirmation NotOnOrAfter should be parsed"))))))

(defun assert-saml-response-xml (saml-response-xml)
  ;; 1. Check namespace declarations
  (rove:ok (search-string "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"" saml-response-xml) "Should contain samlp namespace declaration")
  (rove:ok (search-string "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"" saml-response-xml) "Should contain saml namespace declaration")
  
  ;; 2. Check Response element with all attributes
  (rove:ok (search-string "samlp:Response" saml-response-xml) "Should contain samlp:Response element")
  (rove:ok (search-string "ID=\"_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6\"" saml-response-xml) "Should contain correct Response ID")
  (rove:ok (search-string "Version=\"2.0\"" saml-response-xml) "Should contain Version=\"2.0\"")
  (rove:ok (search-string "IssueInstant=\"2014-07-17T01:01:48Z\"" saml-response-xml) "Should contain correct IssueInstant")
  (rove:ok (search-string "Destination=\"http://sp.example.com/demo1/index.php?acs\"" saml-response-xml) "Should contain correct Destination")
  (rove:ok (search-string "InResponseTo=\"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685\"" saml-response-xml) "Should contain correct InResponseTo")
  
  ;; 3. Check Issuer element
  (rove:ok (search-string "<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>" saml-response-xml) "Should contain correct Issuer")
  
  ;; 4. Check Status element with success code
  (rove:ok (search-string "samlp:Status" saml-response-xml) "Should contain samlp:Status element")
  (rove:ok (search-string "samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"" saml-response-xml) "Should contain success status code")
  
  ;; 5. Check Assertion element with key attributes
  (rove:ok (search-string "saml:Assertion" saml-response-xml) "Should contain saml:Assertion element")
  (rove:ok (search-string "ID=\"_d71a3a8e9fcc45c9e9d248ef7049393fc8f04e5f75\"" saml-response-xml) "Should contain correct Assertion ID")
  (rove:ok (search-string "IssueInstant=\"2014-07-17T01:01:48Z\"" saml-response-xml) "Should contain correct Assertion IssueInstant")
  
  ;; 6. Check Assertion child elements
  (rove:ok (search-string "<saml:Issuer>http://idp.example.com/metadata.php</saml:Issuer>" saml-response-xml) "Should contain Assertion Issuer")
  (rove:ok (search-string "saml:Subject" saml-response-xml) "Should contain Subject element")
  (rove:ok (search-string "saml:NameID" saml-response-xml) "Should contain NameID element")
  (rove:ok (search-string "saml:Conditions" saml-response-xml) "Should contain Conditions element")
  (rove:ok (search-string "saml:AuthnStatement" saml-response-xml) "Should contain AuthnStatement element")
  (rove:ok (search-string "saml:AttributeStatement" saml-response-xml) "Should contain AttributeStatement element")
  
  ;; 7. Check key attribute values
  (rove:ok (search-string "Name=\"uid\"" saml-response-xml) "Should contain uid attribute")
  (rove:ok (search-string "Name=\"mail\"" saml-response-xml) "Should contain mail attribute")
  (rove:ok (search-string "Name=\"eduPersonAffiliation\"" saml-response-xml) "Should contain eduPersonAffiliation attribute")
  
  ;; 8. Check attribute values
  (rove:ok (search-string ">test<" saml-response-xml) "Should contain uid value 'test'")
  (rove:ok (search-string ">test@example.com<" saml-response-xml) "Should contain mail value 'test@example.com'")
  (rove:ok (search-string ">users<" saml-response-xml) "Should contain eduPersonAffiliation value 'users'"))

(defun search-string (search-for in-text)
  (search search-for in-text :test #'string-equal))
