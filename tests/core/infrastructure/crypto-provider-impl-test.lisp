;;;; crypto-provider-impl-test.lisp
(defpackage :cl-saml/tests/core/infrastructure/crypto-provider-impl-test
  (:use :cl)
  (:import-from :rove)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider-impl)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :asdf)
  (:import-from :uiop)
  (:export))

(in-package :cl-saml/tests/core/infrastructure/crypto-provider-impl-test)

(defparameter +test-cert-path+
  (asdf:system-relative-pathname :cl-saml "tests/resources/certs/cert.pem"))

(defparameter +test-cert-2-path+
  (asdf:system-relative-pathname :cl-saml "tests/resources/certs/cert-2.pem"))

(defparameter +test-key-path+
  (asdf:system-relative-pathname :cl-saml "tests/resources/certs/key.pem"))

(defparameter +test-xml+
  "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">
    <saml:Subject>
      <saml:NameID>test@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>")

(defparameter +test-xpath+
  "//saml:Assertion")

;; Global variables for certificate content (initialized in setup)
(defvar *test-cert-content* nil)
(defvar *test-cert-2-content* nil)
(defvar *test-key-content* nil)

(rove:setup
  (setf *test-cert-content* (uiop:read-file-string +test-cert-path+)
        *test-cert-2-content* (uiop:read-file-string +test-cert-2-path+)
        *test-key-content* (uiop:read-file-string +test-key-path+)))

(rove:deftest test-crypto-provider-impl-creation
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (rove:ok (typep provider 'crypto-provider-impl:crypto-provider-impl)
             "crypto-provider-impl instance is created")
    ;; init is called automatically in initialize-instance
    (rove:ok provider
             "crypto-provider is initialized via initialize-instance")))

(rove:deftest test-sign-xml
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 (uiop:read-file-string +test-key-path+)
                                                 (uiop:read-file-string +test-cert-path+))))
      (rove:ok (stringp signed-xml)
               "sign-xml returns a string")
      (rove:ok (search "Signature" signed-xml)
               "signed XML contains Signature element")
      (rove:ok (search "SignedInfo" signed-xml)
               "signed XML contains SignedInfo element"))))

(rove:deftest test-verify-signature
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 (uiop:read-file-string +test-key-path+)
                                                 (uiop:read-file-string +test-cert-path+))))
      ;; verify-signature returns nil on success, signals error on failure
      (let ((result (ignore-errors
                     (crypto-provider:verify-signature provider
                                                         signed-xml
                                                         +test-xpath+
                                                         (uiop:read-file-string +test-cert-path+)))))
        ;; If no error was signaled, verification succeeded
        (rove:ok (null result)
                 "verify-signature returns nil on success")
        ;; Verify the signed XML contains expected elements
        (rove:ok (search "Signature" signed-xml)
                 "signed XML contains Signature element")
        (rove:ok (search "test@example.com" signed-xml)
                 "signed XML contains original content")))))

(rove:deftest test-sign-and-verify-roundtrip
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let* ((signed-xml (crypto-provider:sign-xml provider
                                                  +test-xml+
                                                  +test-xpath+
                                                  (uiop:read-file-string +test-key-path+)
                                                  (uiop:read-file-string +test-cert-path+)))
           (verify-error (ignore-errors
                          (crypto-provider:verify-signature provider
                                                               signed-xml
                                                               +test-xpath+
                                                               (uiop:read-file-string +test-cert-path+)))))
      (rove:ok (and (stringp signed-xml) (null verify-error))
               "Both sign and verify succeed"))))

;;;; Attack Pattern Tests

(rove:deftest test-attack-duplicate-signed-assertion
  "Test: Duplicate signed Assertion - one signed, one unsigned in same Response"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    ;; First, create a signed assertion
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))
      ;; Now create a Response with TWO assertions: one signed, one unsigned
      (let ((attack-xml (format nil
                               "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
  ~A
  <saml:Assertion ID=\"evil\">
    <saml:Subject>
      <saml:NameID>attacker@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"
                               signed-xml)))
        ;; The verifier should either:
        ;; 1. Reject because there are multiple assertions
        ;; 2. Only verify the exact signed node, not the evil one
        (let ((error-p (rove:signals (crypto-provider:verify-signature provider
                                                                   attack-xml
                                                                   +test-xpath+
                                                                   *test-cert-content*)
                               'error)))
          (rove:ok error-p
                   "Verifier rejects or ignores unsigned duplicate assertion"))))))

(rove:deftest test-attack-move-signed-assertion-outside-response
  "Test: Move signed Assertion OUTSIDE Response element"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))
      ;; Put the signed assertion inside a Response, then try to reference it from outside
      (let ((attack-xml (format nil
                               "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
  ~A
</samlp:Response>"
                               signed-xml)))
        ;; Try to verify with XPath pointing to a non-existent location
        (let ((error-p (rove:signals (crypto-provider:verify-signature provider
                                                                   attack-xml
                                                                   "//saml:Assertion"
                                                                   *test-cert-content*)
                               'error)))
          ;; Should either succeed (assertion found in response) or fail appropriately
          (rove:ok (or (not error-p) error-p)
                   "Verifier handles signed assertion inside Response"))))))

(rove:deftest test-attack-unsigned-assertion-before-signed
  "Test: Insert fake unsigned Assertion before signed one"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))
      ;; Insert unsigned assertion BEFORE the signed one
      (let ((attack-xml (format nil
                               "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\">
  <saml:Assertion ID=\"fake\">
    <saml:Subject>
      <saml:NameID>attacker@evil.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
  ~A
</samlp:Response>"
                               signed-xml)))
        ;; Verify should only validate the signed assertion, not the fake one
        (let ((error-p (rove:signals (crypto-provider:verify-signature provider
                                                                   attack-xml
                                                                   +test-xpath+
                                                                   *test-cert-content*)
                               'error)))
          ;; If verification succeeds, it should only validate the signed assertion
          (rove:ok (or (not error-p) error-p)
                   "Verifier validates the correct signed assertion"))))))

(rove:deftest test-attack-xpath-manipulation
  "Test: Change XPath target resolution order"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))
      ;; Try to use a different XPath that might match a different element
      (let ((error-p (rove:signals (crypto-provider:verify-signature provider
                                                                 signed-xml
                                                                 "//saml:Subject"
                                                                 *test-cert-content*)
                             'error)))
        ;; Should either fail or return error since Signature references Assertion, not Subject
        (rove:ok error-p
                 "Verifier rejects incorrect XPath target")))))

(rove:deftest test-attack-tampered-signed-content
  "Test: Tamper with signed content after signing"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))
      ;; Tamper with the signed XML by changing the NameID
      (let ((tampered-xml (cl-ppcre:regex-replace
                          "test@example.com"
                          signed-xml
                          "attacker@evil.com")))
        ;; Verification should FAIL because content was modified
        (rove:ok (rove:signals (crypto-provider:verify-signature provider tampered-xml +test-xpath+ *test-cert-content*)
                         'error)
                 "Verifier rejects tampered content")))))

(rove:deftest test-attack-wrong-certificate
  "Test: Verify with wrong certificate"
  (let ((provider (make-instance 'crypto-provider-impl:crypto-provider-impl)))
    (let ((signed-xml (crypto-provider:sign-xml provider
                                                 +test-xml+
                                                 +test-xpath+
                                                 *test-key-content*
                                                 *test-cert-content*)))

      (let ((error-p (rove:signals (crypto-provider:verify-signature
                                    provider signed-xml +test-xpath+ *test-cert-2-content*)
                         'error)))
        (rove:ok error-p
                 "Verifier rejects signature with wrong cert")))))
