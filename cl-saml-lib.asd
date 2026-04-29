(defsystem :cl-saml
  :name "cl-saml"
  :description "SAML Identity Provider simulation library for Common Lisp"
  :version "0.1.0"
  :author ""
  :license "MIT"
  :class :package-inferred-system
  :defsystem-depends-on (:asdf-package-system)
  :depends-on (#:local-time
               #:uuid
               #:defclass-std
               #:cxml
               #:xpath
               #:pem
               #:cl-saml-lib/src/core/app-ctx)
  :in-order-to ((test-op (test-op "cl-saml/tests"))))

(asdf:defsystem :cl-saml/tests
  :author ""
  :license ""
  :depends-on (#:rove #:cl-saml #:cl-ppcre)
  :components ((:module "tests"
                :components
                ((:file "core/domain/saml/saml-response-test")
                 (:file "core/actions/validate-saml-response-test")
                 (:file "core/actions/generate-sp-metadata-test")
                 (:file "core/actions/generate-idp-metadata-test")
                 (:file "core/actions/decode-idp-metadata-test")
                 (:file "core/actions/decode-sp-metadata-test")
                 (:file "core/infrastructure/crypto-provider-impl-test")
                 )))
  :description "Test system for cl-saml"
  :perform (test-op (op c) (symbol-call :rove :run c)))
