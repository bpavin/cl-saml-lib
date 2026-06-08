(defpackage :cl-saml-lib/src/core/domain/metadata/endpoint
  (:use #:cl)
  (:nicknames :endpoint)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml-lib/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml-lib/src/core/infrastructure/xml)
  (:export
   ;; Classes
   #:endpoint
   #:indexed-endpoint
   ;; Slots
   #:binding
   #:location
   #:response-location
   #:index
   #:is-default
   ;; XML Build
   #:build-endpoint-xml
   ;; XML Parse
   #:parse-endpoint-xml))

(in-package :cl-saml-lib/src/core/domain/metadata/endpoint)

(defclass-std:defclass/std endpoint ()
  ((binding :type string)
   (location :type string)
   (response-location :type (or null string))))

(defclass-std:defclass/std indexed-endpoint (endpoint)
  ((index :type unsigned-byte :std 0)
   (is-default :type (member t nil) :std nil)))

;;; ============================================================================
;;; XML Building - Endpoint
;;; ============================================================================

(defmethod build-endpoint-xml ((this endpoint))
  "Build endpoint XML element."
  (xml:make-xml-element
   "Endpoint"
   :namespace namespaces:+saml-metadata-namespace+
   :attributes (append
                `(("Binding" ,(binding this))
                  ("Location" ,(location this)))
                (when (response-location this)
                  `(("ResponseLocation" ,(response-location this)))))))

(defmethod build-endpoint-xml ((this indexed-endpoint))
  "Build IndexedEndpoint XML element."
  (xml:make-xml-element
   "AssertionConsumerService"
   :namespace namespaces:+saml-metadata-namespace+
   :attributes (append
                `(("Binding" ,(binding this))
                  ("Location" ,(location this))
                  ("index" ,(princ-to-string (index this))))
                (when (is-default this)
                  `(("isDefault" "true")))
                (when (response-location this)
                  `(("ResponseLocation" ,(response-location this)))))))

;;; ============================================================================
;;; XML Parsing - Endpoint
;;; ============================================================================

(defmethod parse-endpoint-xml ((this xml:xml-element) class)
  "Parse Endpoint XML element.
   CLASS is the class to instantiate (endpoint or indexed-endpoint)."
  (let* ((binding (xml:xml-get-attribute this "Binding"))
         (location (xml:xml-get-attribute this "Location"))
         (response-location (xml:xml-get-attribute this "ResponseLocation"))
         (index-str (xml:xml-get-attribute this "index"))
         (is-default (string= (xml:xml-get-attribute this "isDefault") "true")))
    (if (and index-str (eq class 'indexed-endpoint))
        (make-instance 'indexed-endpoint
                       :binding binding
                       :location location
                       :response-location response-location
                       :index (if (and index-str (not (string-equal "" index-str)))
                                  (parse-integer index-str))
                       :is-default (when is-default t))
        (make-instance 'endpoint
                       :binding binding
                       :location location
                       :response-location response-location))))
