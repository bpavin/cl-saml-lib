(defpackage :cl-saml-lib/src/core/domain/metadata/sp-sso-descriptor
  (:use #:cl)
  (:nicknames :sp-sso-descriptor)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml-lib/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml-lib/src/core/infrastructure/xml)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/role-descriptor)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/organization)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/key-descriptor)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/contact-person)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/endpoint)
  (:export
   ;; Class
   #:sp-sso-descriptor
   ;; Slots
   #:authn-requests-signed
   #:want-assertions-signed
   #:assertion-consumer-service
   #:single-logout-service
   #:attribute-consuming-service
   ;; Validation
   #:validate-sp-sso-descriptor
   ;; XML Build
   #:build-spsso-descriptor-xml
   ;; XML Parse
   #:parse-spsso-descriptor-xml))

(in-package :cl-saml-lib/src/core/domain/metadata/sp-sso-descriptor)

(defclass-std:defclass/std sp-sso-descriptor (role-descriptor:role-descriptor)
  ((authn-requests-signed :type (member t nil) :std nil)
   (want-assertions-signed :type (member t nil) :std nil)
   (assertion-consumer-service :type list :std nil)
   (single-logout-service :type list :std nil)
   (attribute-consuming-service :type list :std nil)))

;;; ============================================================================
;;; Validation
;;; ============================================================================

(defmethod validate-sp-sso-descriptor (this)
  "Validate SP SSO descriptor.
   Returns two values: T if valid, list of error messages if invalid."
  (let ((errors '()))
    (dolist (acs (assertion-consumer-service this))
      (unless (and (endpoint:binding acs) (endpoint:location acs))
        (push "AssertionConsumerService requires Binding and Location" errors)
        (return)))
    (if (null errors)
        (values t nil)
        (values nil (nreverse errors)))))

;;; ============================================================================
;;; XML Building - SP SSO Descriptor
;;; ============================================================================

(defmethod build-spsso-descriptor-xml ((this sp-sso-descriptor))
  "Build SPSSODescriptor XML element."
  (let* ((ns-decl namespaces:+saml-metadata-namespace+)
         (attrs (append
                 (when (authn-requests-signed this)
                   `(("AuthnRequestsSigned" "true")))
                 `(("WantAssertionsSigned"
                    ,(if (want-assertions-signed this) "true" "false"))))))
    (xml:make-xml-element
     "SPSSODescriptor"
     :namespace ns-decl
     :attributes attrs
     :children (append
                (list (xml:make-xml-element
                       "protocolSupportEnumeration"
                       :namespace ns-decl
                       :children (list namespaces:+saml-protocol-uri+)))
                (loop for kd in (role-descriptor:key-descriptors this)
                      collect (key-descriptor:build-key-descriptor-xml kd))
                (loop for acs in (assertion-consumer-service this)
                      collect (endpoint:build-endpoint-xml acs))
                (loop for slo in (single-logout-service this)
                      collect (xml:make-xml-element
                               "SingleLogoutService"
                               :namespace ns-decl
                               :attributes (append
                                            `(("Binding" ,(endpoint:binding slo))
                                              ("Location" ,(endpoint:location slo)))
                                            (when (endpoint:response-location slo)
                                              `(("ResponseLocation" ,(endpoint:response-location slo)))))))
                (when (role-descriptor:organization this)
                  (list (organization:build-organization-xml (role-descriptor:organization this))))
                (loop for contact in (role-descriptor:contact-persons this)
                      collect (contact-person:build-contact-person-xml contact))))))

;;; ============================================================================
;;; XML Parsing - SP SSO Descriptor
;;; ============================================================================

(defmethod parse-spsso-descriptor-xml ((this xml:xml-element))
  "Parse SPSSODescriptor XML element."
  (let* ((authn-req-signed (string= (xml:xml-get-attribute this "AuthnRequestsSigned") "true"))
         (want-assertions-signed (string= (xml:xml-get-attribute this "WantAssertionsSigned") "true"))
         (acs-els (xml:xml-find-elements this "md:AssertionConsumerService"))
         (slo-els (xml:xml-find-elements this "md:SingleLogoutService"))
         (key-els (xml:xml-find-elements this "md:KeyDescriptor"))
         (org-el (xml:xml-find-element this "md:Organization"))
         (contact-els (xml:xml-find-elements this "md:ContactPerson")))
    (make-instance 'sp-sso-descriptor
                   :authn-requests-signed (when authn-req-signed t)
                   :want-assertions-signed (when want-assertions-signed t)
                   :assertion-consumer-service (loop for el in acs-els
                                                      collect (endpoint:parse-endpoint-xml el 'endpoint:indexed-endpoint))
                   :single-logout-service (loop for el in slo-els
                                                collect (endpoint:parse-endpoint-xml el 'endpoint:endpoint))
                   :key-descriptors (loop for el in key-els
                                           collect (key-descriptor:parse-key-descriptor-xml el))
                   :organization (when org-el (organization:parse-organization-xml org-el))
                   :contact-persons (loop for el in contact-els
                                          collect (contact-person:parse-contact-person-xml el)))))
