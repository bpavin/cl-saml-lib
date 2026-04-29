(defpackage :cl-saml/src/core/domain/metadata/idp-sso-descriptor
  (:use #:cl)
  (:nicknames :idp-sso-descriptor)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml/src/core/infrastructure/xml)
  (:import-from #:cl-saml/src/core/domain/metadata/role-descriptor)
  (:import-from #:cl-saml/src/core/domain/metadata/organization)
  (:import-from #:cl-saml/src/core/domain/metadata/key-descriptor)
  (:import-from #:cl-saml/src/core/domain/metadata/contact-person)
  (:import-from #:cl-saml/src/core/domain/metadata/endpoint)
  (:export
   ;; Class
   #:idp-sso-descriptor
   ;; Slots
   #:want-authn-requests-signed
   #:single-sign-on-service
   #:single-logout-service
   #:name-id-format
   #:protocol-support
   #:key-descriptors
   #:organization
   #:contact-persons
   ;; Validation
   #:validate-idp-sso-descriptor
   ;; XML Build
   #:build-idpsso-descriptor-xml
   ;; XML Parse
   #:parse-idpsso-descriptor-xml))

(in-package :cl-saml/src/core/domain/metadata/idp-sso-descriptor)

(defclass-std:defclass/std idp-sso-descriptor (role-descriptor:role-descriptor)
  ((want-authn-requests-signed :type (member t nil) :std nil)
   (single-sign-on-service :type list :std nil)
   (single-logout-service :type list :std nil)
   (name-id-format :type list :std (list namespaces:+nameid-format-unspecified+))))

;;; ============================================================================
;;; Validation
;;; ============================================================================

(defmethod validate-idp-sso-descriptor (this)
  "Validate IdP SSO descriptor.
   Returns two values: T if valid, list of error messages if invalid."
  (let ((errors '()))
    (dolist (sso (single-sign-on-service this))
      (unless (and (endpoint:binding sso) (endpoint:location sso))
        (push "SingleSignOnService requires Binding and Location" errors)
        (return)))
    (if (null errors)
        (values t nil)
        (values nil (nreverse errors)))))

;;; ============================================================================
;;; XML Building - IdP SSO Descriptor
;;; ============================================================================

(defmethod build-idpsso-descriptor-xml ((this idp-sso-descriptor))
  "Build IDPSSODescriptor XML element."
  (let* ((ns-decl namespaces:+saml-metadata-namespace+)
         (attrs `(("WantAuthnRequestsSigned"
                   ,(if (want-authn-requests-signed this) "true" "false"))
                  ("protocolSupportEnumeration" ,namespaces:+saml-protocol-uri+)))
         (key-descriptor (loop for kd in (role-descriptor:key-descriptors this)
                               collect (key-descriptor:build-key-descriptor-xml kd)))
         (name-id (loop for fmt in (name-id-format this)
                        collect (xml:make-xml-element
                                 "NameIDFormat"
                                 :namespace ns-decl
                                 :children (list fmt))))
         (sso-service (loop for sso in (single-sign-on-service this)
                            collect (xml:make-xml-element
                                     "SingleSignOnService"
                                     :namespace ns-decl
                                     :attributes (append
                                                  `(("Binding" ,(endpoint:binding sso))
                                                    ("Location" ,(endpoint:location sso)))
                                                  (when (endpoint:response-location sso)
                                                    `(("ResponseLocation" ,(endpoint:response-location sso))))))))
         (slo-service (loop for slo in (single-logout-service this)
                            collect (xml:make-xml-element
                                     "SingleLogoutService"
                                     :namespace ns-decl
                                     :attributes (append
                                                  `(("Binding" ,(endpoint:binding slo))
                                                    ("Location" ,(endpoint:location slo)))
                                                  (when (endpoint:response-location slo)
                                                    `(("ResponseLocation" ,(endpoint:response-location slo))))))))
         (organization (when (role-descriptor:organization this)
                         (list (organization:build-organization-xml (role-descriptor:organization this)))))
         (contact (loop for contact in (role-descriptor:contact-persons this)
                        collect (contact-person:build-contact-person-xml contact))))
    (xml:make-xml-element
     "IDPSSODescriptor"
     :namespace ns-decl
     :attributes attrs
     :children (append
                key-descriptor
                name-id
                sso-service
                slo-service
                organization
                contact))))

;;; ============================================================================
;;; XML Parsing - IdP SSO Descriptor
;;; ============================================================================

(defmethod parse-idpsso-descriptor-xml ((this xml:xml-element))
  "Parse IDPSSODescriptor XML element."
  (let* ((want-authn-signed (string= (xml:xml-get-attribute this "WantAuthnRequestsSigned") "true"))
         (name-id-els (xml:xml-find-elements this "NameIDFormat"))
         (sso-els (xml:xml-find-elements this "md:SingleSignOnService"))
         (slo-els (xml:xml-find-elements this "md:SingleLogoutService"))
         (key-els (xml:xml-find-elements this "md:KeyDescriptor"))
         (org-el (xml:xml-find-element this "md:Organization"))
         (contact-els (xml:xml-find-elements this "md:ContactPerson")))
    (make-instance 'idp-sso-descriptor
                   :want-authn-requests-signed (when want-authn-signed t)
                   :name-id-format (loop for el in name-id-els
                                          collect (xml:xml-element-text-content el))
                   :single-sign-on-service (loop for el in sso-els
                                                collect (endpoint:parse-endpoint-xml el 'endpoint:endpoint))
                   :single-logout-service (loop for el in slo-els
                                                collect (endpoint:parse-endpoint-xml el 'endpoint:endpoint))
                   :key-descriptors (loop for el in key-els
                                           collect (key-descriptor:parse-key-descriptor-xml el))
                   :organization (when org-el (organization:parse-organization-xml org-el))
                   :contact-persons (loop for el in contact-els
                                          collect (contact-person:parse-contact-person-xml el)))))
