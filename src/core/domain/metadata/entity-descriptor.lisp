(defpackage :cl-saml/src/core/domain/metadata/entity-descriptor
  (:use #:cl)
  (:nicknames :entity-descriptor)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml/src/core/infrastructure/time)
  (:import-from #:cl-saml/src/core/infrastructure/identifiers)
  (:import-from #:cl-saml/src/core/infrastructure/xml)
  (:import-from #:cl-saml/src/core/domain/metadata/organization)
  (:import-from #:cl-saml/src/core/domain/metadata/contact-person)
  (:import-from #:cl-saml/src/core/domain/metadata/key-descriptor)
  (:import-from #:cl-saml/src/core/domain/metadata/endpoint)
  (:import-from #:cl-saml/src/core/domain/metadata/sp-sso-descriptor)
  (:import-from #:cl-saml/src/core/domain/metadata/idp-sso-descriptor)
  (:import-from #:cl-saml/src/core/infrastructure/idp-config)
  (:import-from #:cl-saml/src/core/infrastructure/sp-config)
  (:export
   ;; Constants
   #:+saml-metadata-namespace-declaration+
   ;; Class
   #:entity-descriptor
   ;; Slots
   #:entity-id
   #:id
   #:idp-descriptor
   #:sp-sso-descriptor
   #:organization
   #:contact-persons
   #:valid-until
   #:cache-duration
   ;; Validation
   #:validate-entity-descriptor
   ;; XML Build
   #:build-entity-descriptor-xml
   #:build-metadata-xml
   ;; XML Parse
   #:parse-entity-descriptor-xml
   #:parse-metadata-xml
   #:generate-idp-metadata
   #:generate-idp-metadata-xml
   #:generate-sp-metadata
   #:generate-sp-metadata-xml))

(in-package :cl-saml/src/core/domain/metadata/entity-descriptor)

(defclass-std:defclass/std entity-descriptor ()
  ((entity-id :type string)
   (id :type (or null string))
   (valid-until :type (or null integer))
   (cache-duration :type (or null string))
   (idp-descriptor :type (or null idp-sso-descriptor:idp-sso-descriptor))
   (sp-sso-descriptor :type (or null sp-sso-descriptor:sp-sso-descriptor))
   (organization :type (or null organization:organization))
   (contact-persons :type list)))

;;; ============================================================================
;;; Validation
;;; ============================================================================

(defmethod validate-entity-descriptor (this)
  "Validate entity descriptor.
   Returns two values: T if valid, list of error messages if invalid."
  (let ((errors '()))
    (unless (entity-id this)
      (push "Entity ID is required" errors))
    (when (and (valid-until this)
               (< (valid-until this) (get-universal-time)))
      (push "ValidUntil is in the past" errors))
    (if (null errors)
        (values t nil)
        (values nil (nreverse errors)))))

;;; ============================================================================
;;; XML Building - Entity Descriptor
;;; ============================================================================

(defmethod build-entity-descriptor-xml ((this entity-descriptor))
  "Build EntityDescriptor XML element."
  (let ((attrs (append
                `(("entityID" ,(entity-id this)))
                (when (slot-boundp this 'id)
                  `(("ID" ,(entity-id this))))
                (when (valid-until this)
                  `(("validUntil" ,(time:format-saml-time (valid-until this)))))
                (when (cache-duration this)
                  `(("cacheDuration" ,(cache-duration this))))
                `(("xmlns:md" #.namespaces:+saml-metadata-uri+)
                  ("xmlns:ds" #.namespaces:+saml-signature-uri+)))))
    (xml:make-xml-element
     "EntityDescriptor"
     :namespace namespaces:+saml-metadata-namespace+
     :attributes attrs
     :children (append
                (when (idp-descriptor this)
                  (list (idp-sso-descriptor:build-idpsso-descriptor-xml (idp-descriptor this))))
                (when (sp-sso-descriptor this)
                  (list (sp-sso-descriptor:build-spsso-descriptor-xml (sp-sso-descriptor this))))
                (when (organization this)
                  (list (organization:build-organization-xml (organization this))))
                (loop for contact in (contact-persons this)
                      collect (contact-person:build-contact-person-xml contact))))))

(defmethod build-metadata-xml (this)
  "Build complete metadata XML from entity descriptor.
   Returns XML element suitable for serialization."
  (build-entity-descriptor-xml this))

;;; ============================================================================
;;; XML Parsing - Entity Descriptor
;;; ============================================================================

(defmethod parse-entity-descriptor-xml ((this xml:xml-document))
  (parse-entity-descriptor-xml (xml:xml-find-element this "/*")))

(defmethod parse-entity-descriptor-xml ((this xml:xml-element))
  "Parse EntityDescriptor XML element."
  (let* ((entity-id (xml:xml-get-attribute this "entityID"))
         (id (xml:xml-get-attribute this "ID"))
         (valid-until-str (xml:xml-get-attribute this "validUntil"))
         (cache-duration (xml:xml-get-attribute this "cacheDuration"))
         (idp-el (xml:xml-find-element this "md:IDPSSODescriptor"))
         (sp-el (xml:xml-find-element this "md:SPSSODescriptor"))
         (org-el (xml:xml-find-element this "md:Organization"))
         (contact-els (xml:xml-find-elements this "md:ContactPerson")))
    (make-instance 'entity-descriptor
                   :entity-id entity-id
                   :id id
                   :valid-until (when valid-until-str (time:parse-saml-time valid-until-str))
                   :cache-duration cache-duration
                   :idp-descriptor (when idp-el (idp-sso-descriptor:parse-idpsso-descriptor-xml idp-el))
                   :sp-sso-descriptor (when sp-el (sp-sso-descriptor:parse-spsso-descriptor-xml sp-el))
                   :organization (when org-el (organization:parse-organization-xml org-el))
                   :contact-persons (loop for el in contact-els
                                          collect (contact-person:parse-contact-person-xml el)))))

;;; ============================================================================
;;; IdP Config Integration
;;; ============================================================================

(defmethod generate-metadata ((config sp-config:sp-config))
  "Generate SP metadata from SP configuration."
  (let* ((entity-id (sp-config:entity-id config))
         (certificate (sp-config:sp-certificate config))
         (acs-url (sp-config:acs-url config))
         (slo-url (sp-config:slo-url config)))
    ;; Create ACS endpoint (AssertionConsumerService)
    (let* ((acs-endpoint (make-instance 'endpoint:indexed-endpoint
                                        :index 0
                                        :binding namespaces:+binding-http-post+
                                        :location acs-url
                                        :is-default t))
           ;; Create key descriptor from certificate
           (key-descriptor (make-instance 'key-descriptor:key-descriptor
                                          :key-use "signing"
                                          :key-certificate certificate))
           ;; Create SP SSO descriptor
           (sp-descriptor (make-instance 'sp-sso-descriptor:sp-sso-descriptor
                                         :protocol-support (list namespaces:+saml-protocol-uri+)
                                         :key-descriptors (list key-descriptor)
                                         :assertion-consumer-service (list acs-endpoint)
                                         :want-assertions-signed t))
           ;; Create entity descriptor
           (entity-desc (make-instance 'entity-descriptor
                                       :entity-id entity-id
                                       :sp-sso-descriptor sp-descriptor)))
      ;; Add SLO endpoint if provided
      (when slo-url
        (let ((slo-endpoint (make-instance 'endpoint:endpoint
                                          :binding namespaces:+binding-http-redirect+
                                          :location slo-url)))
          (setf (sp-sso-descriptor:single-logout-service sp-descriptor)
                (list slo-endpoint))))
      entity-desc)))

(defmethod generate-metadata ((config idp-config:idp-config))
  "Generate IDP metadata from IDP configuration."
  (let* ((entity-id (idp-config:entity-id config))
         (certificate (idp-config:idp-certificate config))
         (sso-url (idp-config:sso-url config))
         (slo-url (idp-config:slo-url config))

         ;; Create SSO endpoint using HTTP-POST binding constant
         (sso-endpoint (make-instance 'endpoint:endpoint
                                      :binding namespaces:+binding-http-post+
                                      :location sso-url))

         ;; Create key descriptor from certificate
         (key-descriptor (make-instance 'key-descriptor:key-descriptor
                                        :key-use "signing"
                                        :key-certificate certificate))

         ;; Create IDP SSO descriptor with protocol support constant
         (idp-descriptor (make-instance 'idp-sso-descriptor:idp-sso-descriptor
                                        :protocol-support (list namespaces:+saml-protocol-uri+)
                                        :key-descriptors (list key-descriptor)
                                        :single-sign-on-service (list sso-endpoint)
                                        :want-authn-requests-signed nil)))
    (setf (idp-sso-descriptor:single-sign-on-service idp-descriptor)
          (list sso-endpoint))

    ;; Add SLO endpoint if provided (also using HTTP-POST binding)
    (when slo-url
      (let ((slo-endpoint (make-instance 'endpoint:endpoint
                                         :binding namespaces:+binding-http-post+
                                         :location slo-url)))
        (setf (idp-sso-descriptor:single-logout-service idp-descriptor)
              (list slo-endpoint))))

    ;; Create entity descriptor
    (let ((entity-desc (make-instance 'entity-descriptor
                                      :entity-id entity-id
                                      :idp-descriptor idp-descriptor)))

      entity-desc)))

(defmethod generate-idp-metadata-xml (config)
  "Generate IDP metadata XML from idp-config.
   Returns XML string suitable for response."
  (let ((entity (generate-metadata config)))
    (when entity
      (build-metadata-xml entity))))

(defmethod generate-sp-metadata-xml (config)
  "Generate SP metadata XML from sp-config.
   Returns XML string suitable for response."
  (let ((entity (generate-metadata config)))
    (when entity
      (build-metadata-xml entity))))
