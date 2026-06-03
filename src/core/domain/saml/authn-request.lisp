(defpackage :cl-saml-lib/src/core/domain/saml/authn-request
  (:use :cl)
  (:nicknames :authn-request)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/domain/saml/issuer)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-conditions)
  (:import-from :cl-saml-lib/src/core/domain/saml/namespaces)
  (:import-from :cl-saml-lib/src/core/infrastructure/sp-config)
  (:export
   #:name-id-policy
   #:make-name-id-policy
   ;; class
   #:authn-request
   ;; authn-request slots
   #:id
   #:issue-instant
   #:version
   #:destination
   #:issuer
   #:protocol-binding
   #:force-authn
   #:passive
   #:provider-name
   #:relay-state
   #:scoping
   #:conditions

   #:make-authn-request
   #:parse-authn-request
   #:parse-nameidpolicy-xml
   #:validate-authn-request
   #:authn-request-to-string
   #:assertion-consumer-service-url
   #:generate-authn-request-xml
   #:generate-authn-request-from-config
   #:build-authn-request-xml
   ))

(in-package :cl-saml-lib/src/core/domain/saml/authn-request)

;;; NameIDPolicy Structure

(defclass name-id-policy ()
  ((policy-format
    :initarg :policy-format
    :reader policy-format
    :type (or null string)
    :initform nil)
   (sp-name-qualifier
    :initarg :sp-name-qualifier
    :reader sp-qualifier
    :type (or null string)
    :initform nil)
   (allow-create
    :initarg :allow-create
    :reader allow-create
    :type boolean
    :initform nil))
  (:documentation "Policy for NameID format to use in response."))

(defun make-name-id-policy (&key policy-format sp-name-qualifier allow-create)
  "Create a NameIDPolicy."
  (make-instance 'name-id-policy
                 :policy-format policy-format
                 :sp-name-qualifier sp-name-qualifier
                 :allow-create allow-create))

;;; AuthnRequest Structure

(defclass authn-request ()
  ((id
    :initarg :id
    :reader id
    :type string)
   (issue-instant
    :initarg :issue-instant
    :reader issue-instant
    :type integer)
   (version
    :initarg :version
    :reader version
    :type string)
   (destination
    :initarg :destination
    :reader destination
    :type (or null string)
    :initform nil)
   (issuer
    :initarg :issuer
    :reader issuer
    :type (or null issuer)
    :initform nil)
   (assertion-consumer-service-url
    :initarg :assertion-consumer-service-url
    :reader assertion-consumer-service-url
    :type (or null string)
    :initform nil)
   (protocol-binding
    :initarg :protocol-binding
    :reader protocol-binding
    :type (or null string)
    :initform nil)
   (name-id-policy
    :initarg :name-id-policy
    :reader name-id-policy
    :type (or null name-id-policy)
    :initform nil)
   (force-authn
    :initarg :force-authn
    :reader force-authn
    :type boolean
    :initform nil)
   (passive
    :initarg :passive
    :reader passive
    :type boolean
    :initform nil)
   (provider-name
    :initarg :provider-name
    :reader provider-name
    :type (or null string)
    :initform nil)
   (relay-state
    :initarg :relay-state
    :reader relay-state
    :type (or null string)
    :initform nil)
   (scoping
    :initarg :scoping
    :reader scoping
    :type (or null list)
    :initform nil)
   (conditions
    :initarg :conditions
    :reader conditions
    :type (or null conditions)
    :initform nil))
  (:documentation "SAML 2.0 Authentication Request."))

(defun make-authn-request (&key id issue-instant version destination
                         assertion-consumer-service-url protocol-binding
                         name-id-policy force-authn passive provider-name
                         issuer relay-state)
  "Create a new AuthnRequest (usually from parsing)."
  (make-instance 'authn-request
                 :id id
                 :issue-instant issue-instant
                 :version version
                 :destination destination
                 :assertion-consumer-service-url assertion-consumer-service-url
                 :protocol-binding protocol-binding
                 :name-id-policy name-id-policy
                 :force-authn force-authn
                 :passive passive
                 :provider-name provider-name
                 :issuer issuer
                 :relay-state relay-state))

;;; AuthnRequest XML Parsing

(defgeneric parse-authn-request (xml-string-or-element)
  (:documentation "Parse AuthnRequest from XML string or element.
Returns: authn-request"))

(defmethod parse-authn-request ((element xml:xml-document))
  (parse-authn-request
   (xml:xml-find-element element "/samlp:AuthnRequest")))

(defmethod parse-authn-request ((element xml:xml-element))
  (let* ((id (xml:xml-get-attribute element "ID"))
         (version (xml:xml-get-attribute element "Version"))
         (issue-instant-str (xml:xml-get-attribute element "IssueInstant"))
         (issue-instant (when issue-instant-str
                          (time:parse-saml-time issue-instant-str)))
         (destination (xml:xml-get-attribute element "Destination"))
         (assertion-consumer-service-url (xml:xml-get-attribute 
                                          element "AssertionConsumerServiceURL"))
         (protocol-binding (xml:xml-get-attribute element "ProtocolBinding"))
         (force-authn-str (xml:xml-get-attribute element "ForceAuthn"))
         (force-authn (when force-authn-str
                        (string= (string-upcase force-authn-str) "TRUE")))
         (passive-str (xml:xml-get-attribute element "IsPassive"))
         (passive (when passive-str
                    (string= (string-upcase passive-str) "TRUE")))
         (provider-name (xml:xml-get-attribute element "ProviderName"))
         (issuer-el (xml:xml-find-element element "saml:Issuer | saml2:Issuer"))
         (issuer (when issuer-el (issuer:parse-issuer-xml issuer-el)))
         (name-id-policy-el (xml:xml-find-element element "saml:NameIDPolicy | saml2p:NameIDPolicy"))
         (name-id-policy (when name-id-policy-el 
                           (parse-nameidpolicy-xml name-id-policy-el)))
         (conditions-el (xml:xml-find-element element "saml:Conditions | saml2:Conditions"))
         (conditions (when conditions-el (saml-conditions:parse-conditions-xml conditions-el))))
    (make-instance 'authn-request
                   :id id
                   :issue-instant issue-instant
                   :version version
                   :destination destination
                   :assertion-consumer-service-url assertion-consumer-service-url
                   :protocol-binding protocol-binding
                   :force-authn force-authn
                   :passive passive
                   :provider-name provider-name
                   :issuer issuer
                   :name-id-policy name-id-policy
                   :conditions conditions)))

(defun parse-nameidpolicy-xml (element)
  "Parse NameIDPolicy from XML element."
  (let* ((policy-format (xml:xml-get-attribute element "Format"))
         (sp-name-qualifier (xml:xml-get-attribute element "SPNameQualifier"))
         (allow-create-str (xml:xml-get-attribute element "AllowCreate"))
         (allow-create (when allow-create-str
                         (string= (string-upcase allow-create-str) "TRUE"))))
    (make-name-id-policy
     :policy-format policy-format
     :sp-name-qualifier sp-name-qualifier
     :allow-create allow-create)))

(defun build-nameidpolicy-xml (policy)
  "Build XML element for NameIDPolicy."
  (let ((attrs '()))
    (when (policy-format policy)
      (push `("Format" ,(policy-format policy)) attrs))
    (when (sp-qualifier policy)
      (push `("SPNameQualifier" ,(sp-qualifier policy)) attrs))
    (when (allow-create policy)
      (push `("AllowCreate" "true") attrs))
    (xml:make-xml-element "samlp:NameIDPolicy" 
                          :namespace namespaces:+saml-protocol-uri+
                          :attributes (nreverse attrs))))

(defun build-scoping-xml (scope)
  "Build XML element for scoping (placeholder implementation)."
  (declare (ignore scope))
  (xml:make-xml-element "samlp:Scoping"))

;;; AuthnRequest Validation

(defgeneric validate-authn-request (request &key current-time)
  (:documentation "Validate an AuthnRequest.
CURRENT-TIME: timestamp to check against
Returns: (values valid-p error-message)")
  (:method ((req authn-request) &key (current-time (time:current-time)))
    (declare (ignorable current-time))
    ;; Basic validation - subclasses can add more
    (unless (id req)
      (return-from validate-authn-request
        (values nil "Missing ID")))
    (unless (string= (version req) "2.0")
      (return-from validate-authn-request
        (values nil "Unsupported SAML version")))
    (values t nil)))

;;; AuthnRequest to String (for debugging)

(defgeneric authn-request-to-string (request)
  (:documentation "Serialize AuthnRequest to XML string.")
  (:method ((req authn-request))
    (xml:serialize-xml req)))

(defmethod generate-authn-request-xml (config)
  "Generate AuthnRequest XML from sp-config.
   Returns XML element suitable for SAML request."
  (let ((authn-request (generate-authn-request-from-config config)))
    (when authn-request
      (build-authn-request-xml authn-request))))

(defmethod generate-authn-request-from-config ((config sp-config:sp-config))
  "Generate AuthnRequest domain object from SP configuration."
  (let* ((entity-id (sp-config:entity-id config))
         (acs-url (sp-config:acs-url config))
         (slo-url (sp-config:slo-url config))
         ;; Generate request ID and current time
         (request-id (identifiers:generate-saml-id))
         (issue-instant (time:current-time))
         ;; Create authn-request with required fields
         (authn-req (make-authn-request
                     :id request-id
                     :issue-instant issue-instant
                     :version "2.0"
                     :issuer (issuer:make-issuer entity-id)
                     :destination acs-url
                     :assertion-consumer-service-url acs-url)))
    ;; Add optional SLO URL if provided
    (when slo-url
      (setf (slot-value authn-req 'destination) slo-url))
    
    authn-req))

(defmethod build-authn-request-xml ((this authn-request))
  "Build AuthnRequest XML element."
  (let ((attrs (append
                `(("xmlns:samlp" #.namespaces:+saml-protocol-uri+)
                  ("xmlns:saml" #.namespaces:+saml-uri+)
                  ("ID" ,(id this))
                  ("Version" ,(version this))
                  ("IssueInstant" ,(time:format-saml-time (issue-instant this))))
                (when (destination this)
                  `(("Destination" ,(destination this))))
                (when (assertion-consumer-service-url this)
                  `(("AssertionConsumerServiceURL" ,(assertion-consumer-service-url this))))
                (when (protocol-binding this)
                  `(("ProtocolBinding" ,(protocol-binding this))))
                (when (force-authn this)
                  `(("ForceAuthn" "true")))
                (when (passive this)
                  `(("IsPassive" "true")))
                (when (provider-name this)
                  `(("ProviderName" ,(provider-name this))))
                (when (relay-state this)
                  `(("RelayState" ,(relay-state this)))))))
    (xml:make-xml-element
     "AuthnRequest"
     :namespace namespaces:+saml-protocol-namespace+
     :attributes attrs
     :children (append
                (when (issuer this)
                  (list (issuer:build-issuer-xml (issuer this))))
                (when (name-id-policy this)
                  (list (build-nameidpolicy-xml (name-id-policy this))))
                (when (conditions this)
                  (list (saml-conditions:build-conditions-xml (conditions this))))
                (when (scoping this)
                  (loop for scope in (scoping this)
                        collect (build-scoping-xml scope)))))))
