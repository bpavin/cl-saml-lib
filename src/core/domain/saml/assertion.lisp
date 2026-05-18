(defpackage :cl-saml-lib/src/core/domain/saml/assertion
  (:use :cl)
  (:nicknames :assertion)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/saml/issuer)
  (:import-from :cl-saml-lib/src/core/domain/saml/subject)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-conditions)
  (:import-from :cl-saml-lib/src/core/domain/saml/authn-statement)
  (:import-from :cl-saml-lib/src/core/domain/saml/attributes)
  (:export
   #:assertion
   ;; slots
   #:id
   #:issue-instant
   #:signature
   #:issuer
   #:subject
   #:conditions
   #:attribute-statement
   #:authn-statement
   #:version

   #:make-assertion
   #:build-assertion-xml
   #:parse-assertion-xml
   #:parse-authnstatement-xml
   #:parse-authncontext-xml))

(in-package :cl-saml-lib/src/core/domain/saml/assertion)

;;; Assertion Structure

(defclass assertion ()
  ((id
    :initarg :id
    :reader id
    :initform (identifiers:generate-saml-id)
    :type string
    :documentation "Unique identifier for this assertion")
   (issue-instant
    :initarg :issue-instant
    :reader issue-instant
    :initform (time:current-time)
    :type integer
    :documentation "When the assertion was issued")
   (signature
    :initarg :signature
    :reader signature)
   (issuer
    :initarg :issuer
    :reader issuer
    :type issuer
    :documentation "Entity that issued this assertion")
   (subject
    :initarg :subject
    :reader subject
    :type subject
    :documentation "Subject of the assertion")
   (conditions
    :initarg :conditions
    :reader conditions
    :type (or null conditions)
    :initform nil
    :documentation "Conditions governing assertion validity")
   (attribute-statement
    :initarg :attribute-statement
    :reader attribute-statement
    :type (or null attribute-statement)
    :initform nil
    :documentation "Statement containing attributes")
   (authn-statement
    :initarg :authn-statement
    :reader authn-statement
    :type (or null authn-statement)
    :initform nil
    :documentation "Authentication statement")
   (version
    :initarg :version
    :reader version
    :type string
    :initform "2.0"
    :documentation "SAML version (always 2.0)"))
  (:documentation "SAML 2.0 Assertion containing claims about a subject."))

(defun make-assertion (issuer subject &key id issue-instant conditions
                       attribute-statement authn-statement)
  "Create a new Assertion."
  (make-instance 'assertion
                 :id (or id (identifiers:generate-saml-id))
                 :issue-instant (or issue-instant (time:current-time))
                 :issuer issuer
                 :subject subject
                 :conditions conditions
                 :attribute-statement attribute-statement
                 :authn-statement authn-statement))

;;; Assertion XML Building

(defgeneric build-assertion-xml (assertion)
  (:documentation "Build the XML representation of an Assertion.
Does NOT include signature. Use SIGN-ASSERTION for signed assertions.
Returns: xml-element"))

(defmethod build-assertion-xml ((assert assertion))
  (let ((children (list 
                    (issuer:build-issuer-xml (issuer assert))
                    (subject:build-subject-xml (subject assert)))))
    (when (conditions assert)
      (push (saml-conditions:build-conditions-xml (conditions assert)) children))
    (when (authn-statement assert)
      (push (authn-statement:build-authnstatement-xml (authn-statement assert)) children))
    (when (attribute-statement assert)
      (push (attributes:build-attributestatement-xml (attribute-statement assert)) children))
    
    (xml:make-xml-element "saml:Assertion"
                          :attributes `(("ID" ,(id assert))
                                        ("Version" ,(version assert))
                                        ,(when (issue-instant assert)
                                           `("IssueInstant" ,(time:format-saml-time (issue-instant assert)))))
                      :children (nreverse children))))

;;; Assertion Signing

(defgeneric sign-assertion (assertion private-key &key algorithm)
  (:documentation "Sign an assertion.
ASSERTION: assertion object
PRIVATE-KEY: private key for signing
ALGORITHM: signature algorithm
Returns: signed xml-element with Signature child")
  (:method ((assert assertion) private-key 
           &key (algorithm crypto-provider:+signature-rsa-sha256+))
    (declare (ignorable private-key algorithm))
    (error 'saml-error :message "sign-assertion: Must specialize for crypto implementation")))

;;; Assertion XML Parsing

(defgeneric parse-assertion-xml (element)
  (:documentation "Parse Assertion from XML element.
ELEMENT: xml-element
Returns: assertion"))

(defmethod parse-assertion-xml ((element xml:xml-element))
  (let* ((id (xml:xml-get-attribute element "ID"))
         (version (xml:xml-get-attribute element "Version"))
         (issue-instant-str (xml:xml-get-attribute element "IssueInstant"))
         (issue-instant (when issue-instant-str
                          (time:parse-saml-time issue-instant-str)))
         (signature-el (xml:xml-find-element element "ds:Signature"))
         (signature (when signature-el (saml-signature:parse-signature-xml signature-el)))
         (issuer-el (xml:xml-find-element element "saml:Issuer | saml2:Issuer"))
         (issuer (when issuer-el (issuer:parse-issuer-xml issuer-el)))
         (subject-el (xml:xml-find-element element "saml:Subject | saml2:Subject"))
         (subject (when subject-el (subject:parse-subject-xml subject-el)))
         (conditions-el (xml:xml-find-element element "saml:Conditions | saml2:Conditions"))
         (conditions (when conditions-el (saml-conditions:parse-conditions-xml conditions-el)))
         (attr-el (xml:xml-find-element element "saml:AttributeStatement | saml2:AttributeStatement"))
         (attr-stmt (when attr-el (attributes:parse-attributestatement-xml attr-el)))
         (authn-el (xml:xml-find-element element "saml:AuthnStatement | saml2:AuthnStatement"))
         (authn-stmt (when authn-el (parse-authnstatement-xml authn-el))))
    (make-instance 'assertion
                   :id id
                   :version (or version "2.0")
                   :issue-instant issue-instant
                   :signature signature
                   :issuer issuer
                   :subject subject
                   :conditions conditions
                   :attribute-statement attr-stmt
                   :authn-statement authn-stmt)))

(defgeneric parse-authnstatement-xml (element)
  (:documentation "Parse AuthnStatement from XML element.
ELEMENT: xml-element
Returns: authn-statement"))

(defmethod parse-authnstatement-xml ((element xml:xml-element))
  (let* ((authn-instant-str (xml:xml-get-attribute element "AuthnInstant"))
         (authn-instant (when authn-instant-str
                          (time:parse-saml-time authn-instant-str)))
         (session-index (xml:xml-get-attribute element "SessionIndex"))
         (session-not-on-or-after-str (xml:xml-get-attribute
                                       element "SessionNotOnOrAfter"))
         (session-not-on-or-after (when session-not-on-or-after-str
                                     (time:parse-saml-time session-not-on-or-after-str)))
         (context-el (xml:xml-find-element element "saml:AuthnContext | saml2:AuthnContext"))
         (context (when context-el (parse-authncontext-xml context-el))))
    (authn-statement:make-authn-statement authn-instant context
                          :session-index session-index
                          :session-not-on-or-after session-not-on-or-after)))

(defgeneric parse-authncontext-xml (element)
  (:documentation "Parse AuthnContext from XML element.
ELEMENT: xml-element
Returns: authn-context"))

(defmethod parse-authncontext-xml ((element xml:xml-element))
  (let* ((class-ref-el (xml:xml-find-element element "saml:AuthnContextClassRef | saml2:AuthnContextClassRef"))
         (class-ref (when class-ref-el
                      (xml:xml-element-text-content class-ref-el))))
    (authn-statement:make-authn-context class-ref)))

;;; Assertion to String

(defgeneric to-string (assertion)
  (:documentation "Serialize assertion to XML string.
Returns: string"))

(defmethod to-string ((assert assertion))
  (let ((xml (build-assertion-xml assert)))
    (xml:serialize-xml xml)))
