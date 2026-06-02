(defpackage :cl-saml-lib/src/core/domain/saml/saml-response
  (:use :cl)
  (:nicknames :saml-response)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/infrastructure/crypto-provider)
  (:import-from :cl-saml-lib/src/core/domain/saml/issuer)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-status)
  (:import-from :cl-saml-lib/src/core/domain/saml/saml-signature)
  (:import-from :cl-saml-lib/src/core/domain/saml/assertion)
  (:import-from :cl-saml-lib/src/core/domain/saml/namespaces)
  (:export
   #:saml-response
   ;; slots
   #:id
   #:issue-instant
   #:in-response-to
   #:destination
   #:issuer
   #:status
   #:signature
   #:assertions
   #:version

   #:make-saml-response
   #:build-response-xml
   #:parse-response-xml
   ))

(in-package :cl-saml-lib/src/core/domain/saml/saml-response)

(defclass saml-response ()
  ((id
    :initarg :id
    :initform (identifiers:generate-saml-id)
    :reader id
    :type string)
   (issue-instant
    :initarg :issue-instant
    :initform (time:current-time)
    :accessor issue-instant
    :type integer)
   (in-response-to
    :initarg :in-response-to
    :reader in-response-to
    :type (or null string)
    :initform nil)
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
   (status
    :initarg :status
    :reader status
    :type saml-status)
   (signature
    :initarg :signature
    :reader signature
    :type saml-signature)
   (assertions
    :initarg :assertions
    :reader assertions
    :type list
    :initform nil)
   (version
    :initarg :version
    :reader version
    :type string
    :initform "2.0"))
  (:documentation "SAML 2.0 Response containing assertions and status."))

(defun make-saml-response (status &key id issue-instant in-response-to
                           destination issuer assertions)
  "Create a new SAML Response."
  (make-instance 'saml-response
                 :id (or id (identifiers:generate-saml-id))
                 :issue-instant (or issue-instant (time:current-time))
                 :in-response-to in-response-to
                 :destination destination
                 :issuer issuer
                 :status status
                 :assertions (or assertions '())))

;;; Response XML Building

(defgeneric build-response-xml (response)
  (:documentation "Build the XML representation of a Response.
Does NOT include signature. Use SIGN-RESPONSE for signed responses.
Returns: xml-element"))

(defmethod build-response-xml ((resp saml-response))
  (let ((attrs `(("xmlns:samlp" #.namespaces:+saml-protocol-uri+)
                 ("xmlns:saml" #.namespaces:+saml-uri+)
                 ("ID" ,(id resp))
                 ("Version" ,(version resp))
                 ("IssueInstant"
                  ,(time:format-saml-time (issue-instant resp))))))
    (when (in-response-to resp)
      (push `("InResponseTo" ,(in-response-to resp)) attrs))
    (when (destination resp)
      (push `("Destination" ,(destination resp)) attrs))
    
    (let ((children (list (saml-status:build-status-xml (status resp)))))
      (when (issuer resp)
        (push (issuer:build-issuer-xml (issuer resp)) children))
      (dolist (assert (assertions resp))
        (push (assertion:build-assertion-xml assert) children))
      
      (xml:make-xml-element "samlp:Response"
                        :attributes attrs
                        :children (nreverse children)))))

;;; Response XML Parsing

(defgeneric parse-response-xml (element)
  (:documentation "Parse Response from XML element.
ELEMENT: xml-element
Returns: saml-response"))

(defmethod parse-response-xml ((element xml:xml-document))
  (parse-response-xml
   (xml:xml-find-element element "/samlp:Response | /saml2p:Response")))

(defmethod parse-response-xml ((element xml:xml-element))
  (let* ((id (xml:xml-get-attribute element "ID"))
         (version (xml:xml-get-attribute element "Version"))
         (issue-instant-str (xml:xml-get-attribute element "IssueInstant"))
         (issue-instant (when issue-instant-str
                          (time:parse-saml-time issue-instant-str)))
         (in-response-to (xml:xml-get-attribute element "InResponseTo"))
         (destination (xml:xml-get-attribute element "Destination"))
         (issuer-el (xml:xml-find-element element "saml:Issuer | saml2:Issuer"))
         (issuer (when issuer-el (issuer:parse-issuer-xml issuer-el)))
         (status-el (xml:xml-find-element element "samlp:Status | saml2p:Status"))
         (status (when status-el (saml-status:parse-status-xml status-el)))
         (signature-el (xml:xml-find-element element "ds:Signature"))
         (signature (when signature-el (saml-signature:parse-signature-xml signature-el)))
         (assertion-els (xml:xml-find-elements element "saml:Assertion | saml2:Assertion"))
         (assertions (mapcar #'assertion:parse-assertion-xml assertion-els)))
    (make-instance 'saml-response
                   :id id
                   :version (or version "2.0")
                   :issue-instant issue-instant
                   :in-response-to in-response-to
                   :destination destination
                   :issuer issuer
                   :status status
                   :signature signature
                   :assertions assertions)))

;;; Response to String

(defgeneric response-to-string (response)
  (:documentation "Serialize response to XML string.
Returns: string"))

(defmethod response-to-string ((resp saml-response))
  (let ((xml (build-response-xml resp)))
    (xml:serialize-xml xml)))
