(defpackage :cl-saml/src/core/domain/saml/name-id
  (:use :cl)
  (:nicknames :name-id)
  (:import-from :cl-saml/src/core/infrastructure/identifiers)
  (:import-from :cl-saml/src/core/infrastructure/time)
  (:import-from :cl-saml/src/core/infrastructure/xml)
  (:import-from :cl-saml/src/core/domain/saml/namespaces)
  (:export
   #:name-id
   ;; slots
   #:name-id-value
   #:name-id-format
   #:name-id-name-qualifier
   #:name-id-sp-name-qualifier

   #:make-name-id
   #:build-nameid-xml
   #:parse-nameid-xml))

(in-package :cl-saml/src/core/domain/saml/name-id)

;;; NameID Structure

(defclass name-id ()
  ((value
    :initarg :value
    :reader name-id-value
    :type string)
   (format
    :initarg :format
    :reader name-id-format
    :type (or null string)
    :initform nil)
   (name-qualifier
    :initarg :name-qualifier
    :reader name-id-name-qualifier
    :type (or null string)
    :initform nil)
   (sp-name-qualifier
    :initarg :sp-name-qualifier
    :reader name-id-sp-name-qualifier
    :type (or null string)
    :initform nil))
  (:documentation "SAML NameID represents an identity."))

(defun make-name-id (value &key format name-qualifier sp-name-qualifier)
  "Create a new NameID."
  (make-instance 'name-id
                 :value (string value)
                 :format format
                 :name-qualifier name-qualifier
                 :sp-name-qualifier sp-name-qualifier))

;;; NameID XML Generation

(defgeneric build-nameid-xml (name-id)
  (:documentation "Build XML element for NameID.
Returns: xml-element"))

(defmethod build-nameid-xml ((name-id name-id))
  (let* ((value (name-id-value name-id))
         (format (name-id-format name-id))
         (nq (name-id-name-qualifier name-id))
         (spnq (name-id-sp-name-qualifier name-id)))
    (xml:make-xml-element "saml:NameID"
                          :attributes (append
                                       (when format `(("Format" ,format)))
                                       (when nq `(("NameQualifier" ,nq)))
                                       (when spnq `(("SPNameQualifier" ,spnq))))
                          :children (list value))))

;;; NameID XML Parsing

(defgeneric parse-nameid-xml (element)
  (:documentation "Parse NameID from XML element.
ELEMENT: xml-element
Returns: name-id"))

(defmethod parse-nameid-xml ((element xml:xml-element))
  (let ((value (xml:xml-element-text-content element))
        (format (xml:xml-get-attribute element "Format"))
        (nq (xml:xml-get-attribute element "NameQualifier"))
        (spnq (xml:xml-get-attribute element "SPNameQualifier")))
    (make-name-id value
                  :format format
                  :name-qualifier nq
                  :sp-name-qualifier spnq)))

;;; NameID Equality

(defmethod print-object ((name-id name-id) stream)
  (print-unreadable-object (name-id stream :type t)
    (format stream "~A~@[:~A~]"
            (name-id-value name-id)
            (name-id-format name-id))))

;;; Utility

(defun email-name-id (email &key name-qualifier sp-name-qualifier)
  "Create an email-format NameID."
  (make-name-id email
                :format namespaces:+nameid-format-email+
                :name-qualifier name-qualifier
                :sp-name-qualifier sp-name-qualifier))

(defun persistent-name-id (identifier &key name-qualifier sp-name-qualifier)
  "Create a persistent-format NameID."
  (make-name-id identifier
                :format namespaces:+nameid-format-persistent+
                :name-qualifier name-qualifier
                :sp-name-qualifier sp-name-qualifier))

(defun transient-name-id (identifier &key name-qualifier)
  "Create a transient-format NameID."
  (make-name-id identifier
                :format namespaces:+nameid-format-transient+
                :name-qualifier name-qualifier))
