(defpackage :cl-saml/src/core/domain/saml/issuer
  (:use :cl)
  (:nicknames :issuer)
  (:import-from :cl-saml/src/core/infrastructure/identifiers)
  (:import-from :cl-saml/src/core/infrastructure/time)
  (:import-from :cl-saml/src/core/infrastructure/xml)
  (:import-from :cl-saml/src/core/domain/saml/namespaces)
(:export
   #:issuer
   ;; slots
   #:issuer-value
   #:issuer-format
   #:issuer-qualifier

   #:make-issuer
   #:build-issuer-xml
   #:parse-issuer-xml))

(in-package :cl-saml/src/core/domain/saml/issuer)

;;; Issuer Structure

(defclass issuer ()
  ((value
    :initarg :value
    :reader issuer-value
    :type string)
   (format
    :initarg :format
    :reader issuer-format
    :type (or null string)
    :initform nil)
   (qualifier
    :initarg :qualifier
    :reader issuer-qualifier
    :type (or null string)
    :initform nil))
  (:documentation "SAML Issuer represents the entity that created a SAML message."))

(defun make-issuer (value &key format qualifier)
  "Create a new Issuer."
  (make-instance 'issuer
                 :value (string value)
                 :format format
                 :qualifier qualifier))

;;; Issuer XML Generation

(defgeneric build-issuer-xml (issuer)
  (:documentation "Build XML element for Issuer.
Returns: xml-element"))

(defmethod build-issuer-xml ((issuer issuer))
  (let ((value (issuer-value issuer))
        (format (issuer-format issuer))
        (qualifier (issuer-qualifier issuer)))
    (xml:make-xml-element "saml:Issuer"
                      ;; :attributes (append
                      ;;              (when format `(("Format" ,format)))
                      ;;              (when qualifier `(("NameQualifier" ,qualifier))))
                      :text value)))

;;; Issuer XML Parsing

(defgeneric parse-issuer-xml (element)
  (:documentation "Parse Issuer from XML element.
ELEMENT: xml-element
Returns: issuer"))

(defmethod parse-issuer-xml ((element xml:xml-element))
  (let ((value (xml:xml-element-text-content element))
        (format (xml:xml-get-attribute element "Format"))
        (qualifier (xml:xml-get-attribute element "NameQualifier")))
    (make-issuer value :format format :qualifier qualifier)))

;;; Default issuer format

(defparameter +issuer-format-entity+ namespaces:+nameid-format-entity+
  "Use entity format for Issuer by default")
