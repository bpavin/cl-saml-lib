(defpackage :cl-saml-lib/src/core/domain/saml/attributes
  (:use :cl)
  (:nicknames :attributes)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:saml-attribute
   ;; slots
   #:name
   #:friendly-name
   #:name-format
   #:attribute-values

   #:make-attribute
   #:make-attribute-value
   #:build-attribute-xml
   #:parse-attribute-xml

   ;; class
   #:attribute-statement
   ;; slots
   #:attribute-statement-attributes

   #:make-attribute-statement
   #:build-attributestatement-xml
   #:parse-attributestatement-xml
   #:make-email-attribute
   #:make-name-attribute
   #:make-groups-attribute
   #:map-user-to-attributes))

(in-package :cl-saml-lib/src/core/domain/saml/attributes)

;;; Attribute Structure

(defclass saml-attribute ()
  ((name
    :initarg :name
    :reader name
    :type string)
   (friendly-name
    :initarg :friendly-name
    :reader friendly-name
    :type (or null string)
    :initform nil)
   (name-format
    :initarg :name-format
    :reader name-format
    :type (or null string)
    :initform nil)
   (attribute-values
    :initarg :values
    :reader attribute-values
    :type list
    :initform nil))
  (:documentation "SAML Attribute with optional friendly name and values."))

(defun make-attribute (name &key friendly-name name-format values)
  "Create a new Attribute."
  (make-instance 'saml-attribute
                 :name name
                 :friendly-name friendly-name
                 :name-format (or name-format 
                                  "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified")
                 :values (mapcar #'princ-to-string values)))

;;; AttributeValue

(defun make-attribute-value (value &key (type nil type-p))
  "Create an attribute value.
If TYPE is specified, wraps value in xsi:type attribute."
  (if type-p
      (xml:make-xml-element "saml:AttributeValue"
                            :attributes (list "xsi:type" type)
                            :children (list (princ-to-string value)))
      (xml:make-xml-element "saml:AttributeValue"
                            :children (list (princ-to-string value)))))

;;; Attribute XML Generation

(defgeneric build-attribute-xml (attribute)
  (:documentation "Build XML element for Attribute.
Returns: xml-element"))

(defmethod build-attribute-xml ((attr saml-attribute))
  (let ((attrs (list `("Name" ,(name attr)))))
    (when (friendly-name attr)
      (push `("FriendlyName" ,(friendly-name attr)) attrs))
    (when (name-format attr)
      (push `("NameFormat" ,(name-format attr)) attrs))
    
    (xml:make-xml-element "saml:Attribute"
                      :attributes attrs
                      :children (mapcar #'make-attribute-value (attribute-values attr)))))

;;; Attribute XML Parsing

(defgeneric parse-attribute-xml (element)
  (:documentation "Parse Attribute from XML element.
ELEMENT: xml-element
Returns: saml-attribute"))

(defmethod parse-attribute-xml ((element xml:xml-element))
  (let* ((name (xml:xml-get-attribute element "Name"))
         (friendly-name (xml:xml-get-attribute element "FriendlyName"))
         (name-format (xml:xml-get-attribute element "NameFormat"))
         (value-elements (xml:xml-find-elements element "saml:AttributeValue | saml2:AttributeValue"))
         (values (mapcar #'xml:xml-element-text-content value-elements)))
    (make-instance 'saml-attribute
                   :name name
                   :friendly-name friendly-name
                   :name-format name-format
                   :values values)))

;;; AttributeStatement

(defclass attribute-statement ()
  ((attributes
    :initarg :attributes
    :reader attribute-statement-attributes
    :type list
    :initform nil))
  (:documentation "Container for attributes."))

(defun make-attribute-statement (&rest attributes)
  "Create an AttributeStatement with given attributes."
  (make-instance 'attribute-statement :attributes attributes))

;;; AttributeStatement XML Generation

(defgeneric build-attributestatement-xml (statement)
  (:documentation "Build XML element for AttributeStatement.
Returns: xml-element"))

(defmethod build-attributestatement-xml ((stmt attribute-statement))
  (xml:make-xml-element "saml:AttributeStatement"
                    :children (mapcar #'build-attribute-xml 
                                      (attribute-statement-attributes stmt))))

;;; AttributeStatement XML Parsing

(defgeneric parse-attributestatement-xml (element)
  (:documentation "Parse AttributeStatement from XML element.
ELEMENT: xml-element
Returns: attribute-statement"))

(defmethod parse-attributestatement-xml ((element xml:xml-element))
  (let* ((attr-elements (xml:xml-find-elements element "saml:Attribute | saml2:Attribute"))
         (attributes (mapcar #'parse-attribute-xml attr-elements)))
    (make-instance 'attribute-statement :attributes attributes)))

;;; Common Attribute Factory Functions

(defun make-email-attribute (email)
  "Create standard email attribute."
  (make-attribute "email"
                  :friendly-name "Email Address"
                  :values (list email)))

(defun make-name-attribute (given-name &optional surname)
  "Create standard name attributes."
  (when surname
    (return-from make-name-attribute
      (list (make-attribute "givenName"
                            :friendly-name "Given Name"
                            :values (list given-name))
            (make-attribute "surname"
                            :friendly-name "Surname"
                            :values (list surname)))))
  (make-attribute "givenName"
                  :friendly-name "Given Name"
                  :values (list given-name)))

(defun make-groups-attribute (groups)
  "Create groups/roles attribute."
  (make-attribute "groups"
                   :friendly-name "Groups"
                   :values groups))

;;; Attribute Mapping Helper

(defgeneric map-user-to-attributes (user attribute-mapping)
  (:documentation "Map user properties to SAML attributes.
USER: user object
ATTRIBUTE-MAPPING: plist mapping SAML attribute names to user property names
Returns: list of saml-attribute")
  (:method (user attribute-mapping)
    (let ((attributes '()))
      (loop for (attr-name user-prop) on attribute-mapping by #'cddr
            for value = (slot-value user (alexandria:make-keyword user-prop))
            when value
              do (push (make-attribute attr-name :values (if (listp value) value (list value)))
                       attributes))
      (nreverse attributes))))
