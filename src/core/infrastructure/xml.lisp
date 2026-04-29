(defpackage :cl-saml-lib/src/core/infrastructure/xml
  (:use :cl)
  (:nicknames :xml)
  (:import-from :defclass-std)
  (:export
   #:xml-parser
   #:xml-document
   #:raw
   #:node
   #:xml-element
   #:xml-attribute
   #:xml-text
   #:parse-xml
   #:serialize-xml
   #:make-xml-element
   #:xml-element-tag
   #:xml-element-attributes
   #:xml-element-children
   #:xml-element-text-content
   #:xml-element-namespace-uri
   #:xml-find-element
   #:xml-find-elements
   #:xml-get-attribute
   #:xml-append-child
   #:xml-remove-children
   #:xml-canonicalize
   ))

(in-package :cl-saml-lib/src/core/infrastructure/xml)

;;; Type Definitions

(defclass-std:defclass/std xml-parser ()
  ())

(defgeneric parse-xml (this source &key)
  (:documentation "Parse XML from source.
SOURCE can be a string, stream, pathname, or octet vector.
Returns an xml-document."))

(defclass-std:defclass/std xml-document ()
  ((raw
    node)))

(defclass-std:defclass/std xml-element ()
  ((node)))

(defclass-std:defclass/std xml-attribute ()
  ())

(defclass-std:defclass/std xml-text ()
  ())

;;; XML Parsing and Serialization

(defgeneric serialize-xml (document &key stream pretty)
  (:documentation "Serialize xml-document to string or stream.
If STREAM is provided, writes to stream. Otherwise returns string.")
  ;; (:method ((document xml-document) &key (stream nil) (pretty t))
  ;;   (declare (ignorable pretty))
  ;;   (if stream
  ;;       (error 'saml-error :message "serialize-xml: Must specialize for document type")
  ;;       (with-output-to-string (s)
  ;;         (serialize-xml document :stream s :pretty pretty))))
  )

;;; XML Element Construction

(defgeneric make-xml-element (tag &key attributes children namespace text)
  (:documentation "Create a new XML element.
TAG: string or keyword for element name
ATTRIBUTES: plist of attribute names and values
CHILDREN: list of child elements or strings
NAMESPACE: optional namespace URI")
  (:method ((tag string) &key attributes children namespace text)
    (declare (ignorable tag attributes children namespace text))
    (error 'saml-error :message "make-xml-element: Must specialize"))

  (:method ((tag symbol) &key attributes children namespace text)
    (xml:make-xml-element (string tag) :attributes attributes :children children :namespace namespace :text text)))

;;; XML Element Accessors

(defmethod xml-element-tag (element)
  (:documentation "Returns the tag/element-name of an XML element."))

(defmethod xml-element-attributes (element)
  (:documentation "Returns a plist of attributes for an XML element."))

(defmethod xml-element-children (element)
  (:documentation "Returns list of child nodes (elements and text)."))

(defmethod xml-element-text-content (element)
  (:documentation "Returns the combined text content of an element."))

(defmethod xml-element-namespace-uri (element)
  (:documentation "Returns the namespace URI of an element, or nil."))

;;; XML Navigation

(defgeneric xml-find-element (this xpath &optional nsmap)
  (:documentation "Find first element matching XPath.
ELEMENT: xml-document or xml-element to search
XPATH: string XPath expression
NSMAP: optional namespace prefix to URI mapping alist
Returns: xml-element or nil"))

(defgeneric xml-find-elements (this xpath &optional nsmap)
  (:documentation "Find all elements matching XPath.
Returns: list of xml-element"))

(defgeneric xml-get-attribute (this attr-name &optional namespace)
  (:documentation "Get attribute value by name.
ATTR-NAME: string or keyword
NAMESPACE: optional namespace URI
Returns: string or nil"))

(defgeneric (setf xml-get-attribute) (value element attr-name &optional namespace)
  (:documentation "Set attribute value on element."))

(defgeneric xml-append-child (parent child)
  (:documentation "Append a child element or text node to parent.
PARENT: xml-element
CHILD: xml-element or string"))

(defgeneric xml-remove-children (element)
  (:documentation "Remove all children from element."))

;;; XML Canonicalization

(defgeneric xml-canonicalize (element &key exclusive nsmap)
  (:documentation "Canonicalize XML element according to C14N rules.
If EXCLUSIVE is true, use Exclusive C14N.
Returns: string containing canonical XML."))
