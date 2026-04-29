(defpackage :cl-saml-lib/src/core/infrastructure/cxml-impl
  (:use :cl)
  (:nicknames :cxml-impl)
  (:import-from :cxml)
  (:import-from :xpath)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/domain/saml/namespaces)
  (:export
   #:cxml-parser
   #:cxml-document
   #:parse-xml))

(in-package :cl-saml-lib/src/core/infrastructure/cxml-impl)

;;; Type Definitions
(defclass-std:defclass/std cxml-parser (xml:xml-parser)
  ())

(defmethod xml:parse-xml ((this cxml-parser) source &key)
  (make-instance 'cxml-document
                 :raw source
                 :node (cxml:parse source (cxml-dom:make-dom-builder))))

(defclass-std:defclass/std cxml-document (xml:xml-document)
  ())

(defclass-std:defclass/std cxml-element (xml:xml-element)
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

(defmethod xml:make-xml-element ((tag string) &key attributes children namespace text)
  "Create a new XML element.
TAG: string or keyword for element name
ATTRIBUTES: plist of attribute names and values
CHILDREN: list of child elements or strings
NAMESPACE: optional namespace URI"
  (let ((sink (cxml:make-string-sink :omit-xml-declaration-p t)))
    (cxml:with-xml-output sink
      (cxml:with-element* (namespace tag)
        (dolist (attr attributes)
          (destructuring-bind (attr-name attr-val) attr
            (cxml:attribute attr-name attr-val)))
        (dolist (child children)
          (cxml:unescaped child))
        (when text (cxml:text text))))))

(defmethod xml:make-xml-element ((tag symbol) &key attributes children namespace text)
  (xml:make-xml-element (string tag) :attributes attributes :children children :namespace namespace :text text))

;;; XML Element Accessors

(defmethod xml:xml-element-tag ((this cxml-element))
  "Returns the tag/element-name of an XML element."
  )

(defmethod xml:xml-element-attributes ((this cxml-element))
  "Returns a plist of attributes for an XML element.")

(defmethod xml:xml-element-children ((this cxml-element))
  "Returns list of child nodes (elements and text)."
  (let ((res))
    (dom:map-node-map (lambda (n)
                        (push (make-instance 'cxml-element
                                             :node n)
                              res))
                      (dom:child-nodes (xml:node this)))
    res))

(defmethod xml:xml-element-text-content ((this cxml-element))
  "Returns the combined text content of an element."
  (let ((res))
    (dom:map-node-list (lambda (n)
                         (if (dom:text-node-p n)
                             (setf res (dom:node-value n))))
                       (dom:child-nodes (xml:node this)))
    res))

(defmethod xml:xml-element-namespace-uri ((this cxml-element))
  "Returns the namespace URI of an element, or nil.")

;;; XML Navigation

(defmethod xml:xml-find-element ((this cxml-document) xpath &optional nsmap)
  "Find first element matching XPath.
ELEMENT: xml-document or xml-element to search
XPATH: string XPath expression
NSMAP: optional namespace prefix to URI mapping alist
Returns: xml-element or nil"
  (xpath:with-namespaces #.namespaces:+saml-namespace-declaration+
    (make-instance 'cxml-element
                   :node (xpath:first-node (xpath:evaluate xpath (xml:node this))))))

(defmethod xml:xml-find-element ((this cxml-element) xpath &optional nsmap)
  "Find first element matching XPath.
ELEMENT: xml-document or xml-element to search
XPATH: string XPath expression
NSMAP: optional namespace prefix to URI mapping alist
Returns: xml-element or nil"
  (xpath:with-namespaces #.namespaces:+saml-namespace-declaration+
    (let ((el (xpath:first-node (xpath:evaluate xpath (xml:node this)))))
      (if el (make-instance 'cxml-element :node el)))))

(defmethod xml:xml-find-elements ((this cxml-element) xpath &optional nsmap)
  "Find all elements matching XPath.
Returns: list of xml-element"
  (xpath:with-namespaces #.namespaces:+saml-namespace-declaration+
    (xpath:map-node-set->list (lambda (node)
                                (make-instance 'cxml-element :node node))
                              (xpath:evaluate xpath (xml:node this)))))

(defmethod xml:xml-get-attribute ((this cxml-element) attr-name &optional namespace)
  "Get attribute value by name.
ATTR-NAME: string or keyword
NAMESPACE: optional namespace URI
Returns: string or nil"
  (dom:get-attribute (xml:node this) attr-name))

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
