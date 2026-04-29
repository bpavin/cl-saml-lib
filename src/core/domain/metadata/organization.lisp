(defpackage :cl-saml/src/core/domain/metadata/organization
  (:use #:cl)
  (:nicknames :organization)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml/src/core/infrastructure/xml)
  (:export
   ;; Class
   #:organization
   ;; Slots
   #:name
   #:display-name
   #:url
   ;; XML Build
   #:build-organization-xml
   ;; XML Parse
   #:parse-organization-xml))

(in-package :cl-saml/src/core/domain/metadata/organization)

(defclass-std:defclass/std organization ()
  ((name :type list :std nil)
   (display-name :type list :std nil)
   (url :type list :std nil)))

;;; ============================================================================
;;; XML Building - Organization
;;; ============================================================================

(defmethod build-organization-xml ((this organization))
  "Build Organization XML element."
  (let ((children (append
                   (loop for (name . lang) in (name this)
                         collect (xml:make-xml-element
                                  "OrganizationName"
                                  :namespace namespaces:+saml-metadata-namespace+
                                  :attributes (when lang `(("xml:lang" ,lang)))
                                  :children (list name)))
                   (loop for (name . lang) in (display-name this)
                         collect (xml:make-xml-element
                                  "OrganizationDisplayName"
                                  :namespace namespaces:+saml-metadata-namespace+
                                  :attributes (when lang `(("xml:lang" ,lang)))
                                  :children (list name)))
                   (loop for (url . lang) in (url this)
                         collect (xml:make-xml-element
                                  "OrganizationURL"
                                  :namespace namespaces:+saml-metadata-namespace+
                                  :attributes (when lang `(("xml:lang" ,lang)))
                                  :children (list url))))))
    (xml:make-xml-element
     "Organization"
     :namespace namespaces:+saml-metadata-namespace+
     :children children)))

;;; ============================================================================
;;; XML Parsing - Organization
;;; ============================================================================

(defun parse-localized-strings (parent child-tag)
  "Parse localized strings from child elements.
   Returns list of (value . lang) pairs."
  (let ((elements (xml:xml-find-elements parent child-tag)))
    (loop for el in elements
          collect (let ((lang (xml:xml-get-attribute el "xml:lang"))
                       (text (xml:xml-element-text-content el)))
                    (cons text (or lang "en"))))))

(defmethod parse-organization-xml ((this xml:xml-element))
  "Parse Organization XML element."
  (make-instance 'organization
                 :name (parse-localized-strings this "md:OrganizationName")
                 :display-name (parse-localized-strings this "md:OrganizationDisplayName")
                 :url (parse-localized-strings this "md:OrganizationURL")))
