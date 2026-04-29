(defpackage :cl-saml/src/core/domain/metadata/contact-person
  (:use #:cl)
  (:nicknames :contact-person)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml/src/core/infrastructure/xml)
  (:export
   ;; Class
   #:contact-person
   ;; Slots
   #:contact-type
   #:contact-company
   #:contact-given-name
   #:contact-email-address
   ;; XML Build
   #:build-contact-person-xml
   ;; XML Parse
   #:parse-contact-person-xml))

(in-package :cl-saml/src/core/domain/metadata/contact-person)

(defclass-std:defclass/std contact-person ()
  ((contact-type :type (member :technical :support :administrative :billing :other))
   (company :type (or null string))
   (given-name :type (or null string))
   (email-address :type list :std nil)))

;;; ============================================================================
;;; XML Building - Contact Person
;;; ============================================================================

(defmethod build-contact-person-xml ((this contact-person))
  "Build ContactPerson XML element."
  (let* ((type-str (string-downcase (symbol-name (contact-type this))))
         (attrs (list "contactType" type-str))
         (ns-decl namespaces:+saml-metadata-namespace+)
         (children (append
                    (when (company this)
                      (list (xml:make-xml-element
                            "Company"
                            :namespace ns-decl
                            :children (list (company this)))))
                    (when (given-name this)
                      (list (xml:make-xml-element
                            "GivenName"
                            :namespace ns-decl
                            :children (list (given-name this)))))
                    (loop for email in (email-address this)
                          collect (xml:make-xml-element
                                   "EmailAddress"
                                   :namespace ns-decl
                                   :children (list email))))))
    (xml:make-xml-element
     "ContactPerson"
     :namespace ns-decl
     :attributes attrs
     :children children)))

;;; ============================================================================
;;; XML Parsing - Contact Person
;;; ============================================================================

(defmethod parse-contact-person-xml ((this xml:xml-element))
  "Parse ContactPerson XML element."
  (let* ((type-str (xml:xml-get-attribute this "contactType"))
         (company-el (xml:xml-find-element this "md:Company"))
         (given-name-el (xml:xml-find-element this "md:GivenName"))
         (email-els (xml:xml-find-elements this "md:EmailAddress")))
    (make-instance 'contact-person
                   :contact-type (intern (string-upcase type-str) :keyword)
                   :company (when company-el (xml:xml-element-text-content company-el))
                   :given-name (when given-name-el (xml:xml-element-text-content given-name-el))
                   :email-address (loop for el in email-els
                                        collect (xml:xml-element-text-content el)))))
