(defpackage :cl-saml-lib/src/core/domain/metadata/role-descriptor
  (:use #:cl)
  (:nicknames :role-descriptor)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml-lib/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/organization)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/key-descriptor)
  (:import-from #:cl-saml-lib/src/core/domain/metadata/contact-person)
  (:export
   ;; Class
   #:role-descriptor
   ;; Slots
   #:protocol-support
   #:key-descriptors
   #:organization
   #:contact-persons))

(in-package :cl-saml-lib/src/core/domain/metadata/role-descriptor)

(defclass-std:defclass/std role-descriptor ()
  ((protocol-support :type list :std (list namespaces:+saml-protocol-uri+))
   (key-descriptors :type list :std nil)
   (organization :type (or null organization:organization) :std nil)
   (contact-persons :type list :std nil)))
