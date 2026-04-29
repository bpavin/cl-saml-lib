(defpackage :cl-saml-lib/src/core/domain/metadata/key-descriptor
  (:use #:cl)
  (:nicknames :key-descriptor)
  (:import-from #:defclass-std)
  (:import-from #:cl-saml-lib/src/core/domain/saml/namespaces)
  (:import-from #:cl-saml-lib/src/core/infrastructure/xml)
  (:export
   ;; Class
   #:key-descriptor
   ;; Slots
   #:key-use
   #:key-certificate
   ;; XML Build
   #:build-key-descriptor-xml
   ;; XML Parse
   #:parse-key-descriptor-xml))

(in-package :cl-saml-lib/src/core/domain/metadata/key-descriptor)

(defclass-std:defclass/std key-descriptor ()
  ((key-use :type (member :signing :encryption nil))
   (key-certificate :type string)))

;;; ============================================================================
;;; XML Building - Key Descriptor
;;; ============================================================================

(defmethod build-key-descriptor-xml ((this key-descriptor))
  "Build KeyDescriptor XML element."
  (let* ((ds-ns "ds")
         (attrs (when (key-use this)
                  `(("use" ,(string-downcase (key-use this)))))))
    (xml:make-xml-element
     "KeyDescriptor"
     :namespace namespaces:+saml-metadata-namespace+
     :attributes attrs
     :children (list (xml:make-xml-element
                      "KeyInfo"
                      :namespace ds-ns
                      :children (list (xml:make-xml-element
                                       "X509Data"
                                       :namespace ds-ns
                                       :children (list (xml:make-xml-element
                                                        "X509Certificate"
                                                        :namespace ds-ns
                                                        :text (key-certificate this))))))))))

;;; ============================================================================
;;; XML Parsing - Key Descriptor
;;; ============================================================================

(defmethod parse-key-descriptor-xml ((this xml:xml-element))
  "Parse KeyDescriptor XML element."
  (let* ((use-str (xml:xml-get-attribute this "use"))
         (key-info-el (xml:xml-find-element this "ds:KeyInfo"))
         (x509data-el (when key-info-el
                        (xml:xml-find-element key-info-el "ds:X509Data")))
         (cert-el (when x509data-el
                    (xml:xml-find-element x509data-el "ds:X509Certificate"))))
    (make-instance 'key-descriptor
                   :key-use (when use-str (intern (string-upcase use-str) :keyword))
                   :key-certificate (when cert-el
                                      (xml:xml-element-text-content cert-el)))))
