(defpackage :cl-saml-lib/src/core/domain/saml/saml-signature
  (:use :cl)
  (:nicknames :saml-signature)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:saml-signature
   #:parse-signature-xml
   #:build-signature-xml))

(in-package :cl-saml-lib/src/core/domain/saml/saml-signature)

;;; Status Structure

(defclass-std:defclass/std saml-signature ()
  ((canonicalization-method)
   (digest-method)
   (signature-value)
   (x509-certificate))
  (:documentation "SAML signature data."))


;;; Status XML Generation

(defgeneric build-signature-xml (signature)
  (:documentation "Build XML element for Status.
Returns: xml-element"))

(defmethod build-signature-xml ((status saml-signature))
  )

;;; Status XML Parsing

(defgeneric parse-signature-xml (element)
  (:documentation "Parse Status from XML element.
ELEMENT: xml-element
Returns: saml-signature"))

(defmethod parse-signature-xml ((element xml:xml-element))
  (let* ((sig-value-el (xml:xml-find-element element "ds:SignatureValue"))
         (signature-value (when sig-value-el (xml:xml-element-text-content sig-value-el)))
         (sig-info-el (xml:xml-find-element element "ds:SignedInfo"))
         (canon-method-el (when sig-info-el (xml:xml-find-element sig-info-el "ds:CanonicalizationMethod")))
         (canonicalization-method (when canon-method-el (xml:xml-get-attribute canon-method-el "Algorithm")))
         (digest-method-el (when sig-info-el (xml:xml-find-element sig-info-el "ds:DigestMehotd")))
         (digest-method (when digest-method-el (xml:xml-get-attribute digest-method-el "Algorithm")))
         (key-info-el (xml:xml-find-element element "ds:KeyInfo"))
         (x509-data-el (when key-info-el (xml:xml-find-element key-info-el "ds:X509Data")))
         (x509-cert-el (when x509-data-el (xml:xml-find-element x509-data-el "ds:X509Certificate")))
         (x509-certificate (when x509-cert-el (xml:xml-element-text-content x509-cert-el))))
    (make-instance 'saml-signature
                   :signature-value signature-value
                   :canonicalization-method canonicalization-method
                   :digest-method digest-method
                   :x509-certificate x509-certificate)))

   
