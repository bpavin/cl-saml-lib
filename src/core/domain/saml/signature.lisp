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

(defclass saml-signature ()
  ((status-code
    :initarg :status-code
    :reader saml-signature-code
    :type string)
   (status-message
    :initarg :status-message
    :reader saml-signature-message
    :type (or null string)
    :initform nil))
  (:documentation "SAML Status code and optional message."))

(defun make-saml-signature (status-code &optional status-message)
  "Create a SAML Status."
  (make-instance 'saml-signature
                 :status-code status-code
                 :status-message status-message))

;;; Status Success Check

(defun status-success-p (status)
  "Check if status indicates success."
  (string= (saml-signature-code status) +status-success+))

;;; Status XML Generation

(defgeneric build-signature-xml (status)
  (:documentation "Build XML element for Status.
Returns: xml-element"))

(defmethod build-signature-xml ((status saml-signature))
  (let ((children (list (xml:make-xml-element "samlp:StatusCode"
                                              :attributes `(("Value" ,(saml-signature-code status)))))))
    (when (saml-signature-message status)
      (push (xml:make-xml-element "samlp:StatusMessage"
                                  :children (list (saml-signature-message status)))
            children))
    (xml:make-xml-element "samlp:Status"
                          :children children)))

;;; Status XML Parsing

(defgeneric parse-signature-xml (element)
  (:documentation "Parse Status from XML element.
ELEMENT: xml-element
Returns: saml-signature"))

(defmethod parse-signature-xml ((element xml:xml-element))
  (let* ((signature-el (xml:xml-find-element element "ds:Signature"))
         (status-code (when status-code-el
                        (xml:xml-get-attribute status-code-el "Value")))
         (status-msg-el (xml:xml-find-element element "saml:StatusMessage | saml2p:StatusMessage"))
         (status-message (when status-msg-el
                           (xml:xml-element-text-content status-msg-el))))
    (make-saml-signature status-code status-message)))

