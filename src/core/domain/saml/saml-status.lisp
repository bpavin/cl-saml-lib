(defpackage :cl-saml-lib/src/core/domain/saml/saml-status
  (:use :cl)
  (:nicknames :saml-status)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:saml-status
   #:saml-status-code
   #:saml-status-message
   #:parse-status-xml
   #:build-status-xml))

(in-package :cl-saml-lib/src/core/domain/saml/saml-status)

;;; Status Structure

(defclass saml-status ()
  ((status-code
    :initarg :status-code
    :reader saml-status-code
    :type string)
   (status-message
    :initarg :status-message
    :reader saml-status-message
    :type (or null string)
    :initform nil))
  (:documentation "SAML Status code and optional message."))

(defun make-saml-status (status-code &optional status-message)
  "Create a SAML Status."
  (make-instance 'saml-status
                 :status-code status-code
                 :status-message status-message))

;;; Status Success Check

(defun status-success-p (status)
  "Check if status indicates success."
  (string= (saml-status-code status) namespaces:+status-success+))

;;; Status XML Generation

(defgeneric build-status-xml (status)
  (:documentation "Build XML element for Status.
Returns: xml-element"))

(defmethod build-status-xml ((status saml-status))
  (let ((children (list (xml:make-xml-element "samlp:StatusCode"
                                              :attributes `(("Value" ,(saml-status-code status)))))))
    (when (saml-status-message status)
      (push (xml:make-xml-element "samlp:StatusMessage"
                                  :children (list (saml-status-message status)))
            children))
    (xml:make-xml-element "samlp:Status"
                          :children children)))

;;; Status XML Parsing

(defgeneric parse-status-xml (element)
  (:documentation "Parse Status from XML element.
ELEMENT: xml-element
Returns: saml-status"))

(defmethod parse-status-xml ((element xml:xml-element))
  (let* ((status-code-el (xml:xml-find-element element "saml:StatusCode | saml2p:StatusCode"))
         (status-code (when status-code-el
                        (xml:xml-get-attribute status-code-el "Value")))
         (status-msg-el (xml:xml-find-element element "saml:StatusMessage | saml2p:StatusMessage"))
         (status-message (when status-msg-el
                           (xml:xml-element-text-content status-msg-el))))
    (make-saml-status status-code status-message)))

;;; Common Status Factories

(defun make-status-success ()
  "Create a success status."
  (make-saml-status namespaces:+status-success+))

(defun make-status-requester (&optional message)
  "Create a Requester error status."
  (make-saml-status namespaces:+status-requester+ message))

(defun make-status-responder (&optional message)
  "Create a Responder error status."
  (make-saml-status namespaces:+status-responder+ message))

(defun make-status-version-mismatch (&optional message)
  "Create a VersionMismatch error status."
  (make-saml-status namespaces:+status-version-mismatch+ message))
