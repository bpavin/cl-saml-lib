(defpackage :cl-saml-lib/src/core/domain/saml/subject
  (:use :cl)
  (:nicknames :subject)
  (:import-from :cl-saml-lib/src/core/infrastructure/identifiers)
  (:import-from :cl-saml-lib/src/core/infrastructure/time)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:import-from :cl-saml-lib/src/core/domain/saml/name-id)
  (:export
   #:subject
   ;; slots
   #:subject-name-id
   #:subject-confirmations

   #:subject-confirmation
   ;; slots
   #:confirmation-method
   #:confirmation-data
   #:confirmation-recipient
   #:confirmation-in-response-to
   #:confirmation-not-on-or-after
   #:confirmation-not-before
   #:confirmation-address
   #:build-subject-xml
   #:build-subject-confirmation-xml
   #:parse-subject-xml
   #:parse-subject-confirmation-xml))

(in-package :cl-saml-lib/src/core/domain/saml/subject)
;;;
;;; Subject Structure

(defclass subject ()
  ((name-id
    :initarg :name-id
    :reader subject-name-id
    :type (or null name-id))
   (subject-confirmations
    :initarg :confirmations
    :reader subject-confirmations
    :type list
    :initform nil))
  (:documentation "SAML Subject contains NameID and optional confirmation methods."))

(defun make-subject (name-id &key confirmations)
  "Create a new Subject."
  (make-instance 'subject
                 :name-id name-id
                 :confirmations confirmations))

;;; SubjectConfirmation Structure

(defclass subject-confirmation ()
  ((method
    :initarg :method
    :reader confirmation-method
    :type string)
   (subject-confirmation-data
    :initarg :confirmation-data
    :reader confirmation-data
    :type (or null string)
    :initform nil)
   (recipient
    :initarg :recipient
    :reader confirmation-recipient
    :type (or null string)
    :initform nil)
   (in-response-to
    :initarg :in-response-to
    :reader confirmation-in-response-to
    :type (or null string)
    :initform nil)
   (not-on-or-after
    :initarg :not-on-or-after
    :reader confirmation-not-on-or-after
    :type (or null integer)
    :initform nil)
   (not-before
    :initarg :not-before
    :reader confirmation-not-before
    :type (or null integer)
    :initform nil)
   (address
    :initarg :address
    :reader confirmation-address
    :type (or null string)
    :initform nil))
  (:documentation "SubjectConfirmation specifies how the subject can be confirmed."))

;;; SubjectConfirmation Method Constants

(defparameter +confirmation-bearer+ "urn:oasis:names:tc:SAML:2.0:cm:bearer"
  "Bearer confirmation - no further proof required")

(defparameter +confirmation-holder-of-key+ "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
  "Holder-of-key confirmation")

(defparameter +confirmation-sender-vouches+ "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"
  "Sender-vouches confirmation")

(defun make-subject-confirmation (method &key confirmation-data recipient 
                                    in-response-to not-on-or-after 
                                    not-before address)
  "Create a new SubjectConfirmation."
  (make-instance 'subject-confirmation
                 :method method
                 :confirmation-data confirmation-data
                 :recipient recipient
                 :in-response-to in-response-to
                 :not-on-or-after not-on-or-after
                 :not-before not-before
                 :address address))

;;; Subject XML Generation

(defgeneric build-subject-xml (subject)
  (:documentation "Build XML element for Subject.
Returns: xml-element"))

(defmethod build-subject-xml ((subject subject))
  (let ((name-id (subject-name-id subject))
        (confirmations (subject-confirmations subject)))
    (xml:make-xml-element "saml:Subject"
                      :children (append
                                 (when name-id (list (name-id:build-nameid-xml name-id)))
                                 (mapcar #'build-subject-confirmation-xml confirmations)))))

;;; SubjectConfirmation XML Generation

(defgeneric build-subject-confirmation-xml (subject-confirmation)
  (:documentation "Build XML element for SubjectConfirmation.
Returns: xml-element"))

(defmethod build-subject-confirmation-xml ((conf subject-confirmation))
  (let ((method (confirmation-method conf))
        (data (confirmation-data conf))
        (recipient (confirmation-recipient conf))
        (in-response-to (confirmation-in-response-to conf))
        (not-on-or-after (confirmation-not-on-or-after conf))
        (not-before (confirmation-not-before conf))
        (address (confirmation-address conf)))
    (let ((attrs (list `("Method" ,method))))
      (when recipient (push `("Recipient" ,recipient) attrs))
      (when in-response-to (push `("InResponseTo" ,in-response-to) attrs))
      (when not-on-or-after 
        (push `("NotOnOrAfter" ,(time:format-saml-time not-on-or-after)) attrs))
      (when not-before
        (push `("NotBefore" ,(time:format-saml-time not-before)) attrs))
      (when address (push `("Address" ,address) attrs))
      (xml:make-xml-element "saml:SubjectConfirmation"
                            :attributes attrs
                            :children (when data
                                        (list (xml:make-xml-element "saml:SubjectConfirmationData"
                                                                :attributes (list `("NotOnOrAfter"
                                                                                        ,(time:format-saml-time not-on-or-after)))
                                                                :children (list data))))))))

;;; Subject XML Parsing

(defgeneric parse-subject-xml (element)
  (:documentation "Parse Subject from XML element.
ELEMENT: xml-element
Returns: subject"))

(defmethod parse-subject-xml ((element xml:xml-element))
  (let* ((name-id-el (xml:xml-find-element element "saml:NameID | saml2:NameID"))
         (name-id (when name-id-el (name-id:parse-nameid-xml name-id-el)))
         (conf-elements (xml:xml-find-elements element "saml:SubjectConfirmation | saml2:SubjectConfirmation"))
         (confirmations (mapcar #'parse-subject-confirmation-xml conf-elements)))
    (make-subject name-id :confirmations confirmations)))

(defgeneric parse-subject-confirmation-xml (element)
  (:documentation "Parse SubjectConfirmation from XML element.
ELEMENT: xml-element
Returns: subject-confirmation"))

(defmethod parse-subject-confirmation-xml ((element xml:xml-element))
  (let* ((method (xml:xml-get-attribute element "Method"))
         (data-el (xml:xml-find-element element "saml:SubjectConfirmationData | saml2:SubjectConfirmationData"))
         (data (when data-el (xml:xml-element-text-content data-el)))
         (recipient (xml:xml-get-attribute data-el "Recipient"))
         (in-response-to (xml:xml-get-attribute data-el "InResponseTo"))
         (not-on-or-after-str (when data-el (xml:xml-get-attribute data-el "NotOnOrAfter")))
         (not-on-or-after (when not-on-or-after-str
                            (time:parse-saml-time not-on-or-after-str)))
         (not-before-str (when data-el (xml:xml-get-attribute data-el "NotBefore")))
         (not-before (when not-before-str
                       (time:parse-saml-time not-before-str)))
         (address (xml:xml-get-attribute element "Address")))
    (make-subject-confirmation method
                               :confirmation-data data
                               :recipient recipient
                               :in-response-to in-response-to
                               :not-on-or-after not-on-or-after
                               :not-before not-before
                               :address address)))
