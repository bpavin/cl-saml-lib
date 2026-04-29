(defpackage :cl-saml/src/core/domain/saml/saml-conditions
  (:use :cl)
  (:nicknames :saml-conditions)
  (:import-from :cl-saml/src/core/infrastructure/xml)
  (:export
   #:conditions
   ;; slots
   #:conditions-not-before
   #:conditions-not-on-or-after
   #:conditions-audience-restrictions
   #:conditions-one-time-use
   #:conditions-proxy-restriction

   #:make-conditions
   #:make-default-conditions
   #:build-conditions-xml
   #:parse-conditions-xml
   #:validate-conditions))

(in-package :cl-saml/src/core/domain/saml/saml-conditions)

;;; Conditions Structure

(defclass conditions ()
  ((not-before
    :initarg :not-before
    :reader conditions-not-before
    :type (or null integer)
    :initform nil
    :documentation "Earliest time instant for which the assertion is valid (inclusive)")
   (not-on-or-after
    :initarg :not-on-or-after
    :reader conditions-not-on-or-after
    :type (or null integer)
    :initform nil
    :documentation "Latest time instant for which the assertion is valid (exclusive)")
   (audience-restrictions
    :initarg :audience-restrictions
    :reader conditions-audience-restrictions
    :type list
    :initform nil
    :documentation "List of audience URIs")
   (one-time-use
    :initarg :one-time-use
    :reader conditions-one-time-use
    :type boolean
    :initform nil
    :documentation "If true, assertion cannot be used more than once")
   (proxy-restriction
    :initarg :proxy-restriction
    :reader conditions-proxy-restriction
    :type (or null integer)
    :initform nil
    :documentation "Maximum number of hops for attribute authority chain"))
  (:documentation "Conditions under which the assertion is valid."))

(defun make-conditions (&key not-before not-on-or-after audience-restrictions
                         one-time-use proxy-restriction)
  "Create a new Conditions element."
  (make-instance 'conditions
                 :not-before not-before
                 :not-on-or-after not-on-or-after
                 :audience-restrictions (or audience-restrictions '())
                 :one-time-use one-time-use
                 :proxy-restriction proxy-restriction))

;;; Default Conditions Factory

(defun make-default-conditions (audience &key (validity-seconds 300))
  "Create default conditions for an assertion.
AUDIENCE: string URI of the SP
VALIDITY-SECONDS: assertion validity window (default 5 minutes)"
  (let ((now (time:current-time)))
    (make-conditions
     :not-before now
     :not-on-or-after (time:add-duration now validity-seconds)
     :audience-restrictions (list audience))))

;;; Conditions XML Generation

(defgeneric build-conditions-xml (conditions)
  (:documentation "Build XML element for Conditions.
Returns: xml-element"))

(defmethod build-conditions-xml ((c conditions))
  (let ((attrs '()))
    (when (conditions-not-before c)
      (push `("NotBefore" ,(time:format-saml-time
                            (conditions-not-before c))) attrs))
    (when (conditions-not-on-or-after c)
      (push `("NotOnOrAfter" ,(time:format-saml-time
                               (conditions-not-on-or-after c))) attrs))
    
    (let ((children '()))
      ;; Audience Restrictions
      (dolist (audience (conditions-audience-restrictions c))
        (push (xml:make-xml-element "saml:AudienceRestriction"
                                :children (list (xml:make-xml-element "saml:Audience"
                                                                 :children (list audience))))
              children))
      
      ;; OneTimeUse
      (when (conditions-one-time-use c)
        (push (xml:make-xml-element "saml:OneTimeUse") children))
      
      ;; ProxyRestriction
      (when (conditions-proxy-restriction c)
        (push (xml:make-xml-element "saml:ProxyRestriction"
                                :attributes `(("Count" ,(princ-to-string 
                                                          (conditions-proxy-restriction c)))))
              children))
      
      (xml:make-xml-element "saml:Conditions"
                        :attributes attrs
                        :children (nreverse children)))))

;;; Conditions XML Parsing

(defgeneric parse-conditions-xml (element)
  (:documentation "Parse Conditions from XML element.
ELEMENT: xml-element
Returns: conditions"))

(defmethod parse-conditions-xml ((element xml:xml-element))
  (let* ((not-before-str (xml:xml-get-attribute element "NotBefore"))
         (not-before (when not-before-str
                       (time:parse-saml-time not-before-str)))
         (not-on-or-after-str (xml:xml-get-attribute element "NotOnOrAfter"))
         (not-on-or-after (when not-on-or-after-str
                            (time:parse-saml-time not-on-or-after-str)))
         (audience-elements (xml:xml-find-elements 
                             element "saml:AudienceRestriction/saml:Audience"))
         (audiences (mapcar #'xml:xml-element-text-content audience-elements))
         (one-time-use (xml:xml-find-element element "saml:OneTimeUse | saml2:OneTimeUse"))
         (proxy-el (xml:xml-find-element element "saml:ProxyRestriction | saml2:ProxyRestriction"))
         (proxy-count (when proxy-el
                        (break)
                        (let ((count-str (xml:xml-get-attribute proxy-el "Count")))
                          (when count-str (parse-integer count-str))))))
    (make-conditions
     :not-before not-before
     :not-on-or-after not-on-or-after
     :audience-restrictions audiences
     :one-time-use (when one-time-use t)
     :proxy-restriction proxy-count)))

;;; Conditions Validation

(defgeneric validate-conditions (conditions &key current-time)
  (:documentation "Validate Conditions.
CURRENT-TIME: timestamp to check against (defaults to current time)
Returns: (values valid-p error-message)")
  (:method ((c conditions) &key (current-time (time:current-time)))
    (let ((now current-time))
      (when (and (conditions-not-before c)
                 (time:time-less-than now (conditions-not-before c)))
        (return-from validate-conditions 
          (values nil "Assertion not yet valid (NotBefore)")))
      
      (when (and (conditions-not-on-or-after c)
                 (time:time-greater-than now
                                                          (conditions-not-on-or-after c)))
        (return-from validate-conditions 
          (values nil "Assertion expired (NotOnOrAfter)")))
      
      (values t nil))))
