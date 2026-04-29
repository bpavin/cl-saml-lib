(defpackage :cl-saml/src/core/domain/saml/authn-statement
  (:use :cl)
  (:nicknames :authn-statement)
  (:import-from :cl-saml/src/core/infrastructure/identifiers)
  (:import-from :cl-saml/src/core/infrastructure/time)
  (:import-from :cl-saml/src/core/infrastructure/xml)
  (:import-from :cl-saml/src/core/domain/saml/namespaces)
  (:export
   #:authn-statement
   ;; slots
   #:authn-instant
   #:session-index
   #:session-not-on-or-after
   #:authn-context

   #:make-authn-statement
   #:authn-context
   ;; slots
   #:class-ref
   #:authn-context-declaration

   #:make-authn-context
   #:make-password-authn-context
   #:make-x509-authn-context
   #:build-authnstatement-xml
   #:build-authncontext-xml
   ))

(in-package :cl-saml/src/core/domain/saml/authn-statement)

;;; AuthnStatement Structure

(defclass authn-statement ()
  ((authn-instant
    :initarg :authn-instant
    :reader authn-instant
    :type integer
    :documentation "Time of authentication")
   (session-index
    :initarg :session-index
    :reader session-index
    :type (or null string)
    :initform nil
    :documentation "Identifier for this authentication event")
   (session-not-on-or-after
    :initarg :session-not-on-or-after
    :reader session-not-on-or-after
    :type (or null integer)
    :initform nil
    :documentation "Time after which the session is invalid")
   (authn-context
    :initarg :authn-context
    :reader authn-context
    :type authn-context
    :documentation "Authentication context"))
  (:documentation "Statement about an authentication event."))

(defun make-authn-statement (authn-instant authn-context 
                              &key session-index session-not-on-or-after)
  "Create a new AuthnStatement."
  (make-instance 'authn-statement
                 :authn-instant authn-instant
                 :authn-context authn-context
                 :session-index session-index
                 :session-not-on-or-after session-not-on-or-after))

;;; AuthnContext Structure

(defclass authn-context ()
  ((class-ref
    :initarg :class-ref
    :reader class-ref
    :type string
    :documentation "URI identifying authentication method")
   (authn-context-declaration
    :initarg :declaration
    :reader authn-context-declaration
    :type (or null xml-element)
    :initform nil
    :documentation "Optional authentication declaration"))
  (:documentation "Authentication context information."))

(defun make-authn-context (class-ref &key declaration)
  "Create a new AuthnContext."
  (make-instance 'authn-context
                 :class-ref class-ref
                 :declaration declaration))

;;; Common AuthnContext Factories

(defun make-password-authn-context (&key (class-ref namespaces:+authn-context-password-protected-transport+))
  "Create password authentication context."
  (make-authn-context class-ref))

(defun make-x509-authn-context ()
  "Create X.509 certificate authentication context."
  (make-authn-context namespaces:+authn-context-x509+))

;;; AuthnStatement XML Generation

(defgeneric build-authnstatement-xml (statement)
  (:documentation "Build XML element for AuthnStatement.
Returns: xml-element"))

(defmethod build-authnstatement-xml ((stmt authn-statement))
  (let ((attrs (list `("AuthnInstant"
                       ,(time:format-saml-time
                         (authn-instant stmt))))))
    (when (session-index stmt)
      (push `("SessionIndex" ,(session-index stmt)) attrs))
    (when (session-not-on-or-after stmt)
      (push `("SessionNotOnOrAfter"
              ,(time:format-saml-time
                (session-not-on-or-after stmt))) attrs))
    
    (xml:make-xml-element "saml:AuthnStatement"
                          :attributes attrs
                          :children (list (build-authncontext-xml
                                           (authn-context stmt))))))

;;; AuthnContext XML Generation

(defgeneric build-authncontext-xml (context)
  (:documentation "Build XML element for AuthnContext.
Returns: xml-element"))

(defmethod build-authncontext-xml ((ctx authn-context))
  (xml:make-xml-element "saml:AuthnContext"
                        :children (list (xml:make-xml-element "saml:AuthnContextClassRef"
                                                              :children (list (class-ref ctx))))))
