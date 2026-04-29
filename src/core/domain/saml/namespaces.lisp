(defpackage :cl-saml/src/core/domain/saml/namespaces
  (:use :cl)
  (:nicknames :namespaces)
  (:export
   #:+saml-uri+
   #:+saml-protocol-namespace+
   #:+saml-protocol-uri+
   #:+saml-namespace-declaration+
   #:+nameid-format-email+
   #:+nameid-format-unspecified+
   #:+nameid-format-entity+
   #:+nameid-format-kerberos+
   #:+nameid-format-persistent+
   #:+nameid-format-transient+
   #:+status-success+
   #:+status-responder+
   #:+status-version-mismatch+
   #:+authn-context-password+
   #:+authn-context-password-protected-transport+
   #:+authn-context-tls-client+
   #:+binding-http-soap+
   #:+transform-enveloped-signature+
   #:+transform-c14n-inclusive+
   #:+transform-c14n-inclusive-with-comments+
   #:+saml-metadata-uri+
   #:+saml-metadata-namespace+
   #:+binding-http-post+
   #:+binding-http-redirect+
   #:+saml-signature-uri+
   #:+authn-context-x509+))

(in-package :cl-saml/src/core/domain/saml/namespaces)

;;; SAML 2.0 Namespace URIs

(defparameter +saml-uri+ "urn:oasis:names:tc:SAML:2.0:assertion"
  "SAML 2.0 Assertion namespace URI")

(defparameter +saml-protocol-namespace+ "samlp")

(defparameter +saml-protocol-uri+ "urn:oasis:names:tc:SAML:2.0:protocol"
  "SAML 2.0 Protocol namespace URI")

(defparameter +saml-signature-uri+ "http://www.w3.org/2000/09/xmldsig#"
  "SAML 2.0 Signature namespace URI")

(defparameter +saml-namespace-declaration+ 
  `(("saml" ,+saml-uri+)
    ("saml2" ,+saml-uri+)
    (,+saml-protocol-namespace+ ,+saml-protocol-uri+)
    ("saml2p" ,+saml-protocol-uri+)
    ("ds" ,+saml-signature-uri+)
    ("md" "urn:oasis:names:tc:SAML:2.0:metadata"))
  "Alist of namespace prefixes to URIs used in SAML XML")

;;; NameID Format Constants

(defparameter +nameid-format-email+ "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  "Email address NameID format")

(defparameter +nameid-format-unspecified+ "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  "Unspecified NameID format")

(defparameter +nameid-format-entity+ "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
  "Entity NameID format")

(defparameter +nameid-format-kerberos+ "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos"
  "Kerberos NameID format")

(defparameter +nameid-format-persistent+ "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  "Persistent NameID format (anonymous but stable identifier)")

(defparameter +nameid-format-transient+ "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"
  "Transient NameID format (session-scoped, non-persistent)")

;;; SAML Status Codes

(defparameter +status-success+ "urn:oasis:names:tc:SAML:2.0:status:Success"
  "Successful SAML operation")

(defparameter +status-requester+ "urn:oasis:names:tc:SAML:2.0:status:Requester"
  "Request was malformed or invalid")

(defparameter +status-responder+ "urn:oasis:names:tc:SAML:2.0:status:Responder"
  "Server error processing request")

(defparameter +status-version-mismatch+ "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
  "SAML version not supported")

;;; AuthnContext Class Refs

(defparameter +authn-context-password+ "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
  "Password authentication")

(defparameter +authn-context-password-protected-transport+ 
  "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
  "Password with TLS transport")

(defparameter +authn-context-tls-client+ 
  "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
  "TLS client certificate authentication")

(defparameter +authn-context-x509+ 
  "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
  "X.509 certificate authentication")

;;; Binding Constants

(defparameter +binding-http-post+ "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
  "HTTP-POST binding URI")

(defparameter +binding-http-redirect+ "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
  "HTTP-Redirect binding URI")

(defparameter +binding-http-soap+ "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"
  "SOAP binding URI")

;;; Signature Transform URIs

(defparameter +transform-enveloped-signature+ 
  "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
  "Enveloped signature transform")

(defparameter +transform-c14n-inclusive+ 
  "http://www.w3.org/2001/10/xml-exc-c14n#"
  "Exclusive C14N (without comments) transform")

(defparameter +transform-c14n-inclusive-with-comments+ 
  "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
  "Exclusive C14N (with comments) transform")

(defparameter +saml-metadata-uri+ "urn:oasis:names:tc:SAML:2.0:metadata")
(defparameter +saml-metadata-namespace+ "md")
