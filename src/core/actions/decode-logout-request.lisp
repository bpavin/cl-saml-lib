(defpackage :cl-saml-lib/src/core/actions/decode-logout-request
  (:use :cl)
  (:nicknames :decode-logout-request)
  (:import-from :defclass-std)
  (:import-from :cl-saml-lib/src/core/domain/logout/logout-request)
  (:import-from :cl-saml-lib/src/core/infrastructure/xml)
  (:export
   #:decode-logout-request
   #:run))

(in-package :cl-saml-lib/src/core/actions/decode-logout-request)

(defclass-std:defclass/std decode-logout-request ()
  ((xml-parser :type xml:xml-parser)))

(defmethod run ((this decode-logout-request) logout-req-xml)
  "Parse LogoutRequest XML into a logout-request domain object.
THIS: decode-logout-request instance
LOGOUT-REQ-XML: string - the LogoutRequest XML to parse
Returns: logout-request instance"
  (let ((xml-document (xml:parse-xml (xml-parser this) logout-req-xml)))
    (logout-request:parse-logout-request-xml xml-document)))