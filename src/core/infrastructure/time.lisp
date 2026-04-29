(defpackage :cl-saml/src/core/infrastructure/time
  (:use :cl)
  (:nicknames :time)
  (:import-from :local-time)
  (:export
   #:current-time
   #:format-saml-time
   #:parse-saml-time
   #:time-less-than
   #:time-greater-than
   #:add-duration
   #:duration-between
   #:current-saml-time
   #:future-saml-time
   #:past-saml-time
   #:skew-time))

(in-package :cl-saml/src/core/infrastructure/time)

;;; Type Definitions
(local-time:reread-timezone-repository)
(setf local-time:*default-timezone* local-time:+utc-zone+)

(deftype saml-timestamp () 'integer) ; Universal time

;;; SAML Time Format Constants

(defparameter +saml-time-format+ ;;"~4,'0D-~2,'0D-~2,'0DT~2,'0D:~2,'0D:~2,'0DZ"
  '((:YEAR 4) #\- (:MONTH 2) #\- (:DAY 2) #\T (:HOUR 2) #\: (:MIN 2) #\: (:SEC 2) #\Z)
  "SAML 2.0 timestamp format: YYYY-MM-DDTHH:MM:SSZ")

;;; Current Time

(defun current-time ()
  "Get current time as saml-timestamp.
Returns: universal time integer"
  (local-time:now))

;;; Time Formatting (SAML uses ISO 8601)

(defun format-saml-time (timestamp)
  "Format timestamp to SAML time string.
Format: YYYY-MM-DDTHH:MM:SSZ (UTC)
TIMESTAMP: universal time integer
Returns: string"
  (local-time:format-timestring nil timestamp :format +saml-time-format+))

(defun parse-saml-time (time-string)
  "Parse SAML time string to timestamp.
TIME-STRING: SAML formatted time string
Returns: universal time integer"
  (if (not (string= "" time-string))
      (local-time:parse-timestring time-string)))

;;; Time Comparisons and Arithmetic

(defun time-less-than (time1 time2)
  "Compare two timestamps.
TIME1, TIME2: universal time integers
Returns: boolean (true if time1 < time2)"
  (local-time:timestamp< time1 time2))

(defun time-greater-than (time1 time2)
  "Compare two timestamps.
TIME1, TIME2: universal time integers
Returns: boolean (true if time1 > time2)"
  (local-time:timestamp> time1 time2))

(defun add-duration (timestamp duration)
  "Add duration to timestamp.
DURATION is in seconds (integer).
TIMESTAMP: universal time integer
Returns: new universal time integer"
  (local-time:adjust-timestamp timestamp (offset :sec duration)))

(defun duration-between (start-time end-time)
  "Calculate duration between two timestamps.
START-TIME, END-TIME: universal time integers
Returns: duration in seconds (integer)"
  (local-time:timestamp-difference start-time end-time))

;;; Convenience

(defun current-saml-time ()
  "Get current time formatted as SAML time string.
Returns: string"
  (format-saml-time (local-time:now)))

(defun future-saml-time (seconds-from-now)
  "Get future time formatted as SAML time string.
SECONDS-FROM-NOW: integer seconds to add to current time
Returns: string"
  (add-duration (local-time:now) seconds-from-now))

(defun past-saml-time (seconds-ago)
  "Get past time formatted as SAML time string.
SECONDS-AGO: integer seconds to subtract from current time
Returns: string"
  (add-duration (local-time:now) (* -1 seconds-ago)))

;;; Clock Skew Utilities (for testing)

(defun skew-time (timestamp seconds)
  "Skew timestamp by given seconds (for testing).
POSITIVE seconds = future, NEGATIVE = past.
TIMESTAMP: universal time integer
SECONDS: integer offset
Returns: universal time integer"
  (add-duration timestamp seconds))
