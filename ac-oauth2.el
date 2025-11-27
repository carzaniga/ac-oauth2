;;; ac-oauth2.el --- AC/OAuth2 is how I use OAuth2 with Gnus+IMAP  -*- lexical-binding: t -*-

;; Copyright (C) 2024-2025 Antonio Carzaniga

;; Author: Antonio Carzaniga <antonio.carzaniga@usi.ch>
;; Version: 0.01

;; This file is NOT part of GNU Emacs.

;; AC/OAuth2 This is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published
;; by the Free Software Foundation, either version 3 of the License,
;; or (at your option) any later version.

;; AC/OAuth2 is distributed in the hope that it will be useful, but
;; WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
;; General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with GNU Emacs. If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;; Integration of OAuth2 with Gnus.

;; Example configuration for the impatient:
;;
;; Below is a configuration and usage example based on my own
;; configuration, which is using MS' e-mail services:
;;
;; (use-package ac-oauth2
;;     :hook ((gnus-get-new-news . ac/oauth2-get-access-if-necessary)
;;            (message-send . ac/oauth2-get-access-if-necessary))
;;     :config
;;     (ac/oauth2-accounts
;;       '(("Work"
;;          :user "firstname.lastname@example.com"
;;          :imap-host "outlook.office365.com"
;;          :imap-port 993
;;          :smtp-host "smtp.office365.com"
;;          :smtp-port 587
;;
;;          :client-id "5ecd2dc4-..."		;; see CLIENT-ID below
;;          :client-secret "j-k8Q..."		;
;;
;;          :scope "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access"
;;
;;          ;; see TENANT-ID below for more information on these URLs
;;          :auth-url "https://login.microsoftonline.com/95bdc.../oauth2/v2.0/authorize"
;; 	    :token-url "https://login.microsoftonline.com/95bdc.../oauth2/v2.0/token"
;;
;;          ;; Store the access token (password) in this authinfo
;;          ;; file, and add this file to your `auth-sources'. Default
;;          ;; is `ac/oauth2-authinfo-file'.
;;          :authinfo-file "~/.work-authinfo"
;;
;;          ;; If you want to use a specific browser and browser
;;          ;; profile to handle the authorization business.
;; 	    ;; :browser-name "firefox"          ; use firefox to authenticate
;; 	    ;; :browser-args ("-P" "work")      ; with the "work" profile
;; 	 ))
;;       )
;; )
;;
;; (setq mail-sources
;;       '((imap
;;          :server "outlook.office365.com"
;;          :port 993
;;          :stream tls
;;          :user "myusername@example.com"
;;          :authentication xoauth2
;;          :mailbox "INBOX"
;;          :predicate "1:*")))
;;
;; (setq smtpmail-smtp-server "smtp.office365.com"
;;       smtpmail-smtp-service 587
;;       smtpmail-smtp-user "firstname.lastname@example.com"
;;       smtpmail-stream-type 'starttls)
;;
;; (setq gnus-secondary-select-methods
;;       '((nnimap "usi"
;; 		(nnimap-address "outlook.office365.com")
;; 		(nnimap-server-port 993)
;; 		(nnimap-stream tls)
;; 		(nnimap-user "myusername@example.com")
;; 		(nnimap-authenticator xoauth2)
;; 		(nnimap-inbox "INBOX"))))
;;
;; Basic ideas and terminology for OAuth2:
;;
;; You might want to read Section 1 (Introduction) of RFC6749: "The
;; OAuth 2.0 Authorization Framework"
;; (https://www.rfc-editor.org/rfc/rfc6749#section-1).  Here is the
;; basic scenario: you work at example.com and want to read your
;; example.com e-mail hosted at provider.com (e.g., MS).  You want to
;; do that with your favorite email client, namely Emacs.  You are the
;; "resource owner"; your email is the "protected resource";
;; provider.com is the "resource server" and also your "authorization
;; server", though the roles are conceptually distinct; and Emacs is
;; the "client".  The idea is that you (resource owner) request that
;; provider.com (authorization server) grant Emacs (client) access to
;; your email (protected resource), so that Emacs can later connect to
;; provider.com (resource server) to actually get your mail.
;;
;; The process of granting access is in fact a bit more involved.  You
;; first get an "authorization" token that then allows you to get an
;; "access" token that contains the IMAP/SMTP authentication password
;; that Emacs can then use to access your email.  The tokens remain
;; valid for some specified time.
;;
;; So, OAuth2, which is implemented by oauth.el plus some code here,
;; handles the token business, while Gnus, smtpmail.el, and imap.el
;; handle the actual email exchanges.
;;
;; CLIENT-ID and CLIENT-SECRET:
;;
;; Your "client" application must be known to your "authentication
;; server" (see terminology above).  The CLIENT-ID and CLIENT-SECRET
;; can be thought of as the username and password of your email
;; application within your authentication server.  The CLIENT-SECRET
;; may not be necessary, but the bottom line is that your client
;; application must be somehow registered with your resource server,
;; and you must have the corresponding CLIENT-ID.
;;
;; This is how it worked for me.  My client is Emacs with Gnus, and my
;; resource server is MS.  And -- you might have guessed it -- MS does
;; not by default recognize Emacs.  Still, fortunately, I was able to
;; register my client application myself on the MS Azure "App
;; registrations" page:
;;
;;     https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/RegisteredApps
;;
;; So, that is where I got my CLIENT-ID and CLIENT-SECRET.  You might
;; be able to find valid CLIENT-ID and CLIENT-SECRET codes elsewhere,
;; perhaps well-known ones for other email clients.
;;
;; TENANT-ID, Authorization URI, and Token URI:
;;
;; You need two more crucial pieces of information to configure your
;; OAuth2 system, namely the Authorization URI, and the Token URI.
;; These should be public URIs at least within your organization.
;; For me, the Authorization and Token URIs are:
;;
;;     https://login.microsoftonline.com/TENANT-ID/oauth2/v2.0/authorize
;;     https://login.microsoftonline.com/TENANT-ID/oauth2/v2.0/token
;;
;; Where the TENANT-ID is my organization's identifier within the MS
;; system, which I could get by going to the MS Azure "Overview" page:
;;
;;     https://portal.azure.com/#view/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/~/Overview
;;
;;; Code:

(defvar ac/oauth2-accounts nil
  "List of OAuth2 accounts.

This should be an alist.  The CAR of each element is a string
that identifies an account.  The CDR is a plist that specifies
the OAuth2 coordinates and some credentials for that account.

For example:

    ((\"Work\"
      :user \"name.lastname@example.com\"

      :imap-host \"outlook.office365.com\"
      :imap-port 993

      :smtp-host \"smtp.office365.com\"
      :smtp-port 587

      ;; You need an identifier and a \"secret\" code for your
      ;; client program.
      :client-id \"5ecd2dc4-...\"
      :client-secret \"j-k8Q~...\"

      :scope \"https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send      offline_access\"

      :auth-url \"https://login.microsoftonline.com/afb595bd-.../oauth2/v2.0/authorize\"
      :token-url \"https://login.microsoftonline.com/afb595bd-.../oauth2/v2.0/token\"

      ;; We use the `browse-url' functions to go to the
      ;; authorization and token URLs as part of the OAuth2
      ;; protocol.  If you would do using a specific browser with
      ;; specific arguments -- for example, because you save your
      ;; credentials in a specific browser profile -- then you can specify
      ;; your preferences here.

      :browser-name \"firefox\"
      :browser-args (\"-P\" \"work\")
    ))
")

;; How to go to the authorization URL
;;
(defvar ac/oauth2-browser-name nil
  "Default `browse-url' function used to access the authentication
URI to get the authentication code as part of the OAuth2
protocol.  This should be a string or `nil', in which case we use
the default `browse-url-function'.

See the example given in the documentation of
`ac/oauth2-accounts', specifically the `:browser-name' keyword.")

(defvar ac/oauth2-browser-args nil
  "Additional arguments to pass to the `browse-url' function
when accessing the authentication URI.  See the example given in
the documentation of `ac/oauth2-accounts', specifically the
`:browser-args' keyword.")

;; Redirection mechanism
;;
(defvar ac/oauth2-redirect-uri-port nil
  "Local port number of the HTTP server that receives the
authentication code.  With a `nil' value, the server uses any
available port number.")

(defvar ac/oauth2-redirect-uri nil
  "URI for the local HTTP server that receives the
authentication code.  When the value is `nil' (default), the
redirection goes to \"http://localhost:PORT/\", where PORT is the
local port of the currently running server.")

(defvar ac/oauth2-redirect-uri-timeout 60
  "Timeout for the HTTP redirection mechanism.
Shut-down the local HTTP server if we do not receive the redirect
request within this number of seconds.")

;; Configuration of the authentication mechanism
;;
(defvar ac/oauth2-authinfo-file "~/.oauth2-authinfo"
  "Where we store the IMAP and SMTP access credentials we
get from the Oauth2 access token.  This is the default file name.  You
can also have a specific an authinfo file for each account defined in
`ac/oauth2-accounts' using the `:authinfo-file' keyword.")

(defvar ac/oauth2-access-token-expiration-time 0)

(require 'auth-source)
(require 'smtpmail)
(require 'oauth2)
(require 'browse-url)
(require 'url-util)

;; We implement a very simplistic HTTP server to receive the code from
;; the redirect-uri mechanism.  These are the variables that hold the
;; essential server data while the server is active.  `nil' means that
;; the server is not active.
;;
(defvar ac/oauth2-srv-server nil)
(defvar ac/oauth2-srv-connection nil)
(defvar ac/oauth2-srv-buffer nil)
(defvar ac/oauth2-srv-timer nil)
(defvar ac/oauth2-srv-code nil)

(defun ac/oauth2-srv-send-http-response (proc code code-text body-text)
  (with-current-buffer ac/oauth2-srv-buffer
    (erase-buffer)
    (let ((html-object (format "<html><body>
<p style=\"font-size:20pt;text-align:center\">
%s
</p>
</body></html>" body-text)))
    (insert
     (format "HTTP/1.1 %d %s\r\n" code code-text)
     "Connection: close\r\n"
     "Content-Type: text/html\r\n"
     (format "Content-Length: %d\r\n" (length html-object))
     "\r\n"
     html-object))
    (process-send-region proc (point-min) (point-max))
    (process-send-eof proc)))

(defun ac/oauth2-srv-path-get-code (path)
  "Get the code from the path query args."
  (if (string-match "\\?" path)
      (cadr (assoc "code" (url-parse-query-string (substring path (match-end 0)))))))

(defun ac/oauth2-srv-filter (proc chunk)
  "Process the HTTP request containing the OAuth2 code and coming from the
URI redirect mechanism."
  (unless ac/oauth2-srv-buffer
    (setq ac/oauth2-srv-buffer (generate-new-buffer " *OAuth2 Get Code Server*")))
  (with-current-buffer ac/oauth2-srv-buffer
    (goto-char (point-max))
    (insert chunk)
    (goto-char (point-min))
    (when (search-forward "\r\n\r\n" nil t)
      (goto-char (point-min))
      (if (looking-at "\\([^ ]+\\) +\\([^ ]+\\) +\\([^\r]+\\)\r\n")
	  (let ((code (ac/oauth2-srv-path-get-code (match-string 2))))
	    (if (not code)
		(ac/oauth2-srv-send-http-response proc 200 "Okay" "No code in redirect uri.")
	      (setq ac/oauth2-srv-code code)
	      (message "Got OAuth2 authorization code.")
	      (ac/oauth2-srv-send-http-response proc 200 "Okay" "Code transferred to Emacs.")))
	(ac/oauth2-srv-send-http-response proc 400 "Bad Request" "Bad request"))
      (ac/oauth2-srv-stop))))

(defun ac/oauth2-srv-accept (server connection message)
  (delete-process server)
  (setq ac/oauth2-srv-connection connection))

(defun ac/oauth2-srv-timeout ()
  (when ac/oauth2-srv-server
    (message "Timeout while getting OAuth2 code.")
    (ac/oauth2-srv-stop)))

(defun ac/oauth2-srv-start ()
  "Start a simplistic HTTP server to catch the authentication CODE
passed thorugh the redirect USI mechanism."
  (interactive)
  (if ac/oauth2-srv-server
      (error "Server already running.")
    (setq ac/oauth2-srv-connection nil)
    (setq ac/oauth2-srv-buffer nil)
    (setq ac/oauth2-srv-code nil)
    (setq ac/oauth2-srv-server (make-network-process
				:name "OAuth2 redirect server"
				:server t
				:host 'local
				:service (or ac/oauth2-redirect-uri-port t)
				:reuseaddr (not (null ac/oauth2-redirect-uri-port))
				:log   'ac/oauth2-srv-accept
				:filter   'ac/oauth2-srv-filter
				:filter-multibyte nil
				:coding   'binary))
    (setq ac/oauth2-srv-timer (run-at-time (format "%d sec" ac/oauth2-redirect-uri-timeout)
					   nil 'ac/oauth2-srv-timeout))))

(defun ac/oauth2-get-redirect-uri ()
  (or ac/oauth2-redirect-uri
      (when ac/oauth2-srv-server
	(format "http://localhost:%d/" (cadr (process-contact ac/oauth2-srv-server))))))

(defun ac/oauth2-srv-stop ()
  (interactive)
  (when ac/oauth2-srv-connection
    (delete-process ac/oauth2-srv-connection)
    (setq ac/oauth2-srv-connection nil))
  (when ac/oauth2-srv-buffer
    (kill-buffer ac/oauth2-srv-buffer)
    (setq ac/oauth2-srv-buffer nil))
  (when ac/oauth2-srv-timer
    (cancel-timer ac/oauth2-srv-timer)
    (setq ac/oauth2-srv-timer nil))
  (when ac/oauth2-srv-server
    (delete-process ac/oauth2-srv-server)
    (setq ac/oauth2-srv-server nil)))

;; 
;;
(defun ac/oauth2-request-authorization (auth-url client-id &optional scope state redirect-uri
						 user-name code-verifier)
  "Request OAuth authorization at AUTH-URL by launching `browse-url'.

This function is a reimplementation of
`oauth2-request-authorization' from `oauth2.el' that directly
returns the code provided by the authentication service through
the browser redirect mechanism."
  (browse-url (concat auth-url
                      (if (string-match-p "\?" auth-url) "&" "?")
                      "client_id=" (url-hexify-string client-id)
                      "&response_type=code"
                      "&redirect_uri=" (url-hexify-string redirect-uri)
                      (if scope (concat "&scope=" (url-hexify-string scope)) "")
                      (if state (concat "&state=" (url-hexify-string state)) "")
		      (if user-name (concat "&login_hint=" (url-hexify-string user-name)))
                      "&access_type=offline"))
  (when ac/oauth2-srv-server
    (message
     (format "Waiting for OAuth2 authorization code through redirect-uri (%d sec)..."
	     ac/oauth2-redirect-uri-timeout))
    (while ac/oauth2-srv-server
      (sit-for .1))
    ac/oauth2-srv-code))

;; The OAuth2 requests use `browse-url' to go to the authentication
;; URL.  We want to be able to customize the way these particular
;; requests are handled.  However, we do not want to affect any other
;; use of the `browse-url' package.  We therefore temporarily switch
;; to our browser function and arguments with
;; `ac/oauth2-browser-push', and then immediately restore the initial
;; values with `ac/oauth2-browser-pop'.
;;
(defvar ac/oauth2-browser-function-prev nil)
(defvar ac/oauth2-browser-args-prev nil)
(defvar ac/oauth2-browser-args-sym nil)
(defun ac/oauth2-browser-push (account)
  "Switch the `browse-url-function' to a preferred one if that is
specified in `account'.  The preferred browser may be given by
the `:browser-name' property in `account'.  For example, if the
`:browser-name' property is \"firefox\", then we set
`browse-url-function' to `browse-url-firefox'.  You may also
specify additional arguments for the browser with the
`:browser-args' property in `account'.  When we're done with the
OAuth2 business, we switch back to the initial values of the
browser and arguments variables with `ac/oauth2-browser-pop'."
  (when-let 
      ((browser-name (or (plist-get account :browser-name) ac/oauth2-browser-name))
       (browser-sym (intern-soft (concat "browse-url-" browser-name))))
    (setq ac/oauth2-browser-function-prev browse-url-browser-function)
    (setq browse-url-browser-function browser-sym)
    (when-let
	((browser-args (or (plist-get account :browser-args) ac/oauth2-browser-args))
	 (browser-args-sym (intern-soft (concat "browse-url-" browser-name "-arguments"))))
      (setq ac/oauth2-browser-args-prev (symbol-value browser-args-sym))
      (setq ac/oauth2-browser-args-sym browser-args-sym)
      (set browser-args-sym browser-args))))

(defun ac/oauth2-browser-pop ()
  (when ac/oauth2-browser-function-prev
    (setq browse-url-browser-function ac/oauth2-browser-function-prev)
    (when ac/oauth2-browser-args-sym
      (set ac/oauth2-browser-args-sym ac/oauth2-browser-args-prev)))
  (setq ac/oauth2-browser-function-prev nil)
  (setq ac/oauth2-browser-args-prev nil)
  (setq ac/oauth2-browser-args-sym nil))

(defun ac/oauth2-get-account (&optional account-id)
  (let ((account (cdr (if (and (stringp account-id) (not (equal account-id "")))
			  (assoc account-id ac/oauth2-accounts)
			(car ac/oauth2-accounts)))))
    (if (not account)
	(error "Could not find OAuth2 Account `%s'" (or account-id "(default)")))
    (mapc (lambda (sym)
	     (if (not (plist-get account sym))
		 (error "Property `%s' is undefined for account `%s'"
			(symbol-name sym) (or account-id "(default)"))))
	   '(:auth-url :token-url :scope :client-id :client-secret))
    account))

(defun ac/oauth2-get-authorization (&rest account-id)
  "Request and store an OAuth2 AUTHORIZATION token.

The account information is taken from `ac/oauth2-accounts'.  If
an account name is given with `account-id', then that account
information is used.  Otherwise, use the first account in
`ac/oauth2-accounts'."
  (interactive "sAccount: ")
  (let ((account (ac/oauth2-get-account account-id)))
    (ac/oauth2-srv-start)
    (ac/oauth2-browser-push account)
    (advice-add 'oauth2-request-authorization :override #'ac/oauth2-request-authorization)
    (unwind-protect
	(oauth2-auth-and-store (plist-get account :auth-url)
			       (plist-get account :token-url)
			       (plist-get account :scope)
			       (plist-get account :client-id)
			       (plist-get account :client-secret)
			       (ac/oauth2-get-redirect-uri)))
    (advice-remove 'oauth2-request-authorization #'ac/oauth2-request-authorization)
    (ac/oauth2-browser-pop)
    (ac/oauth2-srv-stop)))

(defun ac/oauth2-get-access (&optional account-id)
  "Get or refresh and then store an OAuth2 ACCESS token.

The account information is taken from `ac/oauth2-accounts'. If an
account name is given with `account-id', then that account
information is used.  Otherwise, use the first account in
`ac/oauth2-accounts'."
  (interactive "sAccount: ")
  (let ((account (ac/oauth2-get-account account-id)))
    (ac/oauth2-srv-start)
    (ac/oauth2-browser-push account)
    (advice-add 'oauth2-request-authorization :override #'ac/oauth2-request-authorization)
    (unwind-protect
	(let (token access-token)
	  (setq token (oauth2-auth-and-store (plist-get account :auth-url)
					     (plist-get account :token-url)
					     (plist-get account :scope)
					     (plist-get account :client-id)
					     (plist-get account :client-secret)
					     (ac/oauth2-get-redirect-uri)))
	  (unless token
	    (error "Could not get OAuth2 authorization token for account `%s'."
		   (or account-id "(default)")))
	  (setq access-token (oauth2-token-access-token (oauth2-refresh-access token)))
	  (unless access-token
	    (error "Could not get OAuth2 access token for account `%s'."
		   (or account-id "(default)")))
	  (when-let ((access-response (oauth2-token-access-response token))
		     (exp-time (cdr (assoc 'expires_in (oauth2-token-access-response token)))))
	    (setq ac/oauth2-access-token-expiration-time
		  (+ (time-convert (current-time) 'integer) exp-time)))
	  (let ((user (plist-get account :user))
		(authinfo-file (plist-get account :authinfo-file))
		(smtp-host (plist-get account :smtp-host))
		(smtp-port (plist-get account :smtp-port))
		(imap-host (plist-get account :imap-host))
		(imap-port (plist-get account :imap-port)))
	    (unless (or (and smtp-host smtp-port) (and imap-host imap-port))
	      (error "Account `%s' does not specify either IMAP or SMTP host and port." account-id))
	    (with-temp-buffer
	      (when (and smtp-host smtp-port)
		(insert
		 (format "machine %s port %d smtp-auth xoauth2 login %s password \"%s\"\n"
			 smtp-host smtp-port user access-token)))
	      (when (and imap-host imap-port)
		(insert
		 (format "machine %s port %d login %s password \"%s\"\n"
			 imap-host imap-port (plist-get account :user) access-token)))
	      (write-file authinfo-file nil))
	      (unless (member authinfo-file auth-sources)
		(push authinfo-file auth-sources))
	      (setq mail-source-password-cache nil)
	      (auth-source-forget+ :host smtp-host)
	      (auth-source-forget+ :host imap-host)))
      (advice-remove 'oauth2-request-authorization #'ac/oauth2-request-authorization)
      (ac/oauth2-browser-pop)
      (ac/oauth2-srv-stop))))

(defun ac/oauth2-get-access-if-necessary (&optional account-id)
  "Get or refresh, and then store an ACCESS token if the previous
one has expired."
  (interactive "sAccount: ")
  (if (> (time-convert (current-time) 'integer) ac/oauth2-access-token-expiration-time)
      (ac/oauth2-get-access account-id)))

;; Add the XOAUTH2 authentication mechanism to IMAP from imap.el.
;; That mechanism is already implemented for IMAP in nnimap.el and for
;; SMTP in smtpmail.el.  In fact, that is where I essentially got this
;; code.
;;
(require 'imap)

(defun ac/imap-xoauth2-auth (buffer)
  "Login to IMAP server using the XOAUTH2 command."
  (message "imap: Authenticating using XOAUTH2...")
  (imap-send-command
   (concat "AUTHENTICATE XOAUTH2 "
	   (base64-encode-string
            (format "user=%s\001auth=Bearer %s\001\001"
                    (imap-quote-specials imap-username)
                    (imap-quote-specials imap-password))))))

(defun ac/imap-xoauth2-auth-p (buffer)
  (imap-capability 'AUTH=XOAUTH2))

(unless (assoc 'xoauth2 imap-authenticator-alist)
  (push '(xoauth2 ac/imap-xoauth2-auth-p ac/imap-xoauth2-auth) imap-authenticator-alist))

(unless (memq 'xoauth2 imap-authenticators)
  (push 'xoauth2 imap-authenticators))

(unless (memq 'xoauth2 smtpmail-auth-supported)
  (push 'xoauth2 smtpmail-auth-supported))

(provide 'ac-oauth2)
