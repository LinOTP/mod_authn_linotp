
/*
   mod_authn_linotp - Apache module to talk to one time password 
  						solution LinOTP (http://linotp.org)
 
   Copyright 2012 LSE Leading Security Experts GmbH <linotp-community@lsexperts.de>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
   
 * This is module is based on 
 *     mod_authn_otp (http://code.google.com/p/mod-authn-otp/) and
 *     mod_auth_radius (http://freeradius.org/mod_auth_radius/)
 *
 * This module only supports basic authentication
 * It stores the authentication state in a configurable cookie.
 * 
 * TODO:
 *   - use per-server config
 *
 */

#include "apr_lib.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_time.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"
#include "util_md5.h"

#include <time.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>

#include	<curl/curl.h>
//#include	<curl/types.h>  # was removed from libcurl 7.21.7
#include 	<curl/easy.h>

/* Apache backward-compat */
#ifndef AUTHN_PROVIDER_VERSION
#define AUTHN_PROVIDER_VERSION "0"
#endif

/* Module definition */
module AP_MODULE_DECLARE_DATA authn_linotp_module;

/* Our unique authentication provider name */
#define LINOTP_AUTHN_PROVIDER_NAME         "LinOTP"


/* Default configuration settings */
#define DEFAULT_TIMEOUT                 (10 * 60)   /* 10 minutes */
#define DEFAULT_LOG_USER				1
#define DEFAULT_LOG_PASSWORD			0
#define DEFAULT_SSL_CERT_VERIFY			0
#define DEFAULT_SSL_HOSTNAME_VERIFY		0
#define DEFAULT_COOKIE_NAME				"linotp_auth_module"

    
/* Buffer size for OTPs */
#define OTP_BUF_SIZE                    16

/* Per-directory configuration */
struct linotp_config {
    char *validateurl;			/* The validation URL like https://localhost/validate/simplecheck */
	int sslcertverify;	        /* wether the certficate should be checked */
	int sslhostnameverify;		/* wether the hostname in the cert should be checked */
	char *realm;				/* the optional realm name */
	char *resConf;				/* the optional resolver name */
	int loguser;				/* wether the username should be logged */
	int logpassword;			/* wether the password should be logged */
	int timeout;             /* Maximum time for which the OTP is valid */
	char *secret;				/* secret to encrypt the cookie */
  	const char *cookie_name;			/* name of the cookie */
};


/* Internal functions */
static authn_status authn_linotp_check_password(request_rec *r, const char *username, const char *password);
static struct       linotp_config *get_config_dir(request_rec *r);
static void         register_hooks(apr_pool_t *p);
static void         *create_authn_linotp_dir_config(apr_pool_t *p, char *d);
static void         *merge_authn_linotp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf);

/**********************************************************************************
 * 
 * 
 * cookie stuff
 * 
 */
 
#define COOKIE_SIZE 1024
/* make a cookie based on secret + public information */
static char *
make_cookie(request_rec *r, time_t expires, const char *passwd, const char *string)
{
  char one[COOKIE_SIZE], two[COOKIE_SIZE];
  char *cookie = apr_pcalloc(r->pool, COOKIE_SIZE);
  conn_rec *c = r->connection;
  //server_rec *s = r->server;
 
  struct linotp_config *const scr = get_config_dir(r);

  // TODO: This can be used to get the server or directory config
  //ap_get_module_config(s->module_config, &authn_linotp_module);
  const char *hostname;
  
  if ((hostname = ap_get_remote_host(c, r->per_dir_config, REMOTE_NAME, NULL)) == NULL)
    hostname = "no.one@example.com";

  /*
   * Arg! We can't use 'ntohs(c->remote_addr.sin_port)', because I.E.
   * ignores keepalives, and opens a new connection on EVERY request!
   * This is a BAD security problem!  It allows multiple users on the
   * same machine to access the data.
   *
   * A derivative security problem is users authenticating from
   * behind a firewall.
   * All users appear to be coming from the firewall.  A malicious
   * agent working in the same company as the authorized user can sniff
   * the cookie, and and use it themselves.  Since they appear to be
   * coming from the same IP address (firewall), they're let in.
   * Oh well, at least the connection is traceable to a particular machine.
   */

  /*
   *  Piotr Klaban <makler@oryl.man.torun.pl> says:
   *
   *  > The "squid" proxy set HTTP_X_FORWARDED_FOR variable - the
   *  > original IP of the client.  We can use HTTP_X_FORWARDED_FOR
   *  > variable besides REMOTE_ADDR.
   *
   *  > If cookie is stolen, then atacker could use the same proxy as
   *  > the client, to validate the cookie. If we would use
   *  > HTTP_X_FORWARDED_FOR, then useing the proxy would not be
   *  > sufficient.
   *
   *  We don't do this, mainly because I haven't gotten around to
   *  writing the code...
   */

  /*
   * Make a cookie based on secret + public information.
   *
   * cookie = MAC(M) = apr_md5(secret, MD5(secret, M))
   *
   * See Scheier, B, "Applied Cryptography" 2nd Ed., p.458
   * Also, RFC 2104.  I don't know if the HMAC gives any additional
   * benefit here.
   */  
  apr_snprintf(one, COOKIE_SIZE, "%s%s%s%s%s%08x", scr->secret,
	      r->user, passwd, c->remote_ip, hostname, (int)expires);

  /* MD5 the cookie to make it secure, and add more secret information */
  apr_snprintf(two, COOKIE_SIZE, "%s%s", scr->secret, ap_md5(r->pool, one));
  if (string == NULL) {
    apr_snprintf(cookie, COOKIE_SIZE, "%s%08x",
		ap_md5(r->pool, two), (int)expires);
  } else {
    apr_snprintf(cookie, COOKIE_SIZE, "%s%08x%s",
		ap_md5(r->pool, two), (int)expires, string);
  }
  return cookie;
}
static int
valid_cookie(request_rec *r, const char *cookie, const char *passwd)
{
  time_t expires, now;

  if (strlen(cookie) < (16 + 4)*2) { /* MD5 is 16 bytes, and expiry date is 4*/
    return FALSE;		/* invalid */
  }
    
  sscanf(&cookie[32], "%8lx", &expires);

  now = time(NULL);
  if (expires < now) {	/* valid only for a short window of time */
    return FALSE;		/* invalid: expired */
  }

  /* Is the returned cookie identical to one made from our secret? */
  if (strcmp(cookie, make_cookie(r, expires, passwd, NULL)) == 0)
    return TRUE;
  
  return FALSE;			/* cookie doesn't match: re-validate */
}

static void
add_cookie(request_rec *r, apr_table_t *header, char *cookie, time_t expires)
{
	struct linotp_config *const conf = get_config_dir(r);	
	
  char *new_cookie = apr_pcalloc(r->pool, COOKIE_SIZE); /* so it'll stick around */

  if (expires != 0) {
    char buffer[1024];

    strftime(buffer, sizeof(buffer), "%a %d-%b-%Y %H:%M:%S %Z",
	     gmtime(&expires));
    apr_snprintf(new_cookie, 1024, "%s=%s; path=/; expires=%s;",
		conf->cookie_name, cookie, buffer);
  } else {
    apr_snprintf(new_cookie, 1024,
		"%s=%s; path=/; expires=Wed, 01-Oct-97 01:01:01 GMT;",
		conf->cookie_name, cookie);
  }
    
  apr_table_set(header,"Set-Cookie", new_cookie);
}
/* Spot a cookie in an incoming request */
static char *
spot_cookie(request_rec *r)
{
  const char *cookie;
  char *value;
  
  struct linotp_config *const conf = get_config_dir(r);

  if ((cookie = apr_table_get(r->headers_in, "Cookie"))) {
    if ((value=strstr(cookie, conf->cookie_name))) {
      char *cookiebuf, *cookieend;
      ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0,r->server,"Found LinOTP auth Cookie, now check if it's valid...");
      value += strlen(conf->cookie_name); /* skip the name */

      /*
       *  Ensure there's an '=' after the name.
       */
      if (*value != '=') {
	return NULL;
      } else {
	value++;
      }
      
      cookiebuf = apr_pstrdup( r->pool, value );
      cookieend = strchr(cookiebuf,';');
      if (cookieend) *cookieend = '\0';	/* Ignore anything after a ; */
      
      /* Set the cookie in a note, for logging */
      return cookiebuf;          /* Theres already a cookie, no new one */
    }
  }
  return NULL;                        /* no cookie was found */
}


/**********************************************************************************
 * Utils
 * 
 */
 

static int inline valid_char(unsigned char c)
{
	int i;

	/* We disallow anything except known good */
	const char allowed_nonalpha[] = "-_+.@";

	/* a-z */
	if (c >= 'a' && c <= 'z')
		return 1;

	/* A-Z */
	if (c >= 'A' && c <= 'Z')
		return 1;
	
	/* 0-9 */
	if (c >= '0' && c <= '9')
		return 1;

	/* Non-alphanumeric */
	for (i=0; i < sizeof(allowed_nonalpha)-1; i++)
		if (c == allowed_nonalpha[i])
			return 1;

	/* Invalid */
	return 0;
}

static int inline valid_realm_char(unsigned char c)
{
        int i;

        /* We disallow anything except known good */
        const char allowed_nonalpha[] = "-_";

        /* a-z */
        if (c >= 'a' && c <= 'z')
                return 1;

        /* A-Z */
        if (c >= 'A' && c <= 'Z')
                return 1;

        /* 0-9 */
        if (c >= '0' && c <= '9')
                return 1;

        /* Non-alphanumeric */
        for (i=0; i < sizeof(allowed_nonalpha)-1; i++)
                if (c == allowed_nonalpha[i])
                        return 1;

        /* Invalid */
        return 0;
}


#ifndef LINOTP_MAX_USERNAME_LEN
#define LINOTP_MAX_USERNAME_LEN 256
#endif

#ifndef LINOTP_MAX_REALMNAME_LEN
#define LINOTP_MAX_REALMNAME_LEN 256
#endif

// username and password was correct
#define LINOTPD_OK			":-)"
#define LINOTPD_REJECT		":-("
#define LINOTPD_FAIL		":-/"


static int inline valid_username(const char *s)
{
	size_t len = 0;

	while (*s)
	{
		if (!valid_char(*s))
			return 0;

		if (++len >= LINOTP_MAX_USERNAME_LEN)
			return 0;

		++s;
	}

	return 1;
}

static int inline valid_realm(const char *s )
{
	size_t len = 0;
	if (s == NULL)
	{
		return 1;
	}
	while (*s)
	{
		if (!valid_realm_char(*s))
			return 0;
		if (++len >= LINOTP_MAX_REALMNAME_LEN)
			return 0;
		++s;
	}
	return 1;
}

/***********************************************
   Curl stuff
***********************************************/
struct MemoryStruct {
  char *memory;
  size_t size;
};
 
static void *myrealloc(void *ptr, size_t size)
{
	void * ret = NULL;

	if (size > 1024 * 1024)
	{
		ret = NULL;
	}

	/* There might be a realloc() out there that doesn't like reallocing
     NULL pointers, so we take care of it here */ 
	if(ptr)
		ret = realloc(ptr, size);
	else
		ret = malloc(size);

	return ret;
}
 
static size_t WriteMemoryCallback(void *ptr, size_t size, size_t nmemb, void *data)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)data;

	/* failsafe */
	if (realsize > 1024*1024)
	{
		//error("The linotpd responded to our authentication request with more than 1MB of data! Something is really wrong here!");
		return mem->size;
	}

	mem->memory = myrealloc(mem->memory, mem->size + realsize + 1);
	if (mem->memory)
	{
		memcpy(&(mem->memory[mem->size]), ptr, realsize);
		mem->size += realsize;
		mem->memory[mem->size] = 0;
	}
	return realsize;
}




static char * createUrl(request_rec *r, CURL *curl_handle, char * validateurl, char * realm, char * resConf, const char * user, const char * password)
{
	char * 	url 	= NULL;
	char * url2		= NULL;
	int size		= 300;
	int nchars		= 0;

	// escape user and password
	char *escPassword  = curl_easy_escape(curl_handle, password, 0);
	char *escUser      = curl_easy_escape(curl_handle, user, 0);
	char *escRealm;
	char *escResConf;

	if ( realm == NULL )
	{
		escRealm = NULL;
	} else {
		escRealm = curl_easy_escape(curl_handle, realm, 0);
	}
        if ( resConf == NULL )
        {
                escResConf = NULL;
        } else {
                escResConf = curl_easy_escape(curl_handle, realm, 0);
        }

	if (escPassword == NULL || escUser == NULL)
	{
 		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"faild to escape user or password");
 		goto cleanup;
	}

 	url = (char*) malloc (size);
 	if (url == NULL)
 	{
 	    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"could not allocate size for url");
 	    goto cleanup;
 	}

	// allocate the memory for url string
	memset(url,'\0',size);
	if (escRealm == NULL && escResConf == NULL ) 
	{
		nchars = snprintf( url, size-1, "%s?user=%s&pass=%s", validateurl, 
						escUser, escPassword);
	}
	if (escRealm == NULL && escResConf != NULL )
        {
                nchars = snprintf( url, size-1, "%s?user=%s&pass=%s&resConf=%s", validateurl, 
                                                escUser, escPassword, escResConf);
        }
        if (escRealm != NULL && escResConf != NULL )
        {
                nchars = snprintf( url, size-1, "%s?user=%s&pass=%s&resConf=%s&realm=%s", validateurl,
                                                escUser, escPassword, escResConf, escRealm);
        }
        if (escRealm != NULL && escResConf == NULL )
        {
                nchars = snprintf( url, size-1, "%s?user=%s&pass=%s&realm=%s", validateurl,
                                                escUser, escPassword, escRealm);
        }




	if (nchars >= size-1)
	{
		// reallocate
		size = nchars +1;
		url2 = (char*) myrealloc(url, size);
		if (url2 == NULL)
		{
	 	    ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"failed to alloc space for url + user and password");
	 	    free(url);
	 	    url = NULL; // we need to return NULL
	 		goto cleanup;
		}
		
		memset(url,'\0',size);
	        if (escRealm == NULL && escResConf == NULL ) 
	        {
        	        snprintf( url, size-1, "%s?user=%s&pass=%s", validateurl, 
	                                                escUser, escPassword);
        	}
	        if (escRealm == NULL && escResConf != NULL )
	        {
        	        snprintf( url, size-1, "%s?user=%s&pass=%s&resConf=%s", validateurl,
	                                                escUser, escPassword, escResConf);
        	}
	        if (escRealm != NULL && escResConf != NULL )
	        {
	                snprintf( url, size-1, "%s?user=%s&pass=%s&resConf=%s&realm=%s", validateurl,
	                                                escUser, escPassword, escResConf, escRealm);
	        }
	        if (escRealm != NULL && escResConf == NULL )
	        {
	                snprintf( url, size-1, "%s?user=%s&pass=%s&realm=%s", validateurl,
	                                                escUser, escPassword, escRealm);
        	}
	}

cleanup:
	return url;
}
static int sendRequest(request_rec *r, CURL *curl_handle, char * url,
		struct MemoryStruct * chunk)
{
	/*
	 *  url has the complete URL with username and password
	 */

	
    struct linotp_config *const conf = get_config_dir(r);
	int nosslhostnameverify = (!conf->sslhostnameverify);
	int nosslcertverify = (!conf->sslcertverify);
	
	int all_status	= 0;
	int status		= 0;

	all_status	= 0;
 	status 		= curl_easy_setopt(curl_handle, CURLOPT_URL, url);
 	all_status += status;
 	if (status) {
		if ( conf->logpassword && conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_URL %s: %i", url, status);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_URL %s: %i", conf->validateurl, status);
	}
			
 	status 		= curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
 	all_status += status;
 	if (status)
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_WRITEFUNCTION: %i", status);

 	status 		= curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, chunk);
	all_status += status;
 	if (status)
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_WRITEDATA: %i", status);

	status 		= curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	all_status += status;
	if (status)
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_USERAGENT: %i", status);

 	if ( nosslhostnameverify ) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server,"NO SSL hostname verify");
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
	} else {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server,"SSL hostname verify");
		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
	}
	all_status += status;
	if (status) 
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_SSL_VERIFYHOST: %i", status);
	

 	if ( nosslcertverify ) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server,"NO SSL cert verify");
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
	} else {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server,"SSL cert verify");
 		status = curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
 	}
 	all_status += status;
 	if (status) 
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error setting option CURLOPT_SSL_VERIFYPEER: %i", status);

 	status 		= curl_easy_perform(curl_handle);
 	all_status += status;
 	if (status) {
		if ( conf->logpassword && conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error in curl_easy_perform: %i, url: %s", status, url);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server,"Error in curl_easy_perform: %i, url: %s", status, conf->validateurl);
	}
	
 	curl_easy_cleanup(curl_handle);

 	return all_status;

}

/*
 * HTTP basic authentication
 */
static authn_status
authn_linotp_check_password(request_rec *r, const char *username, const char *otp_given)
{
    struct linotp_config *const conf = get_config_dir(r);
    
   	int returnValue		    	= AUTH_GENERAL_ERROR;
    char errorBuffer[CURL_ERROR_SIZE];
	CURL *	curl_handle		= NULL;
	CURLcode all_status		= 0;
	char *cookie;
	time_t expires;
	char *url 			= NULL;
	struct MemoryStruct chunk;
	chunk.memory		= NULL; /* we expect realloc(NULL, size) to work */
	chunk.size 		= 0;    	/* no data at this point */

	curl_global_init(CURL_GLOBAL_ALL);

	/* check for the existence of a cookie: do weak authentication if so */
	if ((cookie = spot_cookie(r)) != NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server, "Found cookie=%s for user=%s : ", cookie, r->user);
		/* valid username, passwd, and expiry date: don't do LinOTP auth */
		if (valid_cookie(r, cookie, otp_given)) {
		  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,"cookie still valid.  Serving page.");
		  returnValue=AUTH_GRANTED;
		  goto cleanup;
		} else {			/* the cookie has probably expired */
		  /* don't bother logging the fact: we probably don't care */
		  add_cookie(r, r->err_headers_out, cookie, 0);
		  ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," invalid or expired. telling browser to delete cookie");
		  returnValue = HTTP_UNAUTHORIZED;
		  goto cleanup;
		}
	} else {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server," No cookie found.  Trying LinOTP authentication.");
	}
    
    /* check if validate url is defined */
    if (conf->validateurl == NULL) {
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "No LinOTPValidateURL defined!");
        returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
	}
	
	if (!username || !otp_given)
	{
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Username or password not given!");
        returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
	}

	if (!valid_username(username))
	{
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Username or password not given!");
		returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
	}

	if ( conf->realm != NULL )
		if (!valid_realm(conf->realm))
		{
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Realm includes invalid characters.");
			returnValue = AUTH_GENERAL_ERROR;
			goto cleanup;
		}

	if ( conf->resConf != NULL )	
	        if (!valid_realm(conf->resConf))
	        {
				ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Realm includes invalid characters!");
				returnValue = AUTH_GENERAL_ERROR;
				goto cleanup;
	        }

	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "Doing curl_easy_init!");
 	curl_handle = curl_easy_init();
 	if (curl_handle == NULL)
 	{
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Could not get curl handle!");
		returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
 	}
 	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorBuffer);

	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "creating the URL.");
	
 	url = createUrl(r, curl_handle, conf->validateurl, conf->realm, conf->resConf, 
			username, otp_given);

	if ( conf->logpassword && conf->loguser )
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "url created: '%s' \n", url);
		

	if (url == NULL)
	{
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "could not allocate size for url!");
		goto cleanup;
	}

	all_status = sendRequest(r, curl_handle, url, (void *)&chunk);

	if (all_status != 0)
	{
		if ( conf->logpassword && conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Error talking to linotpd server %s: %s. See CURLcode in curl.h for detailes (%i)", url, errorBuffer, all_status);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Error talking to linotpd server %s: %s. See CURLcode in curl.h for detailes (%i)", conf->validateurl, errorBuffer, all_status);
		// Error communicating to linotp server
		returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
	}

	/*
	* Now, our chunk.memory points to a memory block that is chunk.size
	* bytes big and contains the remote file.
	* You should be aware of the fact that at this point we might have an
	* allocated data block, and nothing has yet deallocated that data. So when
	* you're done with it, you should free() it as a nice application.
	*/
	if(chunk.memory == NULL)
	{
		if ( conf->logpassword && conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "No response returned for %s: %s", url, errorBuffer);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "No response returned: %s", errorBuffer);
		goto cleanup;
	}

	ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "LinOTPd on %s returned '%s'", conf->validateurl, chunk.memory);

	if (strcmp(chunk.memory, LINOTPD_REJECT) == 0)
	{
		if ( conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Rejecting authentication for user '%s'", username);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Rejecting authentication");
		returnValue	= AUTH_DENIED;
	    goto cleanup;
	}

	if (strcmp(chunk.memory, LINOTPD_FAIL) == 0)
	{
		if ( conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "authentication for '%s' failed", username);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "authentication failed");
		returnValue = AUTH_GENERAL_ERROR;
		goto cleanup;
	}
	if (strcmp(chunk.memory, LINOTPD_OK) == 0)
	{
		if ( conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "user '%s' authenticated successfully", username);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_INFO, 0, r->server, "user authenticated successfully");
		/*
		 *  we also set a cookie now
		 */
		expires = time(NULL) + conf->timeout;
		cookie = make_cookie(r, expires, otp_given, NULL);

		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,"Cookie expiry in %d seconds.", (int) expires);
		ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,"Adding cookie %s\n", cookie);
		add_cookie(r, r->headers_out, cookie, expires);
			
		returnValue = AUTH_GRANTED;
		goto cleanup;
	}
 	{//default
		if ( conf->loguser )
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Rejecting fall-through '%s'", username);
		else
			ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Rejecting fall-through" );
 		returnValue	= AUTH_GENERAL_ERROR;
 		goto cleanup;
 	}

 cleanup:

 	/* we're done with libcurl, so clean it up */ 
	curl_global_cleanup();

	if (url != NULL)
	{
		free(url);
	}
	if (chunk.memory != NULL)
	{
		free(chunk.memory);
	}
	return returnValue;
    
}

/*
 * Get configuration in directory context
 */
static struct linotp_config *
get_config_dir(request_rec *r)
{
    struct linotp_config *dir_conf;
    struct linotp_config *conf;

	 ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_DEBUG, 0, r->server,"get linotp config");

    /* I don't understand this bug: sometimes r->per_dir_config == NULL. Some weird linking problem. */
    if (r->per_dir_config == NULL) {
        ap_log_error(APLOG_MARK, APLOG_NOERRNO | APLOG_ERR, 0, r->server, "Oops, bug detected in mod_authn_linotp: r->per_dir_config == NULL?");
        dir_conf = create_authn_linotp_dir_config(r->pool, NULL);
    } else
        dir_conf = ap_get_module_config(r->per_dir_config, &authn_linotp_module);

    /* Make a copy of the current per-directory config */
    conf = apr_pcalloc(r->pool, sizeof(*conf));
    if (dir_conf->validateurl != NULL)
        conf->validateurl = apr_pstrdup(r->pool, dir_conf->validateurl);
    if (dir_conf->realm != NULL)
        conf->realm = apr_pstrdup(r->pool, dir_conf->realm);
    if (dir_conf->validateurl != NULL)
        conf->resConf = apr_pstrdup(r->pool, dir_conf->resConf);
    if (dir_conf->secret != NULL)
        conf->secret = apr_pstrdup(r->pool, dir_conf->secret);
    if (dir_conf->cookie_name != NULL)
        conf->cookie_name = apr_pstrdup(r->pool, dir_conf->cookie_name);
        
    conf->timeout = dir_conf->timeout;
    conf->loguser = dir_conf->loguser;
    conf->logpassword = dir_conf->logpassword;
    conf->sslcertverify = dir_conf->sslcertverify;
    conf->sslhostnameverify = dir_conf->sslhostnameverify;

    /* Apply defaults for any unset values */
    if (conf->timeout == -1)
        conf->timeout = DEFAULT_TIMEOUT;
    if (conf->loguser == -1)
        conf->loguser = DEFAULT_LOG_USER;
    if (conf->logpassword == -1)
        conf->logpassword = DEFAULT_LOG_PASSWORD;
    if (conf->sslcertverify == -1)
        conf->sslcertverify = DEFAULT_SSL_CERT_VERIFY;
    if (conf->sslhostnameverify == -1)
        conf->sslhostnameverify = DEFAULT_SSL_HOSTNAME_VERIFY;
    if (conf->cookie_name == NULL)
        conf->cookie_name = DEFAULT_COOKIE_NAME;

    /* Done */
    return conf;
}

/*
 * Constructor for per-directory configuration
 */
static void *
create_authn_linotp_dir_config(apr_pool_t *p, char *d)
{
    struct linotp_config *conf = apr_pcalloc(p, sizeof(struct linotp_config));

    conf->timeout = -1;
    conf->logpassword = 0;
    conf->loguser = 0;
    conf->realm = NULL;
    conf->resConf = NULL;
    conf->validateurl = NULL;
    conf->sslcertverify = 0;
    conf->sslhostnameverify = 0;
    conf->secret = NULL;
    conf->cookie_name = NULL;
   
    return conf;
}

static void *
merge_authn_linotp_dir_config(apr_pool_t *p, void *base_conf, void *new_conf)
{
    struct linotp_config *const conf1 = base_conf;
    struct linotp_config *const conf2 = new_conf;
    struct linotp_config *conf = apr_pcalloc(p, sizeof(struct linotp_config));

	if (conf2->cookie_name != NULL)
        conf->cookie_name = apr_pstrdup(p, conf2->cookie_name);
    else if (conf1->cookie_name != NULL)
        conf->cookie_name = apr_pstrdup(p, conf1->cookie_name);
        
    if (conf2->secret != NULL)
        conf->secret = apr_pstrdup(p, conf2->secret);
    else if (conf1->cookie_name != NULL)
        conf->secret = apr_pstrdup(p, conf1->secret);
    

    if (conf2->validateurl != NULL)
        conf->validateurl = apr_pstrdup(p, conf2->validateurl);
    else if (conf1->validateurl != NULL)
        conf->validateurl = apr_pstrdup(p, conf1->validateurl);
        
    if (conf2->realm != NULL)
        conf->realm = apr_pstrdup(p, conf2->realm);
    else if (conf1->realm != NULL)
        conf->realm = apr_pstrdup(p, conf1->realm);
        
    if (conf2->resConf != NULL)
        conf->resConf = apr_pstrdup(p, conf2->resConf);
    else if (conf1->resConf != NULL)
        conf->resConf = apr_pstrdup(p, conf1->resConf);
        
    conf->timeout = conf2->timeout != -1 ? conf2->timeout : conf1->timeout;
    conf->logpassword = conf2->logpassword != -1 ? conf2->logpassword : conf1->logpassword;
    conf->loguser = conf2->loguser != -1 ? conf2->loguser : conf1->loguser;
    conf->sslcertverify = conf2->sslcertverify != -1 ? conf2->sslcertverify : conf1->sslcertverify;
    conf->sslhostnameverify = conf2->sslhostnameverify != -1 ? conf2->sslhostnameverify : conf1->sslhostnameverify;
    
    return conf;
}


/* Authorization provider information */
static const authn_provider authn_linotp_provider =
{
    &authn_linotp_check_password,
    NULL						// No digest Auth
};

static void
register_hooks(apr_pool_t *p)
{
    ap_register_provider(p, AUTHN_PROVIDER_GROUP, LINOTP_AUTHN_PROVIDER_NAME, AUTHN_PROVIDER_VERSION, &authn_linotp_provider);
}

/* Configuration directives */
static const command_rec authn_linotp_cmds[] =
{
    AP_INIT_TAKE1("LinOTPValidateURL",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(struct linotp_config, validateurl),
        OR_AUTHCFG,
        "URL of the LinOTP validation server"),
    AP_INIT_TAKE1("LinOTPRealm",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(struct linotp_config, realm),
        OR_AUTHCFG,
        "The realm name, the user will be authenticated in."),
    AP_INIT_TAKE1("LinOTPResolver",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(struct linotp_config, resConf),
        OR_AUTHCFG,
        "The useridresolver, the user will be authenticated in."),
    AP_INIT_TAKE1("LinOTPCookieSecret",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(struct linotp_config, secret),
        OR_AUTHCFG,
        "A secret that is used to encrypt the cookie."),
    AP_INIT_TAKE1("LinOTPCookieName",
        ap_set_string_slot,
        (void *)APR_OFFSETOF(struct linotp_config, cookie_name),
        OR_AUTHCFG,
        "The name of the cookie"),
    AP_INIT_FLAG("LinOTPSSLCertVerify",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct linotp_config, sslcertverify),
        OR_AUTHCFG,
        "Wether the certificate of the LinOTP server should be verified (0|1)"),
    AP_INIT_FLAG("LinOTPSSLHostVerify",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct linotp_config, sslhostnameverify),
        OR_AUTHCFG,
        "Wether the hostname in the certificate of the LinOTP server should be verified (0|1)"),
	AP_INIT_FLAG("LinOTPLogUser",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct linotp_config, loguser),
        OR_AUTHCFG,
        "Wether the certificate of the LinOTP server should be verified (0|1)"),
    AP_INIT_FLAG("LinOTPLogPassword",
        ap_set_flag_slot,
        (void *)APR_OFFSETOF(struct linotp_config, logpassword),
        OR_AUTHCFG,
        "Wether the certificate of the LinOTP server should be verified (0|1)"),
    AP_INIT_TAKE1("LinOTPTimeout",
		ap_set_int_slot,
		(void *)APR_OFFSETOF(struct linotp_config, timeout),
        OR_AUTHCFG,
        "maximum time (in seconds) for which a one-time password is valid"),


    { NULL }
};

/* Module declaration */
module AP_MODULE_DECLARE_DATA authn_linotp_module = {
    STANDARD20_MODULE_STUFF,
    create_authn_linotp_dir_config,        /* create per-dir config */
    merge_authn_linotp_dir_config,         /* merge per-dir config */
    NULL,                               /* create per-server config */
    NULL,                               /* merge per-server config */
    authn_linotp_cmds,                     /* command apr_table_t */
    register_hooks                      /* register hooks */
};

