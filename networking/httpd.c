/* vi: set sw=4 ts=4: */
/*
 * httpd implementation for busybox
 *
 * Copyright (C) 2002,2003 Glenn Engel <glenne@engel.org>
 * Copyright (C) 2003-2006 Vladimir Oleynik <dzo@simtreas.ru>
 *
 * simplify patch stolen from libbb without using strdup
 *
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 *
 *****************************************************************************
 *
 * Typical usage:
 *   for non root user
 * httpd -p 8080 -h $HOME/public_html
 *   or for daemon start from rc script with uid=0:
 * httpd -u www
 * This is equivalent if www user have uid=80 to
 * httpd -p 80 -u 80 -h /www -c /etc/httpd.conf -r "Web Server Authentication"
 *
 *
 * When a url contains "cgi-bin" it is assumed to be a cgi script.  The
 * server changes directory to the location of the script and executes it
 * after setting QUERY_STRING and other environment variables.
 *
 * The server can also be invoked as a url arg decoder and html text encoder
 * as follows:
 *  foo=`httpd -d $foo`           # decode "Hello%20World" as "Hello World"
 *  bar=`httpd -e "<Hello World>"`  # encode as "&#60Hello&#32World&#62"
 * Note that url encoding for arguments is not the same as html encoding for
 * presentation.  -d decodes a url-encoded argument while -e encodes in html
 * for page display.
 *
 * httpd.conf has the following format:
 *
 * A:172.20.         # Allow address from 172.20.0.0/16
 * A:10.0.0.0/25     # Allow any address from 10.0.0.0-10.0.0.127
 * A:10.0.0.0/255.255.255.128  # Allow any address that previous set
 * A:127.0.0.1       # Allow local loopback connections
 * D:*               # Deny from other IP connections
 * /cgi-bin:foo:bar  # Require user foo, pwd bar on urls starting with /cgi-bin/
 * /adm:admin:setup  # Require user admin, pwd setup on urls starting with /adm/
 * /adm:toor:PaSsWd  # or user toor, pwd PaSsWd on urls starting with /adm/
 * .au:audio/basic   # additional mime type for audio.au files
 * *.php:/path/php   # running cgi.php scripts through an interpreter
 *
 * A/D may be as a/d or allow/deny - first char case insensitive
 * Deny IP rules take precedence over allow rules.
 *
 *
 * The Deny/Allow IP logic:
 *
 *  - Default is to allow all.  No addresses are denied unless
 *         denied with a D: rule.
 *  - Order of Deny/Allow rules is significant
 *  - Deny rules take precedence over allow rules.
 *  - If a deny all rule (D:*) is used it acts as a catch-all for unmatched
 *       addresses.
 *  - Specification of Allow all (A:*) is a no-op
 *
 * Example:
 *   1. Allow only specified addresses
 *     A:172.20          # Allow any address that begins with 172.20.
 *     A:10.10.          # Allow any address that begins with 10.10.
 *     A:127.0.0.1       # Allow local loopback connections
 *     D:*               # Deny from other IP connections
 *
 *   2. Only deny specified addresses
 *     D:1.2.3.        # deny from 1.2.3.0 - 1.2.3.255
 *     D:2.3.4.        # deny from 2.3.4.0 - 2.3.4.255
 *     A:*             # (optional line added for clarity)
 *
 * If a sub directory contains a config file it is parsed and merged with
 * any existing settings as if it was appended to the original configuration.
 *
 * subdir paths are relative to the containing subdir and thus cannot
 * affect the parent rules.
 *
 * Note that since the sub dir is parsed in the forked thread servicing the
 * subdir http request, any merge is discarded when the process exits.  As a
 * result, the subdir settings only have a lifetime of a single request.
 *
 *
 * If -c is not set, an attempt will be made to open the default
 * root configuration file.  If -c is set and the file is not found, the
 * server exits with an error.
 *
*/


#include <stdio.h>
#include <ctype.h>         /* for isspace           */
#include <string.h>
#include <stdlib.h>        /* for malloc            */
#include <time.h>
#include <unistd.h>        /* for close             */
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>    /* for connect and socket*/
#include <netinet/in.h>    /* for sockaddr_in       */
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>         /* for open modes        */
#include "busybox.h"


static const char httpdVersion[] = "busybox httpd/1.35 6-Oct-2004";
static const char default_path_httpd_conf[] = "/etc";
static const char httpd_conf[] = "httpd.conf";
static const char home[] = "./";

#ifdef CONFIG_LFS
# define cont_l_fmt "%lld"
# define cont_l_type (long long)
#else
# define cont_l_fmt "%ld"
# define cont_l_type (long)
#endif

#define TIMEOUT 60

// Note: busybox xfuncs are not used because we want the server to keep running
//       if something bad happens due to a malformed user request.
//       As a result, all memory allocation after daemonize
//       is checked rigorously

//#define DEBUG 1

#ifndef DEBUG
# define DEBUG 0
#endif

#define MAX_MEMORY_BUFF 8192    /* IO buffer */

typedef struct HT_ACCESS {
	char *after_colon;
	struct HT_ACCESS *next;
	char before_colon[1];         /* really bigger, must last */
} Htaccess;

typedef struct HT_ACCESS_IP {
	unsigned int ip;
	unsigned int mask;
	int allow_deny;
	struct HT_ACCESS_IP *next;
} Htaccess_IP;

typedef struct
{
  char buf[MAX_MEMORY_BUFF];

  USE_FEATURE_HTTPD_BASIC_AUTH(const char *realm;)
  USE_FEATURE_HTTPD_BASIC_AUTH(char *remoteuser;)

  const char *query;

  USE_FEATURE_HTTPD_CGI(char *referer;)

  const char *configFile;

  unsigned int rmt_ip;
#if defined(CONFIG_FEATURE_HTTPD_CGI) || DEBUG
  char rmt_ip_str[16];     /* for set env REMOTE_ADDR */
#endif
  unsigned port;           /* server initial port and for
			      set env REMOTE_PORT */
  union HTTPD_FOUND {
	const char *found_mime_type;
	const char *found_moved_temporarily;
  } httpd_found;

  off_t ContentLength;          /* -1 - unknown */
  time_t last_mod;

  Htaccess_IP *ip_a_d;          /* config allow/deny lines */
  int flg_deny_all;
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  Htaccess *auth;               /* config user:password lines */
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
  Htaccess *mime_a;             /* config mime types */
#endif

#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
  int accepted_socket;
# define a_c_r config->accepted_socket
# define a_c_w config->accepted_socket
#else
# define a_c_r 0
# define a_c_w 1
#endif
  volatile int alarm_signaled;

#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
  Htaccess *script_i;           /* config script interpreters */
#endif
} HttpdConfig;

static HttpdConfig *config;

static const char request_GET[] = "GET";    /* size algorithmic optimize */

static const char* const suffixTable [] = {
/* Warning: shorted equivalent suffix in one line must be first */
  ".htm.html", "text/html",
  ".jpg.jpeg", "image/jpeg",
  ".gif", "image/gif",
  ".png", "image/png",
  ".txt.h.c.cc.cpp", "text/plain",
  ".css", "text/css",
  ".wav", "audio/wav",
  ".avi", "video/x-msvideo",
  ".qt.mov", "video/quicktime",
  ".mpe.mpeg", "video/mpeg",
  ".mid.midi", "audio/midi",
  ".mp3", "audio/mpeg",
#if 0                        /* unpopular */
  ".au", "audio/basic",
  ".pac", "application/x-ns-proxy-autoconfig",
  ".vrml.wrl", "model/vrml",
#endif
  0, "application/octet-stream" /* default */
  };

typedef enum
{
  HTTP_OK = 200,
  HTTP_MOVED_TEMPORARILY = 302,
  HTTP_BAD_REQUEST = 400,       /* malformed syntax */
  HTTP_UNAUTHORIZED = 401, /* authentication needed, respond with auth hdr */
  HTTP_NOT_FOUND = 404,
  HTTP_FORBIDDEN = 403,
  HTTP_REQUEST_TIMEOUT = 408,
  HTTP_NOT_IMPLEMENTED = 501,   /* used for unrecognized requests */
  HTTP_INTERNAL_SERVER_ERROR = 500,
#if 0 /* future use */
  HTTP_CONTINUE = 100,
  HTTP_SWITCHING_PROTOCOLS = 101,
  HTTP_CREATED = 201,
  HTTP_ACCEPTED = 202,
  HTTP_NON_AUTHORITATIVE_INFO = 203,
  HTTP_NO_CONTENT = 204,
  HTTP_MULTIPLE_CHOICES = 300,
  HTTP_MOVED_PERMANENTLY = 301,
  HTTP_NOT_MODIFIED = 304,
  HTTP_PAYMENT_REQUIRED = 402,
  HTTP_BAD_GATEWAY = 502,
  HTTP_SERVICE_UNAVAILABLE = 503, /* overload, maintenance */
  HTTP_RESPONSE_SETSIZE=0xffffffff
#endif
} HttpResponseNum;

typedef struct
{
  HttpResponseNum type;
  const char *name;
  const char *info;
} HttpEnumString;

static const HttpEnumString httpResponseNames[] = {
  { HTTP_OK, "OK", NULL },
  { HTTP_MOVED_TEMPORARILY, "Found", "Directories must end with a slash." },
  { HTTP_REQUEST_TIMEOUT, "Request Timeout",
    "No request appeared within a reasonable time period." },
  { HTTP_NOT_IMPLEMENTED, "Not Implemented",
    "The requested method is not recognized by this server." },
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  { HTTP_UNAUTHORIZED, "Unauthorized", "" },
#endif
  { HTTP_NOT_FOUND, "Not Found",
    "The requested URL was not found on this server." },
  { HTTP_BAD_REQUEST, "Bad Request", "Unsupported method." },
  { HTTP_FORBIDDEN, "Forbidden", "" },
  { HTTP_INTERNAL_SERVER_ERROR, "Internal Server Error",
    "Internal Server Error" },
#if 0                               /* not implemented */
  { HTTP_CREATED, "Created" },
  { HTTP_ACCEPTED, "Accepted" },
  { HTTP_NO_CONTENT, "No Content" },
  { HTTP_MULTIPLE_CHOICES, "Multiple Choices" },
  { HTTP_MOVED_PERMANENTLY, "Moved Permanently" },
  { HTTP_NOT_MODIFIED, "Not Modified" },
  { HTTP_BAD_GATEWAY, "Bad Gateway", "" },
  { HTTP_SERVICE_UNAVAILABLE, "Service Unavailable", "" },
#endif
};


static const char RFC1123FMT[] = "%a, %d %b %Y %H:%M:%S GMT";
static const char Content_length[] = "Content-length:";


static int
scan_ip (const char **ep, unsigned int *ip, unsigned char endc)
{
  const char *p = *ep;
  int auto_mask = 8;
  int j;

  *ip = 0;
  for (j = 0; j < 4; j++) {
	unsigned int octet;

	if ((*p < '0' || *p > '9') && (*p != '/' || j == 0) && *p != 0)
	  return -auto_mask;
	octet = 0;
	while (*p >= '0' && *p <= '9') {
	  octet *= 10;
	  octet += *p - '0';
	  if (octet > 255)
		return -auto_mask;
	  p++;
	}
	if (*p == '.')
	  p++;
	if (*p != '/' && *p != 0)
	  auto_mask += 8;
	*ip = ((*ip) << 8) | octet;
  }
  if (*p != 0) {
	if (*p != endc)
		return -auto_mask;
	p++;
	if(*p == 0)
		return -auto_mask;
  }
  *ep = p;
  return auto_mask;
}

static int
scan_ip_mask (const char *ipm, unsigned int *ip, unsigned int *mask)
{
  int i;
  unsigned int msk;

  i = scan_ip(&ipm, ip, '/');
  if(i < 0)
	return i;
  if(*ipm) {
	const char *p = ipm;

	i = 0;
	while (*p) {
		if (*p < '0' || *p > '9') {
			if (*p == '.') {
				i = scan_ip (&ipm, mask, 0);
				return i != 32;
			}
			return -1;
		}
		i *= 10;
		i += *p - '0';
		p++;
	}
  }
  if (i > 32 || i < 0)
	  return -1;
  msk = 0x80000000;
  *mask = 0;
  while (i > 0) {
	*mask |= msk;
	msk >>= 1;
	i--;
  }
  return 0;
}

#if defined(CONFIG_FEATURE_HTTPD_BASIC_AUTH) || defined(CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES)
static void free_config_lines(Htaccess **pprev)
{
    Htaccess *prev = *pprev;

    while( prev ) {
	Htaccess *cur = prev;

	prev = cur->next;
	free(cur);
    }
    *pprev = NULL;
}
#endif

/* flag */
#define FIRST_PARSE          0
#define SUBDIR_PARSE         1
#define SIGNALED_PARSE       2
#define FIND_FROM_HTTPD_ROOT 3
/****************************************************************************
 *
 > $Function: parse_conf()
 *
 * $Description: parse configuration file into in-memory linked list.
 *
 * The first non-white character is examined to determine if the config line
 * is one of the following:
 *    .ext:mime/type   # new mime type not compiled into httpd
 *    [adAD]:from      # ip address allow/deny, * for wildcard
 *    /path:user:pass  # username/password
 *
 * Any previous IP rules are discarded.
 * If the flag argument is not SUBDIR_PARSE then all /path and mime rules
 * are also discarded.  That is, previous settings are retained if flag is
 * SUBDIR_PARSE.
 *
 * $Parameters:
 *      (const char *) path . . null for ip address checks, path for password
 *                              checks.
 *      (int) flag  . . . . . . the source of the parse request.
 *
 * $Return: (None)
 *
 ****************************************************************************/
static void parse_conf(const char *path, int flag)
{
    FILE *f;
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
    Htaccess *prev, *cur;
#elif CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
    Htaccess *cur;
#endif

    const char *cf = config->configFile;
    char buf[160];
    char *p0 = NULL;
    char *c, *p;

    /* free previous ip setup if present */
    Htaccess_IP *pip = config->ip_a_d;

    while( pip ) {
	Htaccess_IP *cur_ipl = pip;

	pip = cur_ipl->next;
	free(cur_ipl);
    }
    config->ip_a_d = NULL;

    config->flg_deny_all = 0;

#if defined(CONFIG_FEATURE_HTTPD_BASIC_AUTH) || defined(CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES) || defined(CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR)
    /* retain previous auth and mime config only for subdir parse */
    if(flag != SUBDIR_PARSE) {
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
	free_config_lines(&config->auth);
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
	free_config_lines(&config->mime_a);
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
	free_config_lines(&config->script_i);
#endif
    }
#endif

    if(flag == SUBDIR_PARSE || cf == NULL) {
	cf = alloca(strlen(path) + sizeof(httpd_conf) + 2);
	if(cf == NULL) {
	    if(flag == FIRST_PARSE)
		bb_error_msg_and_die(bb_msg_memory_exhausted);
	    return;
	}
	sprintf((char *)cf, "%s/%s", path, httpd_conf);
    }

    while((f = fopen(cf, "r")) == NULL) {
	if(flag == SUBDIR_PARSE || flag == FIND_FROM_HTTPD_ROOT) {
	    /* config file not found, no changes to config */
	    return;
	}
	if(config->configFile && flag == FIRST_PARSE) /* if -c option given */
	    bb_perror_msg_and_die("%s", cf);
	flag = FIND_FROM_HTTPD_ROOT;
	cf = httpd_conf;
    }

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
    prev = config->auth;
#endif
    /* This could stand some work */
    while ( (p0 = fgets(buf, sizeof(buf), f)) != NULL) {
	c = NULL;
	for(p = p0; *p0 != 0 && *p0 != '#'; p0++) {
		if(!isspace(*p0)) {
		    *p++ = *p0;
		    if(*p0 == ':' && c == NULL)
			c = p;
		}
	}
	*p = 0;

	/* test for empty or strange line */
	if (c == NULL || *c == 0)
	    continue;
	p0 = buf;
	if(*p0 == 'd')
	    *p0 = 'D';
	if(*c == '*') {
	    if(*p0 == 'D') {
		/* memorize deny all */
		config->flg_deny_all++;
	    }
	    /* skip default other "word:*" config lines */
	    continue;
	}

	if(*p0 == 'a')
	    *p0 = 'A';
	else if(*p0 != 'D' && *p0 != 'A'
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
	   && *p0 != '/'
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
	   && *p0 != '.'
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
	   && *p0 != '*'
#endif
	  )
	       continue;
	if(*p0 == 'A' || *p0 == 'D') {
		/* storing current config IP line */
		pip = calloc(1, sizeof(Htaccess_IP));
		if(pip) {
		    if(scan_ip_mask (c, &(pip->ip), &(pip->mask))) {
			/* syntax IP{/mask} error detected, protect all */
			*p0 = 'D';
			pip->mask = 0;
		    }
		    pip->allow_deny = *p0;
		    if(*p0 == 'D') {
			/* Deny:form_IP move top */
			pip->next = config->ip_a_d;
			config->ip_a_d = pip;
		    } else {
			/* add to bottom A:form_IP config line */
			Htaccess_IP *prev_IP = config->ip_a_d;

			if(prev_IP == NULL) {
				config->ip_a_d = pip;
			} else {
				while(prev_IP->next)
					prev_IP = prev_IP->next;
				prev_IP->next = pip;
			}
		    }
		}
		continue;
	}
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
	if(*p0 == '/') {
	    /* make full path from httpd root / curent_path / config_line_path */
	    cf = flag == SUBDIR_PARSE ? path : "";
	    p0 = malloc(strlen(cf) + (c - buf) + 2 + strlen(c));
	    if(p0 == NULL)
		continue;
	    c[-1] = 0;
	    sprintf(p0, "/%s%s", cf, buf);

	    /* another call bb_simplify_path */
	    cf = p = p0;

	    do {
		    if (*p == '/') {
			if (*cf == '/') {    /* skip duplicate (or initial) slash */
			    continue;
			} else if (*cf == '.') {
			    if (cf[1] == '/' || cf[1] == 0) { /* remove extra '.' */
				continue;
			    } else if ((cf[1] == '.') && (cf[2] == '/' || cf[2] == 0)) {
				++cf;
				if (p > p0) {
				    while (*--p != '/');    /* omit previous dir */
				}
				continue;
			    }
			}
		    }
		    *++p = *cf;
	    } while (*++cf);

	    if ((p == p0) || (*p != '/')) {      /* not a trailing slash */
		++p;                             /* so keep last character */
	    }
	    *p = 0;
	    sprintf(p0, "%s:%s", p0, c);
	}
#endif

#if defined(CONFIG_FEATURE_HTTPD_BASIC_AUTH) || defined(CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES) || defined(CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR)
	/* storing current config line */
	cur = calloc(1, sizeof(Htaccess) + strlen(p0));
	if(cur) {
	    cf = strcpy(cur->before_colon, p0);
	    c = strchr(cf, ':');
	    *c++ = 0;
	    cur->after_colon = c;
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
	    if(*cf == '.') {
		/* config .mime line move top for overwrite previous */
		cur->next = config->mime_a;
		config->mime_a = cur;
		continue;
	    }
#endif
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
	    if(*cf == '*' && cf[1] == '.') {
		/* config script interpreter line move top for overwrite previous */
		cur->next = config->script_i;
		config->script_i = cur;
		continue;
	    }
#endif
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
	    free(p0);
	    if(prev == NULL) {
		/* first line */
		config->auth = prev = cur;
	    } else {
		/* sort path, if current lenght eq or bigger then move up */
		Htaccess *prev_hti = config->auth;
		size_t l = strlen(cf);
		Htaccess *hti;

		for(hti = prev_hti; hti; hti = hti->next) {
		    if(l >= strlen(hti->before_colon)) {
			/* insert before hti */
			cur->next = hti;
			if(prev_hti != hti) {
			    prev_hti->next = cur;
			} else {
			    /* insert as top */
			    config->auth = cur;
			}
			break;
		    }
		    if(prev_hti != hti)
			    prev_hti = prev_hti->next;
		}
		if(!hti)  {       /* not inserted, add to bottom */
		    prev->next = cur;
		    prev = cur;
		}
	    }
#endif
	}
#endif
   }
   fclose(f);
}

#ifdef CONFIG_FEATURE_HTTPD_ENCODE_URL_STR
/****************************************************************************
 *
 > $Function: encodeString()
 *
 * $Description: Given a string, html encode special characters.
 *   This is used for the -e command line option to provide an easy way
 *   for scripts to encode result data without confusing browsers.  The
 *   returned string pointer is memory allocated by malloc().
 *
 * $Parameters:
 *      (const char *) string . . The first string to encode.
 *
 * $Return: (char *) . . . .. . . A pointer to the encoded string.
 *
 * $Errors: Returns a null string ("") if memory is not available.
 *
 ****************************************************************************/
static char *encodeString(const char *string)
{
  /* take the simple route and encode everything */
  /* could possibly scan once to get length.     */
  int len = strlen(string);
  char *out = malloc(len * 6 + 1);
  char *p=out;
  char ch;

  if (!out) return "";
  while ((ch = *string++)) {
    // very simple check for what to encode
    if (isalnum(ch)) *p++ = ch;
    else p += sprintf(p, "&#%d;", (unsigned char) ch);
  }
  *p=0;
  return out;
}
#endif          /* CONFIG_FEATURE_HTTPD_ENCODE_URL_STR */

/****************************************************************************
 *
 > $Function: decodeString()
 *
 * $Description: Given a URL encoded string, convert it to plain ascii.
 *   Since decoding always makes strings smaller, the decode is done in-place.
 *   Thus, callers should strdup() the argument if they do not want the
 *   argument modified.  The return is the original pointer, allowing this
 *   function to be easily used as arguments to other functions.
 *
 * $Parameters:
 *      (char *) string . . . The first string to decode.
 *      (int)    flag   . . . 1 if require decode '+' as ' ' for CGI
 *
 * $Return: (char *)  . . . . A pointer to the decoded string (same as input).
 *
 * $Errors: None
 *
 ****************************************************************************/
static char *decodeString(char *orig, int flag_plus_to_space)
{
  /* note that decoded string is always shorter than original */
  char *string = orig;
  char *ptr = string;

  while (*ptr)
  {
    if (*ptr == '+' && flag_plus_to_space)    { *string++ = ' '; ptr++; }
    else if (*ptr != '%') *string++ = *ptr++;
    else  {
      unsigned int value1, value2;

      ptr++;
      if(sscanf(ptr, "%1X", &value1) != 1 ||
				sscanf(ptr+1, "%1X", &value2) != 1) {
	if(!flag_plus_to_space)
		return NULL;
	*string++ = '%';
      } else {
	value1 = value1 * 16 + value2;
	if(value1 == '/' || value1 == 0)
		return orig+1;
	*string++ = value1;
	ptr += 2;
      }
    }
  }
  *string = '\0';
  return orig;
}


#ifdef CONFIG_FEATURE_HTTPD_CGI
/****************************************************************************
 *
 > $Function: addEnv()
 *
 * $Description: Add an environment variable setting to the global list.
 *    A NAME=VALUE string is allocated, filled, and added to the list of
 *    environment settings passed to the cgi execution script.
 *
 * $Parameters:
 *  (char *) name_before_underline - The first part environment variable name.
 *  (char *) name_after_underline  - The second part environment variable name.
 *  (char *) value  . . The value to which the env variable is set.
 *
 * $Return: (void)
 *
 * $Errors: Silently returns if the env runs out of space to hold the new item
 *
 ****************************************************************************/
static void addEnv(const char *name_before_underline,
			const char *name_after_underline, const char *value)
{
  char *s = NULL;
  const char *underline;

  if (!value)
	value = "";
  underline = *name_after_underline ? "_" : "";
  asprintf(&s, "%s%s%s=%s", name_before_underline, underline,
					name_after_underline, value);
  if(s) {
    putenv(s);
  }
}

#if defined(CONFIG_FEATURE_HTTPD_SET_REMOTE_PORT_TO_ENV) || defined(CONFIG_FEATURE_HTTPD_WITHOUT_INETD)
/* set environs SERVER_PORT and REMOTE_PORT */
static void addEnvPort(const char *port_name)
{
      char buf[16];

      sprintf(buf, "%u", config->port);
      addEnv(port_name, "PORT", buf);
}
#endif
#endif          /* CONFIG_FEATURE_HTTPD_CGI */


#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
/****************************************************************************
 *
 > $Function: decodeBase64()
 *
 > $Description: Decode a base 64 data stream as per rfc1521.
 *    Note that the rfc states that none base64 chars are to be ignored.
 *    Since the decode always results in a shorter size than the input, it is
 *    OK to pass the input arg as an output arg.
 *
 * $Parameter:
 *      (char *) Data . . . . A pointer to a base64 encoded string.
 *                            Where to place the decoded data.
 *
 * $Return: void
 *
 * $Errors: None
 *
 ****************************************************************************/
static void decodeBase64(char *Data)
{

  const unsigned char *in = (const unsigned char *)Data;
  // The decoded size will be at most 3/4 the size of the encoded
  unsigned long ch = 0;
  int i = 0;

  while (*in) {
    int t = *in++;

    if(t >= '0' && t <= '9')
	t = t - '0' + 52;
    else if(t >= 'A' && t <= 'Z')
	t = t - 'A';
    else if(t >= 'a' && t <= 'z')
	t = t - 'a' + 26;
    else if(t == '+')
	t = 62;
    else if(t == '/')
	t = 63;
    else if(t == '=')
	t = 0;
    else
	continue;

    ch = (ch << 6) | t;
    i++;
    if (i == 4) {
	*Data++ = (char) (ch >> 16);
	*Data++ = (char) (ch >> 8);
	*Data++ = (char) ch;
	i = 0;
    }
  }
  *Data = 0;
}
#endif


#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
/****************************************************************************
 *
 > $Function: openServer()
 *
 * $Description: create a listen server socket on the designated port.
 *
 * $Return: (int)  . . . A connection socket. -1 for errors.
 *
 * $Errors: None
 *
 ****************************************************************************/
static int openServer(void)
{
  struct sockaddr_in lsocket;
  int fd;
  int on = 1;

  /* create the socket right now */
  /* inet_addr() returns a value that is already in network order */
  memset(&lsocket, 0, sizeof(lsocket));
  lsocket.sin_family = AF_INET;
  lsocket.sin_addr.s_addr = INADDR_ANY;
  lsocket.sin_port = htons(config->port);
  fd = bb_xsocket(AF_INET, SOCK_STREAM, 0);
  /* tell the OS it's OK to reuse a previous address even though */
  /* it may still be in a close down state.  Allows bind to succeed. */
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *)&on, sizeof(on)) ;
#else
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&on, sizeof(on)) ;
#endif
  bb_xbind(fd, (struct sockaddr *)&lsocket, sizeof(lsocket));
  listen(fd, 9); /* bb_xlisten? */
  signal(SIGCHLD, SIG_IGN);   /* prevent zombie (defunct) processes */
  return fd;
}
#endif  /* CONFIG_FEATURE_HTTPD_WITHOUT_INETD */

/****************************************************************************
 *
 > $Function: sendHeaders()
 *
 * $Description: Create and send HTTP response headers.
 *   The arguments are combined and sent as one write operation.  Note that
 *   IE will puke big-time if the headers are not sent in one packet and the
 *   second packet is delayed for any reason.
 *
 * $Parameter:
 *      (HttpResponseNum) responseNum . . . The result code to send.
 *
 * $Return: (int)  . . . . writing errors
 *
 ****************************************************************************/
static int sendHeaders(HttpResponseNum responseNum)
{
  char *buf = config->buf;
  const char *responseString = "";
  const char *infoString = 0;
  const char *mime_type;
  unsigned int i;
  time_t timer = time(0);
  char timeStr[80];
  int len;

  for (i = 0;
	i < (sizeof(httpResponseNames)/sizeof(httpResponseNames[0])); i++) {
		if (httpResponseNames[i].type == responseNum) {
			responseString = httpResponseNames[i].name;
			infoString = httpResponseNames[i].info;
			break;
		}
  }
  /* error message is HTML */
  mime_type = responseNum == HTTP_OK ?
		config->httpd_found.found_mime_type : "text/html";

  /* emit the current date */
  strftime(timeStr, sizeof(timeStr), RFC1123FMT, gmtime(&timer));
  len = sprintf(buf,
	"HTTP/1.0 %d %s\r\nContent-type: %s\r\n"
	"Date: %s\r\nConnection: close\r\n",
	  responseNum, responseString, mime_type, timeStr);

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  if (responseNum == HTTP_UNAUTHORIZED) {
    len += sprintf(buf+len, "WWW-Authenticate: Basic realm=\"%s\"\r\n",
							    config->realm);
  }
#endif
  if(responseNum == HTTP_MOVED_TEMPORARILY) {
	len += sprintf(buf+len, "Location: %s/%s%s\r\n",
		config->httpd_found.found_moved_temporarily,
		(config->query ? "?" : ""),
		(config->query ? config->query : ""));
  }

  if (config->ContentLength != -1) {    /* file */
    strftime(timeStr, sizeof(timeStr), RFC1123FMT, gmtime(&config->last_mod));
    len += sprintf(buf+len, "Last-Modified: %s\r\n%s " cont_l_fmt "\r\n",
			      timeStr, Content_length, cont_l_type config->ContentLength);
  }
  strcat(buf, "\r\n");
  len += 2;
  if (infoString) {
    len += sprintf(buf+len,
	    "<HEAD><TITLE>%d %s</TITLE></HEAD>\n"
	    "<BODY><H1>%d %s</H1>\n%s\n</BODY>\n",
	    responseNum, responseString,
	    responseNum, responseString, infoString);
  }
#if DEBUG
  fprintf(stderr, "Headers: '%s'", buf);
#endif
  return bb_full_write(a_c_w, buf, len);
}

/****************************************************************************
 *
 > $Function: getLine()
 *
 * $Description: Read from the socket until an end of line char found.
 *
 *   Characters are read one at a time until an eol sequence is found.
 *
 * $Return: (int) . . . . number of characters read.  -1 if error.
 *
 ****************************************************************************/
static int getLine(void)
{
  int  count = 0;
  char *buf = config->buf;

  while (read(a_c_r, buf + count, 1) == 1) {
    if (buf[count] == '\r') continue;
    if (buf[count] == '\n') {
      buf[count] = 0;
      return count;
    }
    if(count < (MAX_MEMORY_BUFF-1))      /* check owerflow */
	count++;
  }
  if (count) return count;
  else return -1;
}

#ifdef CONFIG_FEATURE_HTTPD_CGI
/****************************************************************************
 *
 > $Function: sendCgi()
 *
 * $Description: Execute a CGI script and send it's stdout back
 *
 *   Environment variables are set up and the script is invoked with pipes
 *   for stdin/stdout.  If a post is being done the script is fed the POST
 *   data in addition to setting the QUERY_STRING variable (for GETs or POSTs).
 *
 * $Parameters:
 *      (const char *) url . . . . . . The requested URL (with leading /).
 *      (int bodyLen)  . . . . . . . . Length of the post body.
 *      (const char *cookie) . . . . . For set HTTP_COOKIE.
 *      (const char *content_type) . . For set CONTENT_TYPE.

 *
 * $Return: (char *)  . . . . A pointer to the decoded string (same as input).
 *
 * $Errors: None
 *
 ****************************************************************************/
static int sendCgi(const char *url,
		   const char *request, int bodyLen, const char *cookie,
		   const char *content_type)
{
  int fromCgi[2];  /* pipe for reading data from CGI */
  int toCgi[2];    /* pipe for sending data to CGI */

  static char * argp[] = { 0, 0 };
  int pid = 0;
  int inFd;
  int outFd;
  int firstLine = 1;

  do {
    if (pipe(fromCgi) != 0) {
      break;
    }
    if (pipe(toCgi) != 0) {
      break;
    }

    pid = fork();
    if (pid < 0) {
	pid = 0;
	break;
    }

    if (!pid) {
      /* child process */
      char *script;
      char *purl = strdup( url );
      char realpath_buff[MAXPATHLEN];

      if(purl == NULL)
	_exit(242);

      inFd  = toCgi[0];
      outFd = fromCgi[1];

      dup2(inFd, 0);  // replace stdin with the pipe
      dup2(outFd, 1);  // replace stdout with the pipe
      if(!DEBUG)
	dup2(outFd, 2);  // replace stderr with the pipe

      close(toCgi[0]);
      close(toCgi[1]);
      close(fromCgi[0]);
      close(fromCgi[1]);

      /*
       * Find PATH_INFO.
       */
      script = purl;
      while((script = strchr( script + 1, '/' )) != NULL) {
	/* have script.cgi/PATH_INFO or dirs/script.cgi[/PATH_INFO] */
	struct stat sb;

	*script = '\0';
	if(is_directory(purl + 1, 1, &sb) == 0) {
		/* not directory, found script.cgi/PATH_INFO */
		*script = '/';
		break;
	}
	*script = '/';          /* is directory, find next '/' */
      }
      addEnv("PATH", "INFO", script);   /* set /PATH_INFO or NULL */
      addEnv("PATH",           "",         getenv("PATH"));
      addEnv("REQUEST",        "METHOD",   request);
      if(config->query) {
	char *uri = alloca(strlen(purl) + 2 + strlen(config->query));
	if(uri)
	    sprintf(uri, "%s?%s", purl, config->query);
	addEnv("REQUEST",        "URI",   uri);
      } else {
	addEnv("REQUEST",        "URI",   purl);
      }
      if(script != NULL)
	*script = '\0';         /* reduce /PATH_INFO */
       /* SCRIPT_FILENAME required by PHP in CGI mode */
       if(realpath(purl + 1, realpath_buff))
	 addEnv("SCRIPT", "FILENAME", realpath_buff);
       else
	 *realpath_buff = 0;
      /* set SCRIPT_NAME as full path: /cgi-bin/dirs/script.cgi */
      addEnv("SCRIPT_NAME",    "",         purl);
      addEnv("QUERY_STRING",   "",         config->query);
      addEnv("SERVER",         "SOFTWARE", httpdVersion);
      addEnv("SERVER",         "PROTOCOL", "HTTP/1.0");
      addEnv("GATEWAY_INTERFACE", "",      "CGI/1.1");
      addEnv("REMOTE",         "ADDR",     config->rmt_ip_str);
#ifdef CONFIG_FEATURE_HTTPD_SET_REMOTE_PORT_TO_ENV
      addEnvPort("REMOTE");
#endif
      if(bodyLen) {
	char sbl[32];

	sprintf(sbl, "%d", bodyLen);
	addEnv("CONTENT", "LENGTH", sbl);
      }
      if(cookie)
	addEnv("HTTP", "COOKIE", cookie);
      if(content_type)
	addEnv("CONTENT", "TYPE", content_type);
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
      if(config->remoteuser) {
	addEnv("REMOTE", "USER", config->remoteuser);
	addEnv("AUTH_TYPE", "", "Basic");
      }
#endif
      if(config->referer)
	addEnv("HTTP", "REFERER", config->referer);

	/* set execve argp[0] without path */
      argp[0] = strrchr( purl, '/' ) + 1;
	/* but script argp[0] must have absolute path and chdiring to this */
      if(*realpath_buff) {
	    script = strrchr(realpath_buff, '/');
	    if(script) {
		*script = '\0';
		if(chdir(realpath_buff) == 0) {
		  // now run the program.  If it fails,
		  // use _exit() so no destructors
		  // get called and make a mess.
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
		  char *interpr = NULL;
		  char *suffix = strrchr(purl, '.');

		  if(suffix) {
			Htaccess * cur;
			for (cur = config->script_i; cur; cur = cur->next)
				if(strcmp(cur->before_colon + 1, suffix) == 0) {
					interpr = cur->after_colon;
					break;
				}
		  }
#endif
		  *script = '/';
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_SCRIPT_INTERPR
		  if (interpr)
			execv(interpr, argp);
		  else
#endif
			execv(realpath_buff, argp);
		}
	    }
      }
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
      config->accepted_socket = 1;      /* send to stdout */
#endif
      sendHeaders(HTTP_NOT_FOUND);
      _exit(242);
    } /* end child */

  } while (0);

  if (pid) {
    /* parent process */
    int status;
    size_t post_readed_size = 0, post_readed_idx = 0;

    inFd  = fromCgi[0];
    outFd = toCgi[1];
    close(fromCgi[1]);
    close(toCgi[0]);
    signal(SIGPIPE, SIG_IGN);

    while (1) {
      fd_set readSet;
      fd_set writeSet;
      char wbuf[128];
      int nfound;
      int count;

      FD_ZERO(&readSet);
      FD_ZERO(&writeSet);
      FD_SET(inFd, &readSet);
      if(bodyLen > 0 || post_readed_size > 0) {
	FD_SET(outFd, &writeSet);
	nfound = outFd > inFd ? outFd : inFd;
	if(post_readed_size == 0) {
		FD_SET(a_c_r, &readSet);
		if(nfound < a_c_r)
			nfound = a_c_r;
	}
      /* Now wait on the set of sockets! */
	nfound = select(nfound + 1, &readSet, &writeSet, 0, NULL);
      } else {
	if(!bodyLen) {
		close(outFd);
		bodyLen = -1;
	}
	nfound = select(inFd + 1, &readSet, 0, 0, NULL);
      }

      if (nfound <= 0) {
	if (waitpid(pid, &status, WNOHANG) > 0) {
	  close(inFd);
#if DEBUG
	  if (WIFEXITED(status))
	      bb_error_msg("piped has exited with status=%d", WEXITSTATUS(status));
	  if (WIFSIGNALED(status))
	      bb_error_msg("piped has exited with signal=%d", WTERMSIG(status));
#endif
	  break;
	}
      } else if(post_readed_size > 0 && FD_ISSET(outFd, &writeSet)) {
		count = bb_full_write(outFd, wbuf + post_readed_idx, post_readed_size);
		if(count > 0) {
			post_readed_size -= count;
			post_readed_idx += count;
			if(post_readed_size == 0)
				post_readed_idx = 0;
		} else {
			post_readed_size = post_readed_idx = bodyLen = 0; /* broken pipe to CGI */
		}
      } else if(bodyLen > 0 && post_readed_size == 0 && FD_ISSET(a_c_r, &readSet)) {
		count = bodyLen > (int)sizeof(wbuf) ? (int)sizeof(wbuf) : bodyLen;
		count = safe_read(a_c_r, wbuf, count);
		if(count > 0) {
			post_readed_size += count;
			bodyLen -= count;
		} else {
			bodyLen = 0;    /* closed */
		}
      }
      if(FD_ISSET(inFd, &readSet)) {
	int s = a_c_w;
	char *rbuf = config->buf;

#ifndef PIPE_BUF
# define PIPESIZE 4096          /* amount of buffering in a pipe */
#else
# define PIPESIZE PIPE_BUF
#endif
#if PIPESIZE >= MAX_MEMORY_BUFF
# error "PIPESIZE >= MAX_MEMORY_BUFF"
#endif

	// There is something to read
	count = safe_read(inFd, rbuf, PIPESIZE);
	if (count == 0)
		break;  /* closed */
	if (count > 0) {
	  if (firstLine) {
	    rbuf[count] = 0;
	    /* check to see if the user script added headers */
	    if(strncmp(rbuf, "HTTP/1.0 200 OK\r\n", 4) != 0) {
	      bb_full_write(s, "HTTP/1.0 200 OK\r\n", 17);
	    }
	    if (strstr(rbuf, "ontent-") == 0) {
	      bb_full_write(s, "Content-type: text/plain\r\n\r\n", 28);
	    }
	    firstLine = 0;
	  }
	  if (bb_full_write(s, rbuf, count) != count)
	      break;

#if DEBUG
	  fprintf(stderr, "cgi read %d bytes\n", count);
#endif
	}
      }
    }
  }
  return 0;
}
#endif          /* CONFIG_FEATURE_HTTPD_CGI */

/****************************************************************************
 *
 > $Function: sendFile()
 *
 * $Description: Send a file response to an HTTP request
 *
 * $Parameter:
 *      (const char *) url . . The URL requested.
 *
 * $Return: (int)  . . . . . . Always 0.
 *
 ****************************************************************************/
static int sendFile(const char *url)
{
  char * suffix;
  int  f;
  const char * const * table;
  const char * try_suffix;

  suffix = strrchr(url, '.');

  for (table = suffixTable; *table; table += 2)
	if(suffix != NULL && (try_suffix = strstr(*table, suffix)) != 0) {
		try_suffix += strlen(suffix);
		if(*try_suffix == 0 || *try_suffix == '.')
			break;
	}
  /* also, if not found, set default as "application/octet-stream";  */
  config->httpd_found.found_mime_type = *(table+1);
#ifdef CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES
  if (suffix) {
    Htaccess * cur;

    for (cur = config->mime_a; cur; cur = cur->next) {
	if(strcmp(cur->before_colon, suffix) == 0) {
		config->httpd_found.found_mime_type = cur->after_colon;
		break;
	}
    }
  }
#endif  /* CONFIG_FEATURE_HTTPD_CONFIG_WITH_MIME_TYPES */

#if DEBUG
  fprintf(stderr, "Sending file '%s' Content-type: %s\n",
			url, config->httpd_found.found_mime_type);
#endif

  f = open(url, O_RDONLY);
  if (f >= 0) {
	int count;
	char *buf = config->buf;

	sendHeaders(HTTP_OK);
	while ((count = bb_full_read(f, buf, MAX_MEMORY_BUFF)) > 0) {
		if (bb_full_write(a_c_w, buf, count) != count)
			break;
	}
	close(f);
  } else {
#if DEBUG
	bb_perror_msg("Unable to open '%s'", url);
#endif
	sendHeaders(HTTP_NOT_FOUND);
  }

  return 0;
}

static int checkPermIP(void)
{
    Htaccess_IP * cur;

    /* This could stand some work */
    for (cur = config->ip_a_d; cur; cur = cur->next) {
#if DEBUG
	fprintf(stderr, "checkPermIP: '%s' ? ", config->rmt_ip_str);
	fprintf(stderr, "'%u.%u.%u.%u/%u.%u.%u.%u'\n",
		(unsigned char)(cur->ip >> 24),
		(unsigned char)(cur->ip >> 16),
		(unsigned char)(cur->ip >> 8),
				cur->ip & 0xff,
		(unsigned char)(cur->mask >> 24),
		(unsigned char)(cur->mask >> 16),
		(unsigned char)(cur->mask >> 8),
				cur->mask & 0xff);
#endif
	if((config->rmt_ip & cur->mask) == cur->ip)
	    return cur->allow_deny == 'A';   /* Allow/Deny */
    }

    /* if unconfigured, return 1 - access from all */
    return !config->flg_deny_all;
}

/****************************************************************************
 *
 > $Function: checkPerm()
 *
 * $Description: Check the permission file for access password protected.
 *
 *   If config file isn't present, everything is allowed.
 *   Entries are of the form you can see example from header source
 *
 * $Parameters:
 *      (const char *) path  . . . . The file path.
 *      (const char *) request . . . User information to validate.
 *
 * $Return: (int)  . . . . . . . . . 1 if request OK, 0 otherwise.
 *
 ****************************************************************************/

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
static int checkPerm(const char *path, const char *request)
{
    Htaccess * cur;
    const char *p;
    const char *p0;

    const char *prev = NULL;

    /* This could stand some work */
    for (cur = config->auth; cur; cur = cur->next) {
	p0 = cur->before_colon;
	if(prev != NULL && strcmp(prev, p0) != 0)
	    continue;       /* find next identical */
	p = cur->after_colon;
#if DEBUG
	fprintf(stderr,"checkPerm: '%s' ? '%s'\n", p0, request);
#endif
	{
	    size_t l = strlen(p0);

	    if(strncmp(p0, path, l) == 0 &&
			    (l == 1 || path[l] == '/' || path[l] == 0)) {
		char *u;
		/* path match found.  Check request */
		/* for check next /path:user:password */
		prev = p0;
		u = strchr(request, ':');
		if(u == NULL) {
			/* bad request, ':' required */
			break;
			}

#ifdef CONFIG_FEATURE_HTTPD_AUTH_MD5
		{
			char *cipher;
			char *pp;

			if(strncmp(p, request, u-request) != 0) {
				/* user uncompared */
				continue;
			}
			pp = strchr(p, ':');
			if(pp && pp[1] == '$' && pp[2] == '1' &&
						 pp[3] == '$' && pp[4]) {
				pp++;
				cipher = pw_encrypt(u+1, pp);
				if (strcmp(cipher, pp) == 0)
					goto set_remoteuser_var;   /* Ok */
				/* unauthorized */
				continue;
			}
		}
#endif
		if (strcmp(p, request) == 0) {
#ifdef CONFIG_FEATURE_HTTPD_AUTH_MD5
set_remoteuser_var:
#endif
		    config->remoteuser = strdup(request);
		    if(config->remoteuser)
			config->remoteuser[(u - request)] = 0;
		    return 1;   /* Ok */
		}
		/* unauthorized */
	    }
	}
    }   /* for */

    return prev == NULL;
}

#endif  /* CONFIG_FEATURE_HTTPD_BASIC_AUTH */

/****************************************************************************
 *
 > $Function: handle_sigalrm()
 *
 * $Description: Handle timeouts
 *
 ****************************************************************************/

static void
handle_sigalrm( int sig )
{
    sendHeaders(HTTP_REQUEST_TIMEOUT);
    config->alarm_signaled = sig;
}

/****************************************************************************
 *
 > $Function: handleIncoming()
 *
 * $Description: Handle an incoming http request.
 *
 ****************************************************************************/
static void handleIncoming(void)
{
  char *buf = config->buf;
  char *url;
  char *purl;
  int  blank = -1;
  char *test;
  struct stat sb;
  int ip_allowed;
#ifdef CONFIG_FEATURE_HTTPD_CGI
  const char *prequest = request_GET;
  long length=0;
  char *cookie = 0;
  char *content_type = 0;
#endif
  fd_set s_fd;
  struct timeval tv;
  int retval;
  struct sigaction sa;

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  int credentials = -1;  /* if not requred this is Ok */
#endif

  sa.sa_handler = handle_sigalrm;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0; /* no SA_RESTART */
  sigaction(SIGALRM, &sa, NULL);

  do {
    int  count;

    (void) alarm( TIMEOUT );
    if (getLine() <= 0)
	break;  /* closed */

    purl = strpbrk(buf, " \t");
    if(purl == NULL) {
BAD_REQUEST:
      sendHeaders(HTTP_BAD_REQUEST);
      break;
    }
    *purl = 0;
#ifdef CONFIG_FEATURE_HTTPD_CGI
    if(strcasecmp(buf, prequest) != 0) {
	prequest = "POST";
	if(strcasecmp(buf, prequest) != 0) {
	    sendHeaders(HTTP_NOT_IMPLEMENTED);
	    break;
	}
    }
#else
    if(strcasecmp(buf, request_GET) != 0) {
	sendHeaders(HTTP_NOT_IMPLEMENTED);
	break;
    }
#endif
    *purl = ' ';
    count = sscanf(purl, " %[^ ] HTTP/%d.%*d", buf, &blank);

    if (count < 1 || buf[0] != '/') {
      /* Garbled request/URL */
      goto BAD_REQUEST;
    }
    url = alloca(strlen(buf) + 12);      /* + sizeof("/index.html\0") */
    if(url == NULL) {
	sendHeaders(HTTP_INTERNAL_SERVER_ERROR);
	break;
    }
    strcpy(url, buf);
    /* extract url args if present */
    test = strchr(url, '?');
    if (test) {
      *test++ = 0;
      config->query = test;
    }

    test = decodeString(url, 0);
    if(test == NULL)
	goto BAD_REQUEST;
    if(test == (buf+1)) {
	sendHeaders(HTTP_NOT_FOUND);
	break;
    }
    /* algorithm stolen from libbb bb_simplify_path(),
       but don`t strdup and reducing trailing slash and protect out root */
    purl = test = url;

    do {
	if (*purl == '/') {
	    if (*test == '/') {        /* skip duplicate (or initial) slash */
		continue;
	    } else if (*test == '.') {
		if (test[1] == '/' || test[1] == 0) { /* skip extra '.' */
		    continue;
		} else if ((test[1] == '.') && (test[2] == '/' || test[2] == 0)) {
		    ++test;
		    if (purl == url) {
			/* protect out root */
			goto BAD_REQUEST;
		    }
		    while (*--purl != '/');    /* omit previous dir */
		    continue;
		}
	    }
	}
	*++purl = *test;
    } while (*++test);

    *++purl = 0;        /* so keep last character */
    test = purl;        /* end ptr */

    /* If URL is directory, adding '/' */
    if(test[-1] != '/') {
	    if ( is_directory(url + 1, 1, &sb) ) {
		    config->httpd_found.found_moved_temporarily = url;
	    }
    }
#if DEBUG
    fprintf(stderr, "url='%s', args=%s\n", url, config->query);
#endif

    test = url;
    ip_allowed = checkPermIP();
    while(ip_allowed && (test = strchr( test + 1, '/' )) != NULL) {
	/* have path1/path2 */
	*test = '\0';
	if( is_directory(url + 1, 1, &sb) ) {
		/* may be having subdir config */
		parse_conf(url + 1, SUBDIR_PARSE);
		ip_allowed = checkPermIP();
	}
	*test = '/';
    }
    if(blank >= 0) {
      // read until blank line for HTTP version specified, else parse immediate
      while(1) {
	alarm(TIMEOUT);
	count = getLine();
	if(count <= 0)
		break;

#if DEBUG
	fprintf(stderr, "Header: '%s'\n", buf);
#endif

#ifdef CONFIG_FEATURE_HTTPD_CGI
	/* try and do our best to parse more lines */
	if ((strncasecmp(buf, Content_length, 15) == 0)) {
	  if(prequest != request_GET)
		  length = strtol(buf + 15, 0, 0); // extra read only for POST
	} else if ((strncasecmp(buf, "Cookie:", 7) == 0)) {
		  for(test = buf + 7; isspace(*test); test++)
			  ;
		  cookie = strdup(test);
	} else if ((strncasecmp(buf, "Content-Type:", 13) == 0)) {
		  for(test = buf + 13; isspace(*test); test++)
			  ;
		  content_type = strdup(test);
	} else if ((strncasecmp(buf, "Referer:", 8) == 0)) {
		  for(test = buf + 8; isspace(*test); test++)
			  ;
		  config->referer = strdup(test);
	}
#endif

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
	if (strncasecmp(buf, "Authorization:", 14) == 0) {
	  /* We only allow Basic credentials.
	   * It shows up as "Authorization: Basic <userid:password>" where
	   * the userid:password is base64 encoded.
	   */
	  for(test = buf + 14; isspace(*test); test++)
		  ;
	  if (strncasecmp(test, "Basic", 5) != 0)
		  continue;

	  test += 5;  /* decodeBase64() skiping space self */
	  decodeBase64(test);
	  credentials = checkPerm(url, test);
	}
#endif          /* CONFIG_FEATURE_HTTPD_BASIC_AUTH */

      }   /* while extra header reading */
    }
    (void) alarm( 0 );
    if(config->alarm_signaled)
	break;

    if (strcmp(strrchr(url, '/') + 1, httpd_conf) == 0 || ip_allowed == 0) {
		/* protect listing [/path]/httpd_conf or IP deny */
#ifdef CONFIG_FEATURE_HTTPD_CGI
FORBIDDEN:      /* protect listing /cgi-bin */
#endif
		sendHeaders(HTTP_FORBIDDEN);
		break;
    }

#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
    if (credentials <= 0 && checkPerm(url, ":") == 0) {
      sendHeaders(HTTP_UNAUTHORIZED);
      break;
    }
#endif

    if(config->httpd_found.found_moved_temporarily) {
	sendHeaders(HTTP_MOVED_TEMPORARILY);
#if DEBUG
	/* clear unforked memory flag */
	config->httpd_found.found_moved_temporarily = NULL;
#endif
	break;
    }

    test = url + 1;      /* skip first '/' */

#ifdef CONFIG_FEATURE_HTTPD_CGI
    /* if strange Content-Length */
    if (length < 0)
	break;

    if (strncmp(test, "cgi-bin", 7) == 0) {
		if(test[7] == '/' && test[8] == 0)
			goto FORBIDDEN;     // protect listing cgi-bin/
		sendCgi(url, prequest, length, cookie, content_type);
    } else {
	if (prequest != request_GET)
		sendHeaders(HTTP_NOT_IMPLEMENTED);
	else {
#endif  /* CONFIG_FEATURE_HTTPD_CGI */
		if(purl[-1] == '/')
			strcpy(purl, "index.html");
		if ( stat(test, &sb ) == 0 ) {
			config->ContentLength = sb.st_size;
			config->last_mod = sb.st_mtime;
		}
		sendFile(test);
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
		/* unset if non inetd looped */
		config->ContentLength = -1;
#endif

#ifdef CONFIG_FEATURE_HTTPD_CGI
	}
    }
#endif

  } while (0);


#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
/* from inetd don`t looping: freeing, closing automatic from exit always */
# if DEBUG
  fprintf(stderr, "closing socket\n");
# endif
# ifdef CONFIG_FEATURE_HTTPD_CGI
  free(cookie);
  free(content_type);
  free(config->referer);
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  free(config->remoteuser);
#endif
# endif
#endif  /* CONFIG_FEATURE_HTTPD_WITHOUT_INETD */
  shutdown(a_c_w, SHUT_WR);

  /* Properly wait for remote to closed */
  FD_ZERO (&s_fd) ;
  FD_SET (a_c_r, &s_fd) ;

  do {
    tv.tv_sec = 2 ;
    tv.tv_usec = 0 ;
    retval = select (a_c_r + 1, &s_fd, NULL, NULL, &tv);
  } while (retval > 0 && (read (a_c_r, buf, sizeof (config->buf)) > 0));

  shutdown(a_c_r, SHUT_RD);
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
  close(config->accepted_socket);
#endif  /* CONFIG_FEATURE_HTTPD_WITHOUT_INETD */
}

/****************************************************************************
 *
 > $Function: miniHttpd()
 *
 * $Description: The main http server function.
 *
 *   Given an open socket fildes, listen for new connections and farm out
 *   the processing as a forked process.
 *
 * $Parameters:
 *      (int) server. . . The server socket fildes.
 *
 * $Return: (int) . . . . Always 0.
 *
 ****************************************************************************/
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
static int miniHttpd(int server)
{
  fd_set readfd, portfd;

  FD_ZERO(&portfd);
  FD_SET(server, &portfd);

  /* copy the ports we are watching to the readfd set */
  while (1) {
    readfd = portfd;

    /* Now wait INDEFINITELY on the set of sockets! */
    if (select(server + 1, &readfd, 0, 0, 0) > 0) {
      if (FD_ISSET(server, &readfd)) {
	int on;
	struct sockaddr_in fromAddr;

	socklen_t fromAddrLen = sizeof(fromAddr);
	int s = accept(server,
		       (struct sockaddr *)&fromAddr, &fromAddrLen);

	if (s < 0) {
	    continue;
	}
	config->accepted_socket = s;
	config->rmt_ip = ntohl(fromAddr.sin_addr.s_addr);
#if defined(CONFIG_FEATURE_HTTPD_CGI) || DEBUG
	sprintf(config->rmt_ip_str, "%u.%u.%u.%u",
		(unsigned char)(config->rmt_ip >> 24),
		(unsigned char)(config->rmt_ip >> 16),
		(unsigned char)(config->rmt_ip >> 8),
				config->rmt_ip & 0xff);
	config->port = ntohs(fromAddr.sin_port);
#if DEBUG
	bb_error_msg("connection from IP=%s, port %u\n",
					config->rmt_ip_str, config->port);
#endif
#endif /* CONFIG_FEATURE_HTTPD_CGI */

	/*  set the KEEPALIVE option to cull dead connections */
	on = 1;
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&on, sizeof (on));

#if !DEBUG
	if (fork() == 0)
#endif
	{
	    /* This is the spawned thread */
#ifdef CONFIG_FEATURE_HTTPD_RELOAD_CONFIG_SIGHUP
	    /* protect reload config, may be confuse checking */
	    signal(SIGHUP, SIG_IGN);
#endif
	    handleIncoming();
#if !DEBUG
	    exit(0);
#endif
	}
	close(s);
      }
    }
  } // while (1)
  return 0;
}

#else
    /* from inetd */

static int miniHttpd(void)
{
  struct sockaddr_in fromAddrLen;
  socklen_t sinlen = sizeof (struct sockaddr_in);

  getpeername (0, (struct sockaddr *)&fromAddrLen, &sinlen);
  config->rmt_ip = ntohl(fromAddrLen.sin_addr.s_addr);
#ifdef CONFIG_FEATURE_HTTPD_CGI
  sprintf(config->rmt_ip_str, "%u.%u.%u.%u",
		(unsigned char)(config->rmt_ip >> 24),
		(unsigned char)(config->rmt_ip >> 16),
		(unsigned char)(config->rmt_ip >> 8),
				config->rmt_ip & 0xff);
#endif
  config->port = ntohs(fromAddrLen.sin_port);
  handleIncoming();
  return 0;
}
#endif  /* CONFIG_FEATURE_HTTPD_WITHOUT_INETD */

#ifdef CONFIG_FEATURE_HTTPD_RELOAD_CONFIG_SIGHUP
static void sighup_handler(int sig)
{
	/* set and reset */
	struct sigaction sa;

	parse_conf(default_path_httpd_conf,
		    sig == SIGHUP ? SIGNALED_PARSE : FIRST_PARSE);
	sa.sa_handler = sighup_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
}
#endif

enum httpd_opts_nums {
	c_opt_config_file = 0,
	d_opt_decode_url,
	h_opt_home_httpd,
	USE_FEATURE_HTTPD_ENCODE_URL_STR(e_opt_encode_url,)
	USE_FEATURE_HTTPD_BASIC_AUTH(r_opt_realm,)
	USE_FEATURE_HTTPD_AUTH_MD5(m_opt_md5,)
	USE_FEATURE_HTTPD_SETUID(u_opt_setuid,)
	USE_FEATURE_HTTPD_WITHOUT_INETD(p_opt_port,)
};

static const char httpd_opts[]="c:d:h:"
	USE_FEATURE_HTTPD_ENCODE_URL_STR("e:")
	USE_FEATURE_HTTPD_BASIC_AUTH("r:")
	USE_FEATURE_HTTPD_AUTH_MD5("m:")
	USE_FEATURE_HTTPD_SETUID("u:")
	USE_FEATURE_HTTPD_WITHOUT_INETD("p:");

#define OPT_CONFIG_FILE (1<<c_opt_config_file)
#define OPT_DECODE_URL  (1<<d_opt_decode_url)
#define OPT_HOME_HTTPD  (1<<h_opt_home_httpd)

#define OPT_ENCODE_URL  USE_FEATURE_HTTPD_ENCODE_URL_STR((1<<e_opt_encode_url)) \
			SKIP_FEATURE_HTTPD_ENCODE_URL_STR(0)

#define OPT_REALM       USE_FEATURE_HTTPD_BASIC_AUTH((1<<r_opt_realm)) \
			SKIP_FEATURE_HTTPD_BASIC_AUTH(0)

#define OPT_MD5         USE_FEATURE_HTTPD_AUTH_MD5((1<<m_opt_md5)) \
			SKIP_FEATURE_HTTPD_AUTH_MD5(0)

#define OPT_SETUID      USE_FEATURE_HTTPD_SETUID((1<<u_opt_setuid)) \
			SKIP_FEATURE_HTTPD_SETUID(0)

#define OPT_PORT        USE_FEATURE_HTTPD_WITHOUT_INETD((1<<p_opt_port)) \
			SKIP_FEATURE_HTTPD_WITHOUT_INETD(0)


int httpd_main(int argc, char *argv[])
{
  unsigned long opt;
  const char *home_httpd = home;
  char *url_for_decode;
  USE_FEATURE_HTTPD_ENCODE_URL_STR(const char *url_for_encode;)
  USE_FEATURE_HTTPD_WITHOUT_INETD(const char *s_port;)
  USE_FEATURE_HTTPD_WITHOUT_INETD(int server;)

  USE_FEATURE_HTTPD_SETUID(const char *s_uid;)
  USE_FEATURE_HTTPD_SETUID(long uid = -1;)

  USE_FEATURE_HTTPD_AUTH_MD5(const char *pass;)

  config = xcalloc(1, sizeof(*config));
#ifdef CONFIG_FEATURE_HTTPD_BASIC_AUTH
  config->realm = "Web Server Authentication";
#endif

#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
  config->port = 80;
#endif

  config->ContentLength = -1;

  opt = bb_getopt_ulflags(argc, argv, httpd_opts,
			&(config->configFile), &url_for_decode, &home_httpd
			USE_FEATURE_HTTPD_ENCODE_URL_STR(, &url_for_encode)
			USE_FEATURE_HTTPD_BASIC_AUTH(, &(config->realm))
			USE_FEATURE_HTTPD_AUTH_MD5(, &pass)
			USE_FEATURE_HTTPD_SETUID(, &s_uid)
			USE_FEATURE_HTTPD_WITHOUT_INETD(, &s_port)
	);

  if(opt & OPT_DECODE_URL) {
      printf("%s", decodeString(url_for_decode, 1));
      return 0;
  }
#ifdef CONFIG_FEATURE_HTTPD_ENCODE_URL_STR
  if(opt & OPT_ENCODE_URL) {
      printf("%s", encodeString(url_for_encode));
      return 0;
  }
#endif
#ifdef CONFIG_FEATURE_HTTPD_AUTH_MD5
  if(opt & OPT_MD5) {
      printf("%s\n", pw_encrypt(pass, "$1$"));
      return 0;
  }
#endif
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
    if(opt & OPT_PORT)
	config->port = bb_xgetlarg(s_port, 10, 1, 0xffff);
#ifdef CONFIG_FEATURE_HTTPD_SETUID
    if(opt & OPT_SETUID) {
	char *e;

	uid = strtol(s_uid, &e, 0);
	if(*e != '\0') {
		/* not integer */
		uid = bb_xgetpwnam(s_uid);
	}
      }
#endif
#endif

  bb_xchdir(home_httpd);
#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
  server = openServer();
# ifdef CONFIG_FEATURE_HTTPD_SETUID
  /* drop privileges */
  if(uid > 0)
	setuid(uid);
# endif
#endif

#ifdef CONFIG_FEATURE_HTTPD_CGI
   {
	char *p = getenv("PATH");
	if(p) {
		p = bb_xstrdup(p);
	}
	clearenv();
	if(p)
		setenv("PATH", p, 1);
# ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
	addEnvPort("SERVER");
# endif
   }
#endif

#ifdef CONFIG_FEATURE_HTTPD_RELOAD_CONFIG_SIGHUP
  sighup_handler(0);
#else
  parse_conf(default_path_httpd_conf, FIRST_PARSE);
#endif

#ifdef CONFIG_FEATURE_HTTPD_WITHOUT_INETD
# if !DEBUG
  bb_xdaemon(1, 0);     /* don`t change curent directory */
# endif
  return miniHttpd(server);
#else
  return miniHttpd();
#endif
}
