
/*-
 * Copyright (c) 1995 The Apache Group. All rights reserved.
 * 
 *
 * Apache httpd license
 * ====================
 * 
 *
 * This is the license for the Apache Server. It covers all the
 * files which come in this distribution, and should never be removed.
 * 
 * The "Apache Group" has based this server, called "Apache", on
 * public domain code distributed under the name "NCSA httpd 1.3".
 * 
 * NCSA httpd 1.3 was placed in the public domain by the National Center 
 * for Supercomputing Applications at the University of Illinois 
 * at Urbana-Champaign.
 * 
 * As requested by NCSA we acknowledge,
 * 
 *  "Portions developed at the National Center for Supercomputing
 *   Applications at the University of Illinois at Urbana-Champaign."
 *
 * Copyright on the sections of code added by the "Apache Group" belong
 * to the "Apache Group" and/or the original authors. The "Apache Group" and
 * authors hereby grant permission for their code, along with the
 * public domain NCSA code, to be distributed under the "Apache" name.
 * 
 * Reuse of "Apache Group" code outside of the Apache distribution should
 * be acknowledged with the following quoted text, to be included with any new
 * work;
 * 
 * "Portions developed by the "Apache Group", taken with permission 
 *  from the Apache Server   http://www.apache.org/apache/   "
 *
 *
 * Permission is hereby granted to anyone to redistribute Apache under
 * the "Apache" name. We do not grant permission for the resale of Apache, but
 * we do grant permission for vendors to bundle Apache free with other software,
 * or to charge a reasonable price for redistribution, provided it is made
 * clear that Apache is free. Permission is also granted for vendors to 
 * sell support for for Apache. We explicitly forbid the redistribution of 
 * Apache under any other name.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 */



/*
 * http_auth: authentication
 * 
 * Rob McCool & Brian Behlendorf.
 * 
 * Adapted to Shambhala by rst.
 */

/*
 * converted to use mSQL by Vivek Khera <khera@kciLink.com>
 * 
 * converted to use DBI by Doug MacEachern <dougm@osf.org>
 *
 * User must be a unique, non-empty field.  Length is however long you
 * want it to be. 
 * Any other fields in the named table will be ignored.
 * The actual field names are configurable
 * using the parameters listed below.  The defaults (shown here) are "user" and "password"
 * respectively, for the user ID and the password.
 *
 * Usage in per-directory access conf file:
 *
 *  AuthName DBI Testing
 *  AuthType Basic
 *  AuthGroupFile /dev/null
 *  AuthDBIDB www_data
 *  AuthDBIUserTable user_info
 *  AuthDBIDriver Oracle
 *  AuthDBINameField user
 *  AuthDBIPasswordField password
 *
 *  <Limit GET POST>
 *  require valid-user
 *  </Limit>
 *
 * The following parameters are optional in the config file 
 * depending on the Driver 
 *
 * AuthDBIUser
 * AuthDBIAuth
 * 
 * So, the connect call looks like so:
 * DBI->connect(AuthDBIDB, AuthDBIUser, AuthDBIAuth, AuthDBIDriver)
 *
 * You may need to tell the module where it can find DBI and
 * DBD::* modules. This  argument should be the same format as 
 * the environment variable 'PERL5LIB'
 *
 *   PerlINC /path/to/modules
 * 
 * Groups are not implemented in DBI.  Use the original flat file or
 * the Apache DBM version.
 *
 * $Id: mod_auth_dbi.c,v 1.10 1996/04/21 23:51:02 dougm Exp $
 */

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>


typedef struct  {
    char *driver;
    char *db;
    char *user;
    char *auth;
    char *pwtable;
    char *uidfield;
    char *pwfield;
    char *inc;
    int  crypted;
} dbi_auth_config_rec;

void xs_init _((void));
void incpush _((char *));

static
void *create_dbi_auth_dir_config (pool *p, char *d)
{
  dbi_auth_config_rec *dbi = pcalloc (p, sizeof(dbi_auth_config_rec));
  if (!dbi) return NULL;  /* failure to get memory is a bad thing */

  /* defaults */
  dbi->uidfield = "user";
  dbi->pwfield = "password";
  dbi->crypted = 1;
  return (void *)dbi;
}

static
char *set_crypted_password (cmd_parms *cmd, void *mrec, int arg) {
  ((dbi_auth_config_rec *)mrec)->crypted = arg;
  return NULL;
}

static
command_rec dbi_auth_cmds[] = {
{ "AuthDBIDB", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, db),
    OR_AUTHCFG, TAKE1, "DBI database name" },
{ "AuthDBIUser", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, user),
    OR_AUTHCFG, TAKE1, "DBI user name" },
{ "AuthDBIAuth", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, auth),
    OR_AUTHCFG, TAKE1, "DBI password" },
{ "AuthDBIDriver", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, driver),
    OR_AUTHCFG, TAKE1, "DBI driver" },
{ "AuthDBIUserTable", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, pwtable),
    OR_AUTHCFG, TAKE1, "DBI table name" },
{ "AuthDBINameField", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, uidfield),
    OR_AUTHCFG, TAKE1, "DBI User ID field name within table" },
{ "AuthDBIPasswordField", set_string_slot,
    (void*)XtOffsetOf(dbi_auth_config_rec, pwfield),
    OR_AUTHCFG, TAKE1, "DBI Password field name within table" },
{ "AuthDBICryptedPasswords", set_crypted_password,
    NULL, OR_AUTHCFG, FLAG, "DBI passwords are stored encrypted if On" },
{ "PerlINC", set_string_slot,
   (void*)XtOffsetOf(dbi_auth_config_rec, inc),
   OR_AUTHCFG, TAKE1, "Path for @INC" },
{ NULL }
};

module dbi_auth_module;

/*
 * get password from database
 */
static
char *get_dbi_pw(request_rec *r, char *user, dbi_auth_config_rec *dbi) {
  PerlInterpreter *perl = perl_alloc();
  STRLEN length;
    
  char script[MAX_STRING_LEN];
  char *embedding[] = { "", "-e", "" };

  SV* pw;
  char query[MAX_STRING_LEN];
    
  sprintf(query,"SELECT %s FROM %s WHERE %s = '%s'",
	  dbi->pwfield, dbi->pwtable,
	  dbi->uidfield, user);

  sprintf(script, "$dbh = DBI->connect('%s','%s','%s','%s');", 
	           dbi->db, dbi->user, dbi->auth, dbi->driver);
  strcat(script, "$sth = $dbh->prepare(q(");
  strcat(script, query);
  strcat(script, ")); $sth->execute; $pwd = $sth->fetchrow;");
  
  embedding[2] = script;

  perl_construct(perl);
  perl_parse(perl, xs_init, 3, embedding, (char **)NULL);
  incpush(dbi->inc);
  perl_require_pv("DBI.pm");
  perl_run(perl);

  pw = perl_get_sv("pwd", FALSE);
    
  perl_destruct(perl);
  perl_free(perl);

  if(SvTRUE(pw))
    return SvPV(pw, length);
  else
    return NULL; 
}

static
int dbi_authenticate_basic_user (request_rec *r)
{
    dbi_auth_config_rec *sec =
      (dbi_auth_config_rec *)get_module_config (r->per_dir_config,
						&dbi_auth_module);
    conn_rec *c = r->connection;
    char *sent_pw, *real_pw;
    char errstr[MAX_STRING_LEN];
    int res;
    
    if ((res = get_basic_auth_pw (r, &sent_pw)))
        return res;
    
    if(!sec->pwtable)
        return DECLINED;

    if(!(real_pw = get_dbi_pw(r, c->user, sec))) {
        sprintf(errstr,"DBI user `%s' not found", c->user);
	log_reason (errstr, r->uri, r);
	note_basic_auth_failure (r);
	return AUTH_REQUIRED;
    }

    if(strcmp(real_pw, sec->crypted ? crypt(sent_pw,real_pw) : sent_pw)) {
      sprintf(errstr,"user %s: password mismatch",c->user);
      log_reason (errstr, r->uri, r);
      note_basic_auth_failure (r);
      return AUTH_REQUIRED;
    }
    return OK;
}

/* incpush stuff from perl.c
 * Would be nice to have in libperl.a
 */
#if defined(DOSISH)
#    define PERLLIB_SEP ';'
#else
#  if defined(VMS)
#    define PERLLIB_SEP '|'
#  else
#    define PERLLIB_SEP ':'
#  endif
#endif

void
incpush(p)
char *p;
{
    char *s;

    if (!p)
	return;

    /* Break at all separators */
    while (*p) {
	/* First, skip any consecutive separators */
	while ( *p == PERLLIB_SEP ) {
	    /* Uncomment the next line for PATH semantics */
	    /* av_push(GvAVn(incgv), newSVpv(".", 1)); */
	    p++;
	}
	if ( (s = strchr(p, PERLLIB_SEP)) != Nullch ) {
	    av_push(GvAVn(incgv), newSVpv(p, (STRLEN)(s - p)));
	    p = s + 1;
	} else {
	    av_push(GvAVn(incgv), newSVpv(p, 0));
	    break;
	}
    }
}

module dbi_auth_module = {
   STANDARD_MODULE_STUFF,
   NULL,			/* initializer */
   create_dbi_auth_dir_config,	/* dir config creater */
   NULL,			/* dir merger --- default is to override */
   NULL,			/* server config */
   NULL,			/* merge server config */
   dbi_auth_cmds,		/* command table */
   NULL,			/* handlers */
   NULL,			/* filename translation */
   dbi_authenticate_basic_user,	/* check_user_id */
   NULL,			/* check auth */
   NULL,			/* check access */
   NULL,			/* type_checker */
   NULL,			/* fixups */
   NULL				/* logger */
};
