/* scd.c - Interface to Scdaemon
   Copyright (C) 2001, 2002, 2005 Free Software Foundation, Inc.
   Copyright (C) 2007, 2008, 2009 g10code GmbH.

   This file is part of Poldi.

   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see
   <http://www.gnu.org/licenses/>.  */

#include <poldi.h>
#include <security/pam_modules.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>

#include <gpg-error.h>
#include <gcrypt.h>

#include "scd.h"
#include "assuan.h"
#include "util/util.h"
#include "util/membuf.h"
#include "util/support.h"
#include "util/simplelog.h"

#ifdef _POSIX_OPEN_MAX
#define MAX_OPEN_FDS _POSIX_OPEN_MAX
#else
#define MAX_OPEN_FDS 20
#endif

#define READ_END 0
#define WRITE_END 1

#define TRUE 1
#define FALSE 0

/* Initializer objet for struct scd_cardinfo instances.  */
struct scd_cardinfo scd_cardinfo_null;



struct scd_context
{
  assuan_context_t assuan_ctx;
  unsigned int flags;
  log_handle_t loghandle;
  scd_pincb_t pincb;
  void *pincb_cookie;
};

/* Callback parameter for learn card */
struct learn_parm_s
{
  void (*kpinfo_cb)(void*, const char *);
  void *kpinfo_cb_arg;
  void (*certinfo_cb)(void*, const char *);
  void *certinfo_cb_arg;
  void (*sinfo_cb)(void*, const char *, size_t, const char *);
  void *sinfo_cb_arg;
};

struct inq_needpin_s
{
  scd_context_t ctx;
  int (*getpin_cb)(void *, const char *, char*, size_t);
  void *getpin_cb_arg;
};


/* Local prototypes.  */
static assuan_error_t membuf_data_cb (void *opaque,
                                      const void *buffer, size_t length);




static gpg_error_t scd_serialno_internal (assuan_context_t ctx,
					  char **r_serialno);



/* Get the socket of GPG-AGENT by gpgconf. */
static gpg_error_t
get_agent_socket_name (char **gpg_agent_sockname)
{
  gpg_error_t err = 0;
  FILE *input;
  char *result;
  size_t len;

  *gpg_agent_sockname = NULL;

  result = xtrymalloc (256);
  if (!result)
    return gpg_error_from_syserror ();

  /* It is good if we have popen with execv (no SHELL) */
  input = popen (GNUPG_DEFAULT_GPGCONF " --list-dirs agent-socket", "r");
  if (input == (void*) NULL)
    {
      xfree (result);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  len = fread (result, 1, 256, input);
  fclose (input);

  if (len)
    {
      *gpg_agent_sockname = result;
      result[len-1] = 0;	/* Chop off the newline.  */
    }
  else
    {
      xfree (result);
      err =  gpg_error (GPG_ERR_NOT_FOUND);
    }

  return err;
}

/* Get the bindir of GPG-AGENT by gpgconf. */
static gpg_error_t get_agent_bin_dir (char **gpg_agent_bindir)
{
  gpg_error_t err = 0;
  FILE *input;
  char *result;
  size_t len;

  *gpg_agent_bindir = NULL;

  result = xtrymalloc (256);
  if (!result)
    return gpg_error_from_syserror ();

  /* It is good if we have popen with execv (no SHELL) */
  input = popen (GNUPG_DEFAULT_GPGCONF " --list-dirs bindir", "r");
  if (input == (void*) NULL)
    {
      xfree (result);
      return gpg_error (GPG_ERR_NOT_FOUND);
    }

  len = fread (result, 1, 256, input);
  fclose (input);

  if (len)
    {
      *gpg_agent_bindir = result;
      result[len-1] = 0;	/* Chop off the newline.  */
    }
  else
    {
      xfree (result);
      err =  gpg_error (GPG_ERR_NOT_FOUND);
    }

  return err;
}

/* Helper function for get_scd_socket_from_agent(), which is used by
   scd_connect().

   Try to retrieve the SCDaemons socket name from the gpg-agent
   context CTX.  On success, *SOCKET_NAME is filled with a copy ot the
   socket name.  Return proper error code or zero on success. */
static gpg_error_t
agent_scd_getinfo_socket_name (assuan_context_t ctx, char **socket_name)
{
  membuf_t data;
  gpg_error_t err = 0;
  unsigned char *databuf;
  size_t datalen;

  init_membuf (&data, 256);
  *socket_name = NULL;

  err = assuan_transact (ctx, "SCD GETINFO socket_name", membuf_data_cb, &data,
			 NULL, NULL, NULL, NULL);
  databuf = get_membuf (&data, &datalen);
  if (!err)
    {
      if (databuf && datalen)
	{
	  char *res = xtrymalloc (datalen + 1);
	  if (!res)
	    err = gpg_error_from_syserror ();
	  else
	    {
	      memcpy (res, databuf, datalen);
	      res[datalen] = 0;
	      *socket_name = res;
	    }
	}
    }

  xfree (databuf);

  return err;
}

/* Retrieve SCDaemons socket name through a running gpg-agent.  On
   success, *SOCKET_NAME contains a copy of the socket name.  Returns
   proper error code or zero on success.  */
static gpg_error_t
get_scd_socket_from_agent (char **socket_name)
{
  assuan_context_t ctx = NULL;
  gpg_error_t err;
  char *gpg_agent_sockname;

  err = get_agent_socket_name (&gpg_agent_sockname);
  if (err)
    return err;

  err = assuan_socket_connect (&ctx, gpg_agent_sockname, 0);
  xfree (gpg_agent_sockname);
  if (!err)
    err = agent_scd_getinfo_socket_name (ctx, socket_name);

  assuan_disconnect (ctx);

  return err;
}

/* Send a RESTART to SCDaemon.  */
static void
restart_scd (scd_context_t ctx)
{
  assuan_transact (ctx->assuan_ctx, "RESTART",
		   NULL, NULL, NULL, NULL, NULL, NULL);
}



/* Fork off scdaemon and work by pipes.  Returns proper error code or
   zero on success.  */
gpg_error_t
scd_connect (scd_context_t *scd_ctx, int use_agent, const char *scd_path,
	     const char *scd_options, log_handle_t loghandle, pam_handle_t *pam_handle, struct passwd *pw)
{
  assuan_context_t assuan_ctx;
  scd_context_t ctx;
  gpg_error_t err = 0;
  int rt_val = 0;
  size_t buff_size = 512;

  if (fflush (NULL))
    {
      err = gpg_error_from_syserror ();
      log_msg_error (loghandle, "error flushing pending output: %s",
		     strerror (errno));
      return err;
    }

  ctx = xtrymalloc (sizeof (*ctx));
  if (!ctx)
  {
	  return gpg_error_from_syserror ();
  }
  ctx->assuan_ctx = NULL;
  ctx->flags = 0;

  if (use_agent == 2)
    {
	  char *scd_socket_name = NULL;
	  char *gpg_bin_dir = NULL;
	  char  gpg_connect_agent[buff_size];
	  char *connect_agent = "gpg-connect-agent";

	  err = get_agent_bin_dir(&gpg_bin_dir);
	  if(err)
	  {
		  return err;
	  }

	  //if not enough room to copy string
	  if(strlen(gpg_bin_dir) > (buff_size + strlen(connect_agent)+1))
	  {
		  return GPG_ERR_GENERAL;
	  }

	  strcpy(gpg_connect_agent, gpg_bin_dir);
	  strcat(gpg_connect_agent, "/gpg-connect-agent");

	  const char *cmd_start_gpg[] = {gpg_connect_agent, "learn", "/bye", NULL};
	  const char *cmd_start_gpg_tty[] = {gpg_connect_agent, "UPDATESTARTUPTTY", "/bye", NULL};

	  int input;
	  char **env = pam_getenvlist(pam_handle);

	  //start gpg as user
	  run_as_user(pw, loghandle, cmd_start_gpg, &input, env);
	  waitpid(-1, &rt_val, 0);
	  if (input < 0 || rt_val == EXIT_FAILURE)
	  {
		  return GPG_ERR_GENERAL;
	  }

	  //setup gpg tty under user, needed for using gpg-agent ssh with pinentry-qt
	  run_as_user(pw, loghandle, cmd_start_gpg_tty, &input, env);
	  waitpid(-1, &rt_val, 0);
	  if (input < 0 || rt_val == EXIT_FAILURE)
	  {
		  return GPG_ERR_GENERAL;
	  }

	  if (env != NULL)
	  {
	      free(env);
	  }

	  int fd[2];
	  size_t maxBuffSize=1024;
	  char pipe_buff[maxBuffSize];

	  // create pipe descriptors
	  rt_val = pipe(fd);
	  if (rt_val == -1)
	  {
		  return GPG_ERR_GENERAL;
	  }

	  int frk_val = fork();

	  if (frk_val != 0)
	  {
		  //parent process reading only, close write descriptor
		  close_safe(fd[1], loghandle);
		  //read data from child
		  rt_val = read(fd[0], pipe_buff, maxBuffSize);
		  if (rt_val == -1)
		  {
			  return GPG_ERR_GENERAL;
		  }
		  //close read
		  close_safe(fd[0], loghandle);
	  }
	  else//child process
	  {
		  close_safe(fd[0], loghandle);

		  //switch to user process
		  rt_val = setgid(pw->pw_gid);
		  if(rt_val == -1)
		  {
			  exit(-1);
		  }

		  rt_val = setuid(pw->pw_uid);
		  if(rt_val == -1)
		  {
			  exit(-1);
		  }

		  get_scd_socket_from_agent (&scd_socket_name);

		  //close read pipe
		  if(scd_socket_name != NULL)
		  {
			  strcpy(pipe_buff, scd_socket_name);
		  }
		  //get gpg socket path
		  err = write(fd[1], pipe_buff, maxBuffSize);
		  if(err == -1)
		  {
			  exit(-1);
		  }

		  //close write and exit
		  close_safe(fd[1], loghandle);
		  exit(0);
	  }
	  //wait for child to finish
	  waitpid(frk_val, &rt_val, 0);

	  //if child exited on error
	  if(rt_val == -1)
	  {
		  return GPG_ERR_GENERAL;
	  }
	  scd_socket_name=pipe_buff;

	  //connect to users scdeamon socket
	  err = assuan_socket_connect (&assuan_ctx, scd_socket_name, 0);

	  if (!err)
	  {
		  log_msg_debug (loghandle,
		   "got scdaemon socket name from users gpg-agent, "
	  		       "connected to socket '%s'", scd_socket_name);
	  }
	  else
	  {
		  log_msg_debug (loghandle, "Error getting scdaemon socket during session setup: %s", scd_socket_name);
	  }
  }

  /* Try using scdaemon under gpg-agent.  */
  if (use_agent == 1)
    {
      char *scd_socket_name = NULL;

      /* Note that if gpg-agent is there but no scdaemon yet,
       * gpg-agent automatically invokes scdaemon by this query
       * itself.
       */
      err = get_scd_socket_from_agent (&scd_socket_name);
      if (!err)
	err = assuan_socket_connect (&assuan_ctx, scd_socket_name, 0);

      if (!err)
	log_msg_debug (loghandle,
		       "got scdaemon socket name from gpg-agent, "
		       "connected to socket '%s'", scd_socket_name);

      xfree (scd_socket_name);
    }

  /* If scdaemon under gpg-agent is irrelevant or not available,
   * let Poldi invoke scdaemon.
   */
  if ((use_agent==0) || (err && use_agent != 2))
    {
      const char *pgmname;
      const char *argv[5];
      int no_close_list[3];
      int i;

      assuan_ctx = NULL;

      if (!scd_path || !*scd_path)
        scd_path = GNUPG_DEFAULT_SCD;
      if (!(pgmname = strrchr (scd_path, '/')))
        pgmname = scd_path;
      else
        pgmname++;

      /* Fill argument vector for scdaemon.  */

      i = 0;
      argv[i++] = pgmname;
      argv[i++] = "--server";
      if (scd_options)
	{
	  argv[i++] = "--options";
	  argv[i++] = scd_options;
	}
      argv[i++] = NULL;

      i=0;

#if 0
      /* FIXME! Am I right in assumung that we do not need this?
	 -mo */
      if (log_get_fd () != -1)
        no_close_list[i++] = log_get_fd ();
#endif

      /* FIXME: What about stderr? */
      no_close_list[i++] = fileno (stderr);
      no_close_list[i] = -1;

      /* connect to the scdaemon and perform initial handshaking */
      err = assuan_pipe_connect (&assuan_ctx, scd_path, argv, no_close_list);
      if (err)
	{
	  log_msg_error (loghandle, "could not spawn scdaemon: %s",
			 gpg_strerror (err));
	}
      else
	{
	  log_msg_debug (loghandle, "spawned a new scdaemon (path: '%s')",
			 scd_path);
	}
    }

  if (err)
    {
      assuan_disconnect (assuan_ctx);
      xfree (ctx);
    }
  else
    {
      /* FIXME: is this the best way?  -mo */
      //reset_scd (assuan_ctx);

	  char *card_sn = NULL;
      err = scd_serialno_internal (assuan_ctx, &card_sn);

      ctx->assuan_ctx = assuan_ctx;
      ctx->flags = 0;
      ctx->loghandle = loghandle;
      *scd_ctx = ctx;
    }

  return err;
}

/* Disconnect from SCDaemon; destroy the context SCD_CTX.  */
void
scd_disconnect (scd_context_t scd_ctx)
{
  if (scd_ctx)
    {
      restart_scd (scd_ctx);
      assuan_disconnect (scd_ctx->assuan_ctx);
      xfree (scd_ctx);
    }
}


void
scd_set_pincb (scd_context_t scd_ctx,
	       scd_pincb_t pincb, void *cookie)
{
  assert (scd_ctx);

  scd_ctx->pincb = pincb;
  scd_ctx->pincb_cookie = cookie;
}




/* Return a new malloced string by unescaping the string S.  Escaping
   is percent escaping and '+'/space mapping.  A binary Nul will
   silently be replaced by a 0xFF.  Function returns NULL to indicate
   an out of memory status. */
static char *
unescape_status_string (const char *s)
{
  char *buffer, *d;

  buffer = d = xtrymalloc (strlen ((const char*)s)+1);
  if (!buffer)
    return NULL;
  while (*s)
    {
      if (*s == '%' && s[1] && s[2])
        {
          s++;
          *d = xtoi_2 (s);
          if (!*d)
            *d = '\xff';
          d++;
          s += 2;
        }
      else if (*s == '+')
        {
          *d++ = ' ';
          s++;
        }
      else
        *d++ = *s++;
    }
  *d = 0;
  return buffer;
}




/* CARD LEARNING.  */

/* Take a 20 byte hexencoded string and put it into the the provided
   20 byte buffer FPR in binary format. */
static int
unhexify_fpr (const char *hexstr, char *fpr)
{
  const char *s;
  int n;

  for (s=hexstr, n=0; hexdigitp (s); s++, n++)
    ;
  if (*s || (n != 40))
    return 0; /* no fingerprint (invalid or wrong length). */
  n /= 2;
  for (s=hexstr, n=0; *s; s += 2, n++)
    fpr[n] = xtoi_2 (s);
  return 1; /* okay */
}

/* Take the serial number from LINE and return it verbatim in a newly
   allocated string.  We make sure that only hex characters are
   returned. */
static char *
store_serialno (const char *line)
{
  const char *s;
  char *p;

  for (s=line; hexdigitp (s); s++)
    ;
  p = xtrymalloc (s + 1 - line);
  if (p)
    {
      memcpy (p, line, s-line);
      p[s-line] = 0;
    }
  return p;
}

static int
learn_status_cb (void *opaque, const char *line)
{
  struct scd_cardinfo *parm = opaque;
  const char *keyword = line;
  int keywordlen;
  //int i;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      xfree (parm->serialno);
      parm->serialno = store_serialno (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-NAME", keywordlen))
    {
      xfree (parm->disp_name);
      parm->disp_name = unescape_status_string (line);
    }
  else if (keywordlen == 9 && !memcmp (keyword, "DISP-LANG", keywordlen))
    {
      xfree (parm->disp_lang);
      parm->disp_lang = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "PUBKEY-URL", keywordlen))
    {
      xfree (parm->pubkey_url);
      parm->pubkey_url = unescape_status_string (line);
    }
  else if (keywordlen == 10 && !memcmp (keyword, "LOGIN-DATA", keywordlen))
    {
      xfree (parm->login_data);
      parm->login_data = unescape_status_string (line);
    }
  else if (keywordlen == 7 && !memcmp (keyword, "KEY-FPR", keywordlen))
    {
      int no = atoi (line);
      while (*line && !spacep (line))
        line++;
      while (spacep (line))
        line++;
      if (no == 1)
        parm->fpr1valid = unhexify_fpr (line, parm->fpr1);
      else if (no == 2)
        parm->fpr2valid = unhexify_fpr (line, parm->fpr2);
      else if (no == 3)
        parm->fpr3valid = unhexify_fpr (line, parm->fpr3);
    }

  return 0;
}

/* Read information from card and fill the cardinfo structure
   CARDINFO.  Returns proper error code, zero on success.  */
int
scd_learn (scd_context_t ctx,
	   struct scd_cardinfo *cardinfo)
{
  int rc;

  *cardinfo = scd_cardinfo_null;
  rc = assuan_transact (ctx->assuan_ctx, "LEARN --force",
                        NULL, NULL, NULL, NULL,
                        learn_status_cb, cardinfo);

  return rc;
}

/* Simply release the cardinfo structure INFO.  INFO being NULL is
   okay.  */
void
scd_release_cardinfo (struct scd_cardinfo info)
{
  xfree (info.serialno);
  xfree (info.disp_name);
  xfree (info.login_data);
  xfree (info.pubkey_url);
}




/* CMD: SERIALNO.  */

static int
get_serialno_cb (void *opaque, const char *line)
{
  char **serialno = opaque;
  const char *keyword = line;
  const char *s;
  int keywordlen, n;

  for (keywordlen=0; *line && !spacep (line); line++, keywordlen++)
    ;
  while (spacep (line))
    line++;

  if (keywordlen == 8 && !memcmp (keyword, "SERIALNO", keywordlen))
    {
      if (*serialno)
        return gpg_error (GPG_ERR_CONFLICT); /* Unexpected status line. */
      for (n=0,s=line; hexdigitp (s); s++, n++)
        ;
      if (!n || (n&1)|| !(spacep (s) || !*s) )
        return gpg_error (GPG_ERR_ASS_PARAMETER);
      *serialno = xtrymalloc (n+1);
      if (!*serialno)
	return gpg_error_from_errno (errno);
      memcpy (*serialno, line, n);
      (*serialno)[n] = 0;
    }

  return 0;
}

static gpg_error_t
scd_serialno_internal (assuan_context_t ctx, char **r_serialno)
{
  char *serialno;
  int rc;

  serialno = NULL;

  rc = assuan_transact (ctx, "SERIALNO", NULL, NULL, NULL, NULL,
                        get_serialno_cb, &serialno);
  if (rc)
    goto out;

  if (r_serialno)
    *r_serialno = serialno;
  else
    xfree (serialno);

 out:

  return rc;
}

/* Return the serial number of the card or an appropriate error.  The
   serial number is returned as a hexstring. */
gpg_error_t
scd_serialno (scd_context_t ctx, char **r_serialno)
{
  gpg_error_t err;

  err = scd_serialno_internal (ctx->assuan_ctx, r_serialno);

  return err;
}

/* CMD: PKSIGN.  */



static int
membuf_data_cb (void *opaque, const void *buffer, size_t length)
{
  membuf_t *data = opaque;

  if (buffer)
    put_membuf (data, buffer, length);
  return 0;
}

/* Handle the NEEDPIN inquiry. */
static int
inq_needpin (void *opaque, const char *line)
{
  struct inq_needpin_s *parm = opaque;
  char *pin;
  size_t pinlen;
  int rc;

  rc = 0;

  if (!strncmp (line, "NEEDPIN", 7) && (line[7] == ' ' || !line[7]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      line += 7;
      while (*line == ' ')
        line++;

      pinlen = 90;
      pin = xtrymalloc_secure (pinlen);
      if (!pin)
	{
	  rc = gpg_error_from_errno (errno);
	  goto out;
	}

      rc = parm->getpin_cb (parm->getpin_cb_arg, line, pin, pinlen);
      if (!rc)
        rc = assuan_send_data (parm->ctx->assuan_ctx, pin, pinlen);
      xfree (pin);
    }
  else if (!strncmp (line, "POPUPPINPADPROMPT", 17)
           && (line[17] == ' ' || !line[17]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      line += 17;
      while (*line == ' ')
        line++;

      rc = parm->getpin_cb (parm->getpin_cb_arg, line, NULL, 1);
    }
  else if (!strncmp (line, "DISMISSPINPADPROMPT", 19)
           && (line[19] == ' ' || !line[19]))
    {
      if (!parm->getpin_cb)
	{
	  rc = GPG_ERR_BAD_PIN;
	  goto out;
	}

      rc = parm->getpin_cb (parm->getpin_cb_arg, "", NULL, 0);
    }
  else
    {
      log_msg_error (parm->ctx->loghandle,
		     "received unsupported inquiry from scdaemon `%s'",
		     line);
      rc = gpg_error (GPG_ERR_ASS_UNKNOWN_INQUIRE);
    }

 out:

  return gpg_error (rc);
}


/* Create a signature using the current card. CTX is the handle for
   the scd subsystem.  KEYID identifies the key on the card to use for
   signing. GETPIN_CB is the callback, which is called for querying of
   the PIN, GETPIN_CB_ARG is passed as opaque argument to
   GETPIN_CB. INDATA/INDATALEN is the input for the signature
   function.  The signature created is written into newly allocated
   memory in *R_BUF, *S_BUF, *R_BUFLEN, S_BUFLEN will hold the length of the
   signature. */
gpg_error_t
scd_pksign (scd_context_t ctx,
	    const char *keyid,
      key_types key_type,
	    const unsigned char *indata, size_t indatalen,
	    unsigned char **r_buf, size_t *r_buflen)
{
  int rc;
  char *p, line[ASSUAN_LINELENGTH];
  membuf_t data;
  struct inq_needpin_s inqparm;
  size_t len;
  unsigned char *sigbuf;
  size_t sigbuflen;
  const char * hashAlgo;

  *r_buf = NULL;
  *r_buflen = 0;
  rc = 0;

  init_membuf (&data, 1024);

  if (indatalen*2 + 50 > DIM(line)) /* FIXME: Are such long inputs
				       allowed? Should we handle them
				       differently?  */
    {
      rc = gpg_error (GPG_ERR_GENERAL);
      goto out;
    }

  /* Inform scdaemon about the data to be signed. */

  sprintf (line, "SETDATA ");
  p = line + strlen (line);
  bin2hex (indata, indatalen, p);

  rc = assuan_transact (ctx->assuan_ctx, line,
                        NULL, NULL, NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  /* Setup NEEDPIN inquiry handler.  */

  inqparm.ctx = ctx;
  inqparm.getpin_cb = ctx->pincb;
  inqparm.getpin_cb_arg = ctx->pincb_cookie;


  //set hash type based on
  switch (key_type)
  {
    case kType_rsa:
      hashAlgo = "--hash=sha256";
      break;

    case kType_ecc_Ed25519:
      hashAlgo = "";//default is sha512, setting that here causes scd to generate an invalid SIG
      break;

    default:
      rc = -1;
      goto out;
  }//switch

  /* Go, sign it. */
  snprintf (line, DIM(line)-1, "PKSIGN %s %s",hashAlgo, keyid);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (ctx->assuan_ctx, line,
                        membuf_data_cb, &data,
                        inq_needpin, &inqparm,
                        NULL, NULL);
  if (rc)
    goto out;

  /* Extract signature.  FIXME: can't we do this easier?  By reusing
     membuf, without another alloc/free? */

  sigbuf = get_membuf (&data, &sigbuflen);
  *r_buflen = sigbuflen;
  p = xtrymalloc (*r_buflen);
  *r_buf = (unsigned char*)p;
  if (!p)
    {
      rc = gpg_error_from_syserror ();
      goto out;
    }

  memcpy (p, sigbuf, sigbuflen);

 out:

  xfree (get_membuf (&data, &len));

  return rc;
}



/* CMD: READKEY.  */

/* Read a key with ID and return it in an allocate buffer pointed to
   by r_BUF as a valid S-expression. */
int
scd_readkey (scd_context_t ctx,
	     const char *id, gcry_sexp_t *key)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  size_t buflen;
  unsigned char *buffer;

  *key = NULL;
  buffer = NULL;
  init_membuf (&data, 1024);

  /* Execute READKEY command.  */
  snprintf (line, DIM(line)-1, "READKEY %s", id);
  line[DIM(line)-1] = 0;
  rc = assuan_transact (ctx->assuan_ctx, line,
                        membuf_data_cb, &data,
                        NULL, NULL,
                        NULL, NULL);
  if (rc)
    goto out;

  buffer = get_membuf (&data, &buflen);
  if (!buffer)
    {
      rc = gpg_error (GPG_ERR_ENOMEM);
      goto out;
    }

  if (!gcry_sexp_canon_len (buffer, buflen, NULL, NULL))
    {
      rc = gpg_error (GPG_ERR_INV_VALUE);
      *key = NULL;
    }
  else
    rc = gcry_sexp_new (key, buffer, buflen, 1);

 out:

  xfree (buffer);

  return rc;
}




/* Sends a GETINFO command for WHAT to the scdaemon through CTX.  The
   newly allocated result is stored in *RESULT.  Returns proper error
   code, zero on success.  */
int
scd_getinfo (scd_context_t ctx, const char *what, char **result)
{
  int rc;
  char line[ASSUAN_LINELENGTH];
  membuf_t data;
  unsigned char *databuf;
  size_t datalen;
  char *res;

  *result = NULL;

  sprintf (line, "GETINFO %s", what);
  init_membuf (&data, 256);

  rc = assuan_transact (ctx->assuan_ctx, line, membuf_data_cb, &data,
			NULL, NULL, NULL, NULL);
  if (rc)
    goto out;

  databuf = get_membuf (&data, &datalen);
  if (databuf && datalen)
    {
      res = xtrymalloc (datalen + 1);
      if (!res)
	{
	  log_msg_error (ctx->loghandle,
			 "warning: can't store getinfo data: %s",
			 strerror (errno));
	  rc = gpg_error_from_syserror ();
	}
      else
	{
	  memcpy (res, databuf, datalen);
	  res[datalen] = 0;
	  *result = res;
	}
    }

 out:

  xfree (get_membuf (&data, &datalen));

  return rc;
}


int run_as_user(const struct passwd *user, log_handle_t loghandle, const char * const cmd[], int *input, char **env)
{
    int inp[2] = {-1, -1};
    int pid;
    int dev_null;
    int rt_val;

    if (pipe(inp) < 0)
    {
        *input = -1;
        return 0;
    }

    *input = inp[WRITE_END];

    pid = fork();

    switch (pid)
    {
    case -1:
        close_safe(inp[READ_END], loghandle);
        close_safe(inp[WRITE_END], loghandle);
        *input = -1;
        return FALSE;

    case 0:
        break;

    default:
        close_safe(inp[READ_END], loghandle);
        return pid;
    }

    //in child process

    rt_val = dup2(inp[READ_END], STDIN_FILENO);
    if ( rt_val == -1 )
    {
        exit(EXIT_FAILURE);
    }

    close_safe(inp[READ_END], loghandle);
    close_safe(inp[WRITE_END], loghandle);

    //attempt to link stdout and stderr to /dev/null if it exist
    dev_null = open("/dev/null", O_WRONLY);
    if ( dev_null != -1)
    {
        rt_val = dup2(dev_null, STDOUT_FILENO);
        if(rt_val == -1)
        {
        	exit(EXIT_FAILURE);
        }

        rt_val = dup2(dev_null, STDERR_FILENO);
        if(rt_val == -1)
		{
			exit(EXIT_FAILURE);
		}

        rt_val = close(dev_null);
        if(rt_val == -1)
		{
			exit(EXIT_FAILURE);
		}
    }

    if (seteuid(getuid()) < 0 || setegid(getgid()) < 0 ||
        setgid(user->pw_gid) < 0 || setuid(user->pw_uid) < 0 ||
        setegid(user->pw_gid) < 0 || seteuid(user->pw_gid) < 0)
    {
        exit(EXIT_FAILURE);
    }

    if (env != NULL)
    {
        execve(cmd[0], (char * const *) cmd, env);
    }
    else
    {
        execv(cmd[0], (char * const *) cmd);
    }

    exit(EXIT_SUCCESS);
}

void close_safe(int fd, log_handle_t loghandle)
{
     int rt = close(fd);
     errno = 0;

     if(rt == -1)
     {
    	 if(errno != 0)
    	 {
    		 log_msg_error (loghandle, "Error Closing file descriptor: %s\n", strerror(errno));
    	 }
    	 else
    	 {
    		 log_msg_error (loghandle, "Error Closing file descriptor\n");
    	 }

     }

}
/* END */
