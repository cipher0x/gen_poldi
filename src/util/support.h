/* support.h - PAM authentication via OpenPGP smartcards.
   Copyright (C) 2004, 2005, 2007, 2008 g10 Code GmbH

   This file is part of Poldi.

   Poldi is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   Poldi is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
   02111-1307, USA.  */

#ifndef POLDI_SUPPORT_H
#define POLDI_SUPPORT_H

#include <gcrypt.h>
#include <dirent.h>
#include "key-types.h"
/* This function generates a challenge; the challenge will be stored
   in newly allocated memory, which is to be stored in *CHALLENGE;
   it's length in bytes is to be stored in *CHALLENGE_N.  Returns
   proper error code.  */
gpg_error_t challenge_generate (unsigned char **challenge, size_t *challenge_n, key_types key_type);

/* Releases the challenge contained in CHALLENGE generated by
   challenge_generate().  */
void challenge_release (unsigned char *challenge);

/* This functions verifies that the signature contained in RESPONSE of
   size RESPONSE_N (in bytes) is indeed the result of signing the
   challenge given in CHALLENGE of size CHALLENGE_N (in bytes) with
   the secret key belonging to the public key given as PUBLIC_KEY.
   Returns proper error code.  */
gpg_error_t challenge_verify (gcry_sexp_t public_key, key_types key_type,
			      unsigned char *challenge, size_t challenge_n,
			      unsigned char *response, size_t response_n);

/* This function converts the given S-Expression SEXP into it's
   `ADVANCED' string representation, using newly-allocated memory,
   storing the resulting NUL-terminated string in *SEXP_STRING.
   Returns a proper error code.  */
gpg_error_t sexp_to_string (gcry_sexp_t sexp, char **sexp_string);

/* This function retrieves the content from the file specified by
   FILENAMED and writes it into a newly allocated chunk of memory,
   which is then stored in *STRING.  Returns proper error code.  */
gpg_error_t file_to_string (const char *filename, char **string);

/* This function retrieves the content from the file specified by
   FILENAMED and writes it into a newly allocated chunk of memory,
   which is then stored in *DATA and *DATALEN.  Returns proper error
   code.  */
gpg_error_t file_to_binstring (const char *filename, void **data, size_t *datalen);

/* This functions converts the given string-representation of an
   S-Expression into a new S-Expression object, which is to be stored
   in *SEXP.  Returns proper error code.  */
gpg_error_t string_to_sexp (gcry_sexp_t *sexp, char *string);

gpg_error_t char_vector_dup (int len, const char **a, char ***b);

void char_vector_free (char **a);

int my_strlen (const char *s);

void wipestr(char *data);

#endif

/* END */
