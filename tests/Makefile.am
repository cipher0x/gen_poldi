# Copyright (C) 2008, 2009 g10 Code GmbH
#
# This file is part of Poldi.
#
# Poldi is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Poldi is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA

noinst_PROGRAMS = parse-test pam-test session-test

parse_test_SOURCES = parse-test.c
parse_test_CFLAGS = -Wall -I$(top_srcdir)/src/util -I$(top_srcdir)/src \
 $(GPG_ERROR_CFLAGS)
parse_test_LDADD = $(top_builddir)/src/util/libpoldi-util.a \
 $(GPG_ERROR_LIBS) $(LIBGCRYPT_LIBS)

pam_test_SOURCES = pam-test.c
pam_test_CFLAGS = -Wall

pam_test_LDADD = -lpam -lpam_misc


session_test_SOURCES = session-test.c
session_test_CFLAGS = -Wall -I$(top_srcdir)/src/util -I$(top_srcdir)/src \
 $(GPG_ERROR_CFLAGS)
session_test_LDADD = $(top_builddir)/src/util/libpoldi-util.a \
 $(GPG_ERROR_LIBS) $(LIBGCRYPT_LIBS) -lpamtest