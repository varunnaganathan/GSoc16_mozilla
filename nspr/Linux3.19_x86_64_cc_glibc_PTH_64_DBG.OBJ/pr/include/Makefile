# 
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

#! gmake

MOD_DEPTH	= ../..
topsrcdir	= ../../..
srcdir		= ../../../pr/include
VPATH		= ../../../pr/include

include $(MOD_DEPTH)/config/autoconf.mk

DIRS = md private obsolete

include $(topsrcdir)/config/config.mk

HEADERS = $(wildcard $(srcdir)/*.h)

RELEASE_HEADERS = $(HEADERS)
RELEASE_HEADERS_DEST = $(RELEASE_INCLUDE_DIR)

include $(topsrcdir)/config/rules.mk

export:: $(RELEASE_HEADERS)
	$(INSTALL) -m 444 $(RELEASE_HEADERS) $(dist_includedir)
