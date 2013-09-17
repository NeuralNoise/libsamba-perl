/*
 Copyright (C) 2013 Zentyal S.L.

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License, version 2, as
 published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <EXTERN.h>
#include <perl.h>
#include <XSUB.h>
#include <xs_object_magic.h>

#include "ppport.h"

#include <util/data_blob.h>

#include <Samba-ACE.h>

#include <gen_ndr/security.h>
#include <security/secace.h>
#include <security/dom_sid.h>

MODULE = Samba::Security::AccessControlEntry PACKAGE = Samba::Security::AccessControlEntry
PROTOTYPES: ENABLE

void
init(self, sid_str, type, mask, flags)
    SV *self
    const char *sid_str
    unsigned long type
    unsigned long mask
    unsigned char flags
    PREINIT:
    AccessControlEntryCtx *ctx;
    INIT:
    CODE:
    ctx = malloc(sizeof (AccessControlEntryCtx));
    if (ctx == NULL) {
        croak("No memory");
    }

    struct dom_sid *sid = &(ctx->ace.trustee);
    if (!string_to_sid(sid, sid_str)) {
        croak("Failed to parse SID '%s'", sid_str);
    }

    init_sec_ace(&ctx->ace, sid, type, mask, flags);
    xs_object_magic_attach_struct(aTHX_ SvRV(self), ctx);

void
DESTROY(self)
    SV *self
    PREINIT:
    AccessControlEntryCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    free(ctx);
