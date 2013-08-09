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

#include "ppport.h"

#include <util/data_blob.h>

#include <Samba-ACE.h>

#include <gen_ndr/security.h>
#include <security/secace.h>

MODULE = Samba::Security::AccessControlEntry PACKAGE = Samba::Security::AccessControlEntry

AccessControlEntry *
new(class, sid_str, type, mask, flags)
    SV *class
    const char *sid_str
    unsigned long type
    unsigned long mask
    unsigned char flags
    CODE:
    AccessControlEntry *self;
    const char *classname;

    if (sv_isobject(class)) {
        classname = sv_reftype(SvRV(class), 1);
    } else {
        if (!SvPOK(class))
            croak("%s: Need an object or class name as "
                  "first argument to the constructor", __func__);
        classname = SvPV_nolen(class);
    }
    self = malloc(sizeof (AccessControlEntry));

    struct dom_sid *sid = &(self->ace.trustee);
    if (!string_to_sid(sid, sid_str)) {
        croak("Failed to parse SID '%s'", sid_str);
    }

    init_sec_ace(&self->ace, sid, type, mask, flags);

    RETVAL = self;
OUTPUT:
    RETVAL

MODULE = Samba::Security::AccessControlEntry PACKAGE = AccessControlEntryPtr PREFIX=acePtr_

void
acePtr_DESTROY(self)
    AccessControlEntry *self
CODE:
    free(self);
