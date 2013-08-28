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
#include <Samba-Descriptor.h>
#include <Samba-ACE.h>
#include <gen_ndr/security.h>
#include <security/security_descriptor.h>
#include <security/sddl.h>
#include <security/dom_sid.h>
#include <ndr.h>
#include <gen_ndr/ndr_security.h>

#include "const-c.inc"

/* Takes the access mask of a DS ACE and transform them in a File ACE mask */
uint32_t ldapmask2filemask(uint32_t ldm)
{
    uint32_t RIGHT_DS_CREATE_CHILD     = 0x00000001;
    uint32_t RIGHT_DS_DELETE_CHILD     = 0x00000002;
    uint32_t RIGHT_DS_LIST_CONTENTS    = 0x00000004;
    uint32_t ACTRL_DS_SELF             = 0x00000008;
    uint32_t RIGHT_DS_READ_PROPERTY    = 0x00000010;
    uint32_t RIGHT_DS_WRITE_PROPERTY   = 0x00000020;
    uint32_t RIGHT_DS_DELETE_TREE      = 0x00000040;
    uint32_t RIGHT_DS_LIST_OBJECT      = 0x00000080;
    uint32_t RIGHT_DS_CONTROL_ACCESS   = 0x00000100;
    uint32_t FILE_READ_DATA            = 0x0001;
    uint32_t FILE_LIST_DIRECTORY       = 0x0001;
    uint32_t FILE_WRITE_DATA           = 0x0002;
    uint32_t FILE_ADD_FILE             = 0x0002;
    uint32_t FILE_APPEND_DATA          = 0x0004;
    uint32_t FILE_ADD_SUBDIRECTORY     = 0x0004;
    uint32_t FILE_CREATE_PIPE_INSTANCE = 0x0004;
    uint32_t FILE_READ_EA              = 0x0008;
    uint32_t FILE_WRITE_EA             = 0x0010;
    uint32_t FILE_EXECUTE              = 0x0020;
    uint32_t FILE_TRAVERSE             = 0x0020;
    uint32_t FILE_DELETE_CHILD         = 0x0040;
    uint32_t FILE_READ_ATTRIBUTES      = 0x0080;
    uint32_t FILE_WRITE_ATTRIBUTES     = 0x0100;
    uint32_t DELETE                    = 0x00010000;
    uint32_t READ_CONTROL              = 0x00020000;
    uint32_t WRITE_DAC                 = 0x00040000;
    uint32_t WRITE_OWNER               = 0x00080000;
    uint32_t SYNCHRONIZE               = 0x00100000;
    uint32_t STANDARD_RIGHTS_ALL       = 0x001F0000;

    uint32_t filemask = ldm & STANDARD_RIGHTS_ALL;

    if ((ldm & RIGHT_DS_READ_PROPERTY) && (ldm & RIGHT_DS_LIST_CONTENTS)) {
         filemask |= (SYNCHRONIZE | FILE_LIST_DIRECTORY |
                      FILE_READ_ATTRIBUTES | FILE_READ_EA |
                      FILE_READ_DATA | FILE_EXECUTE);
    }

     if (ldm & RIGHT_DS_WRITE_PROPERTY) {
         filemask |= (SYNCHRONIZE | FILE_WRITE_DATA |
                      FILE_APPEND_DATA | FILE_WRITE_EA |
                      FILE_WRITE_ATTRIBUTES | FILE_ADD_FILE |
                      FILE_ADD_SUBDIRECTORY);
     }

     if (ldm & RIGHT_DS_CREATE_CHILD) {
         filemask |= (FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE);
     }

     if (ldm & RIGHT_DS_DELETE_CHILD) {
         filemask |= FILE_DELETE_CHILD;
     }

     return filemask;
}

MODULE = Samba::Security::Descriptor    PACKAGE = Samba::Security::Descriptor
PROTOTYPES: ENABLE

INCLUDE: const-xs.inc

void
init(self)
    SV *self
    PREINIT:
    TALLOC_CTX *mem_ctx;
    DescriptorCtx *ctx;
    CODE:
    mem_ctx = talloc_named(NULL, 0, "Samba::Security::Descriptor");
    if (mem_ctx == NULL) {
        croak("%s: No memory allocating talloc context", __func__);
    }

    ctx = talloc_zero(mem_ctx, DescriptorCtx);
    if (self == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating context", __func__);
    }
    ctx->mem_ctx = mem_ctx;

    ctx->sd = security_descriptor_initialise(ctx->mem_ctx);
    if (ctx->sd == NULL) {
        talloc_free(mem_ctx);
        croak("%s: No memory allocating security descriptor", __func__);
    }
    xs_object_magic_attach_struct(aTHX_ SvRV(self), ctx);

const char *
as_sddl(self, domain_sid)
    SV *self
    const char *domain_sid
    PREINIT:
    DescriptorCtx *ctx;
    char *text;
    struct dom_sid dom_sid;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (!string_to_sid(&dom_sid, domain_sid)) {
        croak("Failed to parse domain sid '%s'", domain_sid);
    }
    text = sddl_encode(ctx->mem_ctx, ctx->sd, &dom_sid);
    if (text == NULL) {
        croak("Failed to encode SD in SDDL format");
    }
    RETVAL = text;
    talloc_free(text);
    OUTPUT:
    RETVAL

int
from_sddl(self, sddl, domain_sid)
    SV *self
    const char *sddl
    const char *domain_sid
    PREINIT:
    DescriptorCtx *ctx;
    struct dom_sid dom_sid;
    struct security_descriptor *new_sd;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (!string_to_sid(&dom_sid, domain_sid)) {
        croak("Failed to parse domain sid '%s'", domain_sid);
    }
    new_sd = sddl_decode(ctx->mem_ctx, sddl, &dom_sid);
    if (new_sd == NULL) {
        talloc_free(ctx->sd);
        ctx->sd = NULL;
        croak("Cannot parse SDDL string '%s'", sddl);
    } else {
        talloc_free(ctx->sd);
        ctx->sd = new_sd;
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
unmarshall(self, blob, length)
    SV *self
    char *blob
    size_t length
    PREINIT:
    DescriptorCtx *ctx;
    NTSTATUS status;
    struct security_descriptor *new_sd;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    status = unmarshall_sec_desc(ctx->mem_ctx, blob, length, &ctx->sd);
    if (NT_STATUS_IS_ERR(status)) {
        talloc_free(ctx->sd);
        ctx->sd = NULL;
        croak("Cannot unmarshall security descriptor: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

SV *
marshall(self)
    SV *self
    PREINIT:
    DescriptorCtx *ctx;
    NTSTATUS status;
    uint8_t *blob;
    size_t length;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialised");
    }
    status = marshall_sec_desc(ctx->mem_ctx, ctx->sd, &blob, &length);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Cannot marshall security descriptor: %s", nt_errstr(status));
    }
    RETVAL = newSV(0);
    sv_setpvn(RETVAL, blob, length);
    OUTPUT:
    RETVAL


int
to_fs_sd(self)
    SV *self
    PREINIT:
    DescriptorCtx *ctx;
    NTSTATUS status;
    struct security_descriptor *fs_sd;
    struct security_acl *acl;
    int i;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security Descriptor not initialized");
    }

    fs_sd = security_descriptor_initialise(ctx->mem_ctx);
    fs_sd->owner_sid = dom_sid_dup(fs_sd, ctx->sd->owner_sid);
    fs_sd->group_sid = dom_sid_dup(fs_sd, ctx->sd->group_sid);
    fs_sd->type = ctx->sd->type;
    fs_sd->revision = ctx->sd->revision;
    acl = ctx->sd->dacl;

    for (i = 0; i < acl->num_aces; i++) {
        struct security_ace *ace = &(acl->aces[i]);
        char *ace_sid_str = dom_sid_string(ctx->mem_ctx, &ace->trustee);

        if (!ace->type & SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT &&
                strcmp(ace_sid_str, SID_BUILTIN_PREW2K) != 0) {
            ace->flags |= (SEC_ACE_FLAG_OBJECT_INHERIT |
                           SEC_ACE_FLAG_CONTAINER_INHERIT);
            if (strcmp(ace_sid_str, SID_CREATOR_OWNER) == 0) {
                ace->flags |= SEC_ACE_FLAG_INHERIT_ONLY;
            }
            ace->access_mask = ldapmask2filemask(ace->access_mask);

            struct security_ace *new_ace = security_ace_create(
                fs_sd, ace_sid_str, ace->type, ace->access_mask,
                ace->flags);
            status = security_descriptor_dacl_add(fs_sd, new_ace);
            if (NT_STATUS_IS_ERR(status)) {
                croak("Failed to add DACL: %s", nt_errstr(status));
            }
        }
        talloc_free(ace_sid_str);
    }
    talloc_free(ctx->sd);
    ctx->sd = fs_sd;
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
sacl_del(self, trustee_str)
    SV *self
    const char *trustee_str
    PREINIT:
    DescriptorCtx *ctx;
    NTSTATUS status;
    struct dom_sid *trustee;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialized");
    }

    trustee = dom_sid_parse_talloc(ctx->mem_ctx, trustee_str);
    if (trustee == NULL) {
        croak("Cannot parse SID string '%s'", trustee_str);
    }

    status = security_descriptor_sacl_del(ctx->sd, trustee);
    talloc_free(trustee);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to delete SACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
sacl_add(self, ace)
    SV *self
    SV *ace
    PREINIT:
    DescriptorCtx *ctx;
    AccessControlEntryCtx *ace_ctx;
    NTSTATUS status;
    struct security_ace *new_ace;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    ace_ctx = xs_object_magic_get_struct_rv(aTHX_ ace);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialized");
    }

    new_ace = talloc_zero(ctx->sd, struct security_ace);
    if (new_ace == NULL) {
        croak("No memory");
    }
    sec_ace_copy(new_ace, &ace_ctx->ace);

    status = security_descriptor_sacl_add(ctx->sd, new_ace);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to add SACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
dacl_del(self, trustee_str)
    SV *self
    const char *trustee_str
    PREINIT:
    DescriptorCtx *ctx;
    NTSTATUS status;
    struct dom_sid *trustee;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialized");
    }

    trustee = dom_sid_parse_talloc(ctx->mem_ctx, trustee_str);
    if (trustee == NULL) {
        croak("Cannot parse SID string '%s'", trustee_str);
    }

    status = security_descriptor_dacl_del(ctx->sd, trustee);
    talloc_free(trustee);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to delete DACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

int
dacl_add(self, ace)
    SV *self
    SV *ace
    PREINIT:
    DescriptorCtx *ctx;
    AccessControlEntryCtx *ace_ctx;
    NTSTATUS status;
    struct security_ace *new_ace;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    ace_ctx = xs_object_magic_get_struct_rv(aTHX_ ace);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialized");
    }

    new_ace = talloc_zero(ctx->sd, struct security_ace);
    if (new_ace == NULL) {
        croak("No memory");
    }
    sec_ace_copy(new_ace, &ace_ctx->ace);

    status = security_descriptor_dacl_add(ctx->sd, new_ace);
    if (NT_STATUS_IS_ERR(status)) {
        croak("Failed to add DACL: %s", nt_errstr(status));
    }
    RETVAL = 1;
    OUTPUT:
    RETVAL

uint16_t
type(self, type = NO_INIT)
    SV *self
    uint16_t type
    PREINIT:
    DescriptorCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    if (ctx->sd == NULL) {
        croak("Security descriptor not initialized");
    }
    if (items > 1) {
        ctx->sd->type = type;
    }
    RETVAL = ctx->sd->type;
    OUTPUT:
    RETVAL

SV *
dump(self)
    SV *self
    PREINIT:
    DescriptorCtx *ctx;
    char *str;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    PPCODE:
    str = ndr_print_struct_string(ctx->mem_ctx,
            (ndr_print_fn_t)ndr_print_security_descriptor,
            "security_descriptor", ctx->sd);
    XPUSHs(sv_2mortal(newSVpv(str, strlen(str))));
    talloc_free(str);

SV *
owner(self, owner_sid_str = NO_INIT)
    SV *self
    char *owner_sid_str
    PREINIT:
    DescriptorCtx *ctx;
    struct dom_sid *owner_sid;
    char *ret;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    PPCODE:
    if (items > 1) {
        owner_sid = dom_sid_parse_talloc(ctx->sd, owner_sid_str);
        if (owner_sid == NULL) {
            croak("Cannot parse SID string '%s'", owner_sid_str);
        }
        talloc_free(ctx->sd->owner_sid);
        ctx->sd->owner_sid = owner_sid;
    }
    ret = dom_sid_string(ctx->mem_ctx, ctx->sd->owner_sid);
    XPUSHs(sv_2mortal(newSVpv(ret, strlen(ret))));
    talloc_free(ret);

SV *
group(self, group_sid_str = NO_INIT)
    SV *self
    char *group_sid_str
    PREINIT:
    DescriptorCtx *ctx;
    struct dom_sid *group_sid;
    char *ret;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    PPCODE:
    if (items > 1) {
        group_sid = dom_sid_parse_talloc(ctx->sd, group_sid_str);
        if (group_sid == NULL) {
            croak("Cannot parse SID string '%s'", group_sid_str);
        }
        talloc_free(ctx->sd->group_sid);
        ctx->sd->group_sid = group_sid;
    }
    ret = dom_sid_string(ctx->mem_ctx, ctx->sd->group_sid);
    XPUSHs(sv_2mortal(newSVpv(ret, strlen(ret))));
    talloc_free(ret);

void
DESTROY(self)
    SV *self
    PREINIT:
    DescriptorCtx *ctx;
    INIT:
    ctx = xs_object_magic_get_struct_rv(aTHX_ self);
    CODE:
    talloc_free(ctx->mem_ctx);
